"""Traffic Audit: capture packets on your own network (or open a .pcap) and turn
what's on the wire into findings, like a Wireshark session distilled into a report.

Capture uses dumpcap (Wireshark's capture engine); analysis uses tshark. Both run
through CommandRunner, so every command is shown and logged.

Safety rules built in here:
  * Capture is passive: nothing is sent. It is refused on interfaces in monitor
    mode, and every capture filter gets `not ether proto 0x888e` appended, so
    WPA handshake frames (EAPOL) are never recorded (non-negotiable #1).
  * Secrets are never stored or shown. The analysis extracts only command and
    scheme NAMES (FTP "PASS", HTTP "Basic", IMAP "LOGIN", form field names...),
    never their values; SNMP community strings are masked. Raw tshark output is
    parsed in memory and discarded. (The .pcap file itself does contain whatever
    crossed the network; it's saved owner-only and can be deleted from the tab.)
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from watchtower.core import deps
from watchtower.core.findings_engine import SEV_WEIGHT, Finding

EAPOL_EXCLUDE = "not ether proto 0x888e"
DEFAULT_SNMP = {"public", "private"}

# tshark fields extracted per packet. Deliberately NOT included: telnet.data,
# ftp.request.arg, smtp.req.parameter, pop/imap arguments, http.authbasic,
# urlencoded-form.value: they carry the actual user names and passwords.
FIELDS = [
    "frame.number", "frame.protocols", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
    "udp.dstport",
    "http.request.method", "http.host", "http.authorization", "urlencoded-form.key",
    "ftp.request.command", "pop.request.command", "imap.request.command", "smtp.req.command",
    "snmp.version", "snmp.community", "smb.cmd", "smb2.cmd", "nbns.name", "dns.qry.name", "dns.flags.response",
    "tls.handshake.type", "tls.handshake.version", "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite", "tls.handshake.extensions_server_name",
]
DISPLAY_FILTER = ("http.request or ftp.request or pop.request or imap.request or smtp.req or snmp or telnet or "
                  "smb or nbns or llmnr or mdns or (dns and dns.flags.response == 0) or ssdp or "
                  "tls.handshake.type == 1 or tls.handshake.type == 2")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
# Cipher suite IDs (IANA) in broken families. Only what a ServerHello *chose* is judged.
WEAK_CIPHERS: dict[int, tuple[str, str]] = {
    **{i: ("NULL (no encryption)", "Critical") for i in (0x0000, 0x0001, 0x0002, 0x003B, 0xC001, 0xC006, 0xC010)},
    **{i: ("export-grade", "Critical") for i in (0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017,
                                                0x0019)},
    **{i: ("anonymous (no authentication)", "Critical") for i in (0x0018, 0x001A, 0x001B, 0x0034, 0x003A, 0x006C,
                                                                  0x006D, 0xC015, 0xC016, 0xC017, 0xC018, 0xC019)},
    **{i: ("RC4", "High") for i in (0x0004, 0x0005, 0xC002, 0xC007, 0xC00C, 0xC011)},
    **{i: ("single DES", "High") for i in (0x0009, 0x000C, 0x000F, 0x0012, 0x0015)},
    **{i: ("3DES (SWEET32)", "Medium") for i in (0x000A, 0x000D, 0x0010, 0x0013, 0x0016, 0xC003, 0xC008, 0xC00D,
                                                 0xC012)},
}


# ---- capture ----

def capture_binary() -> str | None:
    return deps.find_binary("dumpcap")


def tshark_binary() -> str | None:
    return deps.find_binary("tshark")


def capture_filter(user_filter: str = "") -> str:
    """The BPF filter actually used: the user's (if any) AND never EAPOL."""
    f = user_filter.strip()
    return f"({f}) and {EAPOL_EXCLUDE}" if f else EAPOL_EXCLUDE


def capture_argv(interface: str, out_file: str, seconds: int, max_packets: int = 0, user_filter: str = "",
                 monitor_interfaces: set[str] = frozenset()) -> list[str]:
    if not _IFACE_RE.match(interface or ""):
        raise ValueError(f"invalid interface name: {interface!r}")
    if interface in monitor_interfaces:
        raise ValueError(f"{interface} is in monitor mode. Traffic Audit only captures on normal (managed) "
                         "interfaces, so it can't record Wi-Fi handshakes. Switch it back in Interfaces.")
    if seconds <= 0 or seconds > 24 * 3600:
        raise ValueError("capture length must be between 1 second and 24 hours")
    dumpcap = capture_binary()
    if not dumpcap:
        raise RuntimeError("dumpcap is not installed (sudo apt install tshark).")
    argv = [dumpcap, "-i", interface, "-q", "-w", out_file, "-a", f"duration:{int(seconds)}",
            "-f", capture_filter(user_filter)]
    if max_packets:
        argv += ["-c", str(int(max_packets))]
    return argv


def check_filter_argv(user_filter: str) -> list[str]:
    """`dumpcap -d -f FILTER` compiles the filter without capturing (to validate it)."""
    return [capture_binary() or "dumpcap", "-d", "-f", capture_filter(user_filter)]


def list_interfaces_argv() -> list[str]:
    return [capture_binary() or "dumpcap", "-D"]


def parse_interfaces(text: str) -> list[tuple[str, str]]:
    """`dumpcap -D` lines like '3. lo (Loopback)' -> [(name, description)]."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+\.\s+(\S+)(?:\s+\((.*)\))?\s*$", line)
        if m:
            out.append((m.group(1), m.group(2) or ""))
    return out


# Interfaces that aren't network links worth auditing.
SKIP_INTERFACES = re.compile(r"^(bluetooth|dbus|nflog|nfqueue|usbmon|ciscodump|randpkt|sshdump|udpdump|wifidump|"
                             r"etwdump|ifb\d)", re.I)


def useful_interfaces(ifaces: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(n, d) for n, d in ifaces if not SKIP_INTERFACES.match(n)]


# ---- analysis ----

# tshark reads the capture from stdin ("-r -"): Watchtower opens the file and pipes it in. Ubuntu's
# AppArmor profiles for Wireshark's tools only allow certain paths (e.g. not ~/.local/share), so a
# tshark that may not open the file itself would fail with "You don't have permission to read the file".
STDIN = "-"


def fields_argv(pcap: str = STDIN) -> list[str]:
    argv = [tshark_binary() or "tshark", "-r", pcap, "-n", "-Y", DISPLAY_FILTER, "-T", "fields",
            "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "header=y"]
    for f in FIELDS:
        argv += ["-e", f]
    return argv


def stats_argv(pcap: str = STDIN) -> list[str]:
    return [tshark_binary() or "tshark", "-r", pcap, "-q", "-n", "-z", "io,phs", "-z", "conv,ip", "-z", "conv,ipv6",
            "-z", "io,stat,0", "-z", "endpoints,ip", "-z", "endpoints,ipv6", "-z", "conv,tcp", "-z", "conv,udp"]


# Per-device identity and activity: who is this address (MAC maker, DHCP/mDNS name) and what did it
# ask for (DNS names, TLS server names, HTTP host + path). URL query strings are dropped by the parser.
ACTIVITY_FIELDS = [
    "frame.time_relative", "frame.protocols", "eth.src", "eth.src.oui_resolved", "ip.src", "ipv6.src",
    "arp.opcode", "arp.src.hw_mac", "arp.src.proto_ipv4",
    "dhcp.hw.mac_addr", "dhcp.option.hostname", "dhcp.option.vendor_class_id", "dhcp.option.requested_ip_address",
    "dhcp.ip.client", "dns.qry.name", "dns.flags.response", "dns.resp.name", "dns.a",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "http.request.method", "http.host",
    "http.request.uri",
]
ACTIVITY_FILTER = ("arp or dhcp or dns or tls.handshake.type == 1 or http.request")


def activity_argv(pcap: str = STDIN) -> list[str]:
    # -N m: resolve MAC address makers from Wireshark's bundled list (local; no DNS lookups)
    argv = [tshark_binary() or "tshark", "-r", pcap, "-N", "m", "-Y", ACTIVITY_FILTER, "-T", "fields",
            "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "header=y"]
    for f in ACTIVITY_FIELDS:
        argv += ["-e", f]
    return argv


def first_packet_argv(pcap: str = STDIN) -> list[str]:
    return [tshark_binary() or "tshark", "-r", pcap, "-c", "1", "-T", "fields", "-e", "frame.time_epoch"]


_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                                "100.64.0.0/10", "fc00::/7", "fe80::/10")]


def is_lan(ip: str, local_nets: list[str] | None = None) -> bool:
    """On your own network: inside the capturing interface's networks if known, else a private LAN range."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_multicast or a.is_unspecified or ip == "255.255.255.255" or a.is_loopback:
        return False
    nets = []
    for n in local_nets or []:
        try:
            nets.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            continue
    if nets:
        return any(a in n for n in nets if n.version == a.version)
    return any(a in n for n in _LAN_NETS if n.version == a.version)


def is_unicast(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified or ip == "255.255.255.255" or ip.endswith(".255"))


def _strip_query(uri: str) -> str:
    """Path only: query strings and fragments often carry tokens/session ids."""
    path = uri.split("?", 1)[0].split("#", 1)[0]
    return path[:120] + ("…" if len(path) > 120 else "")


def parse_activity(text: str, local_nets: list[str] | None = None) -> dict[str, dict]:
    """tshark activity_argv output -> {ip: {"macs", "vendor", "names", "dhcp_vendor", "dns", "sni", "http",
    "first", "last"}}. Names come from DHCP (hostname option), mDNS answers and the MAC <-> IP pairs seen in
    ARP and normal traffic; MACs are only tied to addresses on your network (a router's MAC carries the
    whole internet)."""
    lines = text.splitlines()
    if not lines:
        return {}
    header = lines[0].split("\t")
    hosts: dict[str, dict] = {}
    mac_ips: dict[str, set] = defaultdict(set)
    mac_vendor: dict[str, str] = {}
    mac_info: dict[str, dict] = defaultdict(dict)

    def host(ip):
        return hosts.setdefault(ip, {"macs": [], "vendor": "", "names": [], "dhcp_vendor": "", "dns": {},
                                     "sni": {}, "http": {}, "first": None, "last": None})

    def bump(d, k):
        if k:
            d[k] = d.get(k, 0) + 1

    for line in lines[1:]:
        cols = line.split("\t")
        r = dict(zip(header, cols + [""] * (len(header) - len(cols)), strict=False))
        protos = r.get("frame.protocols", "").split(":")
        if "icmp" in protos or "icmpv6" in protos:
            continue
        src = _first(r.get("ip.src") or r.get("ipv6.src", ""))
        mac = _first(r.get("eth.src", "")).lower()
        try:
            t = float(_first(r.get("frame.time_relative", "")) or "nan")
        except ValueError:
            t = float("nan")
        if mac and r.get("eth.src.oui_resolved"):
            mac_vendor[mac] = _first(r["eth.src.oui_resolved"])
        if "arp" in protos:
            amac, aip = _first(r.get("arp.src.hw_mac", "")).lower(), _first(r.get("arp.src.proto_ipv4", ""))
            if amac and aip and aip != "0.0.0.0":
                mac_ips[amac].add(aip)
            continue
        if src and mac and is_lan(src, local_nets) and src not in ("0.0.0.0", "::"):
            mac_ips[mac].add(src)
        if "dhcp" in protos:
            dmac = _first(r.get("dhcp.hw.mac_addr", "")).lower() or mac
            info = mac_info[dmac]
            if r.get("dhcp.option.hostname"):
                info["name"] = _first(r["dhcp.option.hostname"])
            if r.get("dhcp.option.vendor_class_id"):
                info["dhcp_vendor"] = _first(r["dhcp.option.vendor_class_id"])
            for k in ("dhcp.option.requested_ip_address", "dhcp.ip.client"):
                v = _first(r.get(k, ""))
                if v and v != "0.0.0.0":
                    mac_ips[dmac].add(v)
            continue
        if not src:
            continue
        h = host(src)
        if t == t:          # not NaN
            h["first"] = t if h["first"] is None else min(h["first"], t)
            h["last"] = t if h["last"] is None else max(h["last"], t)
        if "mdns" in protos:
            # mDNS answers: "<name>.local has address <ip>"
            for name, addr in zip(r.get("dns.resp.name", "").split("|"), r.get("dns.a", "").split("|"),
                                  strict=False):
                if name and addr and name.endswith(".local"):
                    nm = name.removesuffix(".local")
                    if nm not in host(addr)["names"]:
                        host(addr)["names"].append(nm)
            continue
        if "llmnr" in protos or "nbns" in protos:
            continue
        if "dns" in protos and r.get("dns.flags.response", "").split("|")[0] in ("False", "0"):
            bump(h["dns"], _first(r.get("dns.qry.name", "")).rstrip(".").lower())
        if "1" in r.get("tls.handshake.type", "").split("|"):
            bump(h["sni"], _first(r.get("tls.handshake.extensions_server_name", "")).lower())
        method = _first(r.get("http.request.method", ""))
        if method and "ssdp" not in protos:
            hh = _first(r.get("http.host", ""))
            bump(h["http"], f"{method} {hh}{_strip_query(_first(r.get('http.request.uri', '')))}")
    for mac, ips in mac_ips.items():
        for ip in ips:
            h = host(ip)
            if mac not in h["macs"]:
                h["macs"].append(mac)
            if mac_vendor.get(mac) and not h["vendor"]:
                h["vendor"] = mac_vendor[mac]
            info = mac_info.get(mac, {})
            if info.get("name") and info["name"] not in h["names"]:
                h["names"].insert(0, info["name"])
            if info.get("dhcp_vendor"):
                h["dhcp_vendor"] = info["dhcp_vendor"]
    return hosts


@dataclass
class Event:
    kind: str           # cleartext_login / name_broadcast / wpad / upnp / smb1 / tls_server / tls_client / weak_cipher
                        # / plain_dns
    client: str         # who sent it
    server: str         # who it was sent to ("" for broadcasts)
    proto: str          # "FTP", "HTTP Basic", "LLMNR", "TLS 1.0", ...
    port: str = ""      # "21/tcp"
    detail: str = ""    # safe detail: names queried, SNI, masked community. Never a secret.
    count: int = 1
    severity: str = ""  # optional override (weak cipher / masked SNMP default)


def _first(v: str) -> str:
    return v.split("|")[0] if v else ""


def _int(v: str) -> int | None:
    try:
        return int(v, 0)
    except (TypeError, ValueError):
        return None


def mask(secret: str) -> str:
    if secret in DEFAULT_SNMP:
        return f"'{secret}' (factory default)"
    return f"'{secret[0]}{'*' * max(0, len(secret) - 2)}{secret[-1] if len(secret) > 1 else ''}'"


def parse_fields(text: str) -> list[Event]:
    """Turn tshark -T fields output (with header) into de-duplicated events.
    Only names/schemes/masked values are kept from each row."""
    lines = text.splitlines()
    if not lines:
        return []
    header = lines[0].split("\t")
    agg: dict[tuple, Event] = {}

    def add(e: Event):
        k = (e.kind, e.client, e.server, e.proto, e.port, e.detail)
        if k in agg:
            agg[k].count += 1
        else:
            agg[k] = e

    for line in lines[1:]:
        cols = line.split("\t")
        r = dict(zip(header, cols + [""] * (len(header) - len(cols)), strict=False))
        protos = r.get("frame.protocols", "").split(":")
        if "icmp" in protos or "icmpv6" in protos:
            continue                    # ICMP errors quoting the original packet: not a second event
        src = _first(r.get("ip.src") or r.get("ipv6.src", ""))
        dst = _first(r.get("ip.dst") or r.get("ipv6.dst", ""))
        tport, uport = _first(r.get("tcp.dstport", "")), _first(r.get("udp.dstport", ""))
        port = f"{tport}/tcp" if tport else (f"{uport}/udp" if uport else "")

        def cl(proto, detail="", src=src, dst=dst, port=port):
            add(Event("cleartext_login", src, dst, proto, port, detail))

        ftp = r.get("ftp.request.command", "").upper().split("|")
        if "USER" in ftp or "PASS" in ftp:
            cl("FTP")
        if "telnet" in protos and tport in ("23", "992"):      # client -> server only (not the server's echo)
            cl("Telnet")
        pop = r.get("pop.request.command", "").upper().split("|")
        if {"USER", "PASS", "APOP", "AUTH"} & set(pop):
            cl("POP3")
        imap = r.get("imap.request.command", "").upper().split("|")
        if {"LOGIN", "AUTHENTICATE"} & set(imap):
            cl("IMAP")
        if "AUTH" in r.get("smtp.req.command", "").upper().split("|"):
            cl("SMTP AUTH")
        auth = r.get("http.authorization", "")
        scheme = auth.split()[0].capitalize() if auth.strip() else ""
        method = _first(r.get("http.request.method", ""))
        host = _first(r.get("http.host", ""))
        if "ssdp" in protos:
            if method == "NOTIFY":
                add(Event("upnp", src, "", "SSDP/UPnP", port, "advertises itself (NOTIFY)"))
            continue
        if scheme == "Basic":
            cl("HTTP Basic auth", f"Host: {host}" if host else "")
        keys = [k for k in r.get("urlencoded-form.key", "").split("|") if k]
        pw_keys = [k for k in keys if re.search(r"pass|pwd|secret|pin\b", k, re.I)]
        if method == "POST" and pw_keys:
            cl("HTTP login form", f"Host: {host}, field '{pw_keys[0]}'" if host else f"field '{pw_keys[0]}'")
        comm = _first(r.get("snmp.community", ""))
        if comm:
            ver = {"0": "v1", "1": "v2c"}.get(_first(r.get("snmp.version", "")), "")
            add(Event("cleartext_login", src, dst, f"SNMP{(' ' + ver) if ver else ''}", port, f"community {mask(comm)}",
                      severity="High" if comm in DEFAULT_SNMP else "Medium"))
        if r.get("smb.cmd"):
            server = dst if tport in ("445", "139") else src
            client = src if server == dst else dst
            add(Event("smb1", client, server, "SMBv1", f"{tport or '445'}/tcp"))
        if "llmnr" in protos or "nbns" in protos or "mdns" in protos:
            name = (r.get("nbns.name") or r.get("dns.qry.name", "")).split("|")[0]
            proto = "LLMNR" if "llmnr" in protos else "NBT-NS" if "nbns" in protos else "mDNS"
            add(Event("name_broadcast", src, "", proto, port, name))
            if re.match(r"^wpad\b", name, re.I):
                add(Event("wpad", src, "", proto, port, name))
            continue
        if "dns" in protos and r.get("dns.flags.response", "").split("|")[0] in ("False", "0"):
            name = _first(r.get("dns.qry.name", ""))
            add(Event("plain_dns", src, dst, "DNS", port, ""))
            if re.match(r"^wpad[.]", name, re.I):
                add(Event("wpad", src, dst, "DNS", port, name))
        types = r.get("tls.handshake.type", "").split("|")
        if "1" in types or "2" in types:
            sni = _first(r.get("tls.handshake.extensions_server_name", ""))
            supported = [_int(v) for v in r.get("tls.handshake.extensions.supported_version", "").split("|") if v]
            hv = _int(_first(r.get("tls.handshake.version", "")))
            if "2" in types:            # ServerHello: what the server actually chose
                ver = supported[0] if supported else hv
                if ver is not None and ver < 0x0303:
                    add(Event("tls_server", dst, src, TLS_VERSIONS.get(ver, hex(ver)), _src_port(r), sni))
                cs = _int(_first(r.get("tls.handshake.ciphersuite", "")))
                if cs in WEAK_CIPHERS:
                    fam, sev = WEAK_CIPHERS[cs]
                    add(Event("weak_cipher", dst, src, f"{fam} cipher 0x{cs:04X}", _src_port(r), sni, severity=sev))
            elif "1" in types:          # ClientHello: the newest version the client can do
                best = max([v for v in supported if v] or [hv or 0])
                if best and best < 0x0303:
                    add(Event("tls_client", src, dst, TLS_VERSIONS.get(best, hex(best)), port, sni))
    return sorted(agg.values(), key=lambda e: (e.kind, e.server, e.client, e.proto))


def _src_port(r: dict) -> str:
    """In a ServerHello the server is the sender, so its port is the TCP source port."""
    p = _first(r.get("tcp.srcport", ""))
    return f"{p}/tcp" if p else ""


# ---- statistics ----

@dataclass
class Conversation:
    a: str
    b: str
    frames: int
    bytes: int


@dataclass
class Endpoint:
    address: str
    packets: int
    bytes: int
    tx_packets: int
    tx_bytes: int
    rx_packets: int
    rx_bytes: int


@dataclass
class Flow:
    """One TCP/UDP conversation between two address:port pairs (tshark conv,tcp / conv,udp)."""
    proto: str          # "tcp" | "udp"
    a: str
    a_port: int
    b: str
    b_port: int
    frames_ab: int      # a -> b
    bytes_ab: int
    frames_ba: int      # b -> a
    bytes_ba: int
    start: float        # seconds from the start of the capture
    duration: float


@dataclass
class CaptureStats:
    packets: int = 0
    seconds: float = 0.0
    protocols: list[tuple[str, int, int]] = field(default_factory=list)   # (name, depth, frames)
    conversations: list[Conversation] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    activity: dict = field(default_factory=dict)        # ip -> per-device activity (see parse_activity)
    start_epoch: float | None = None                    # absolute time of the first packet
    local_nets: list[str] = field(default_factory=list)  # the capturing interface's networks (live captures)


_UNITS = {"bytes": 1, "": 1, "kB": 1000, "KiB": 1024, "MB": 10**6, "MiB": 2**20, "GB": 10**9, "GiB": 2**30}


def _nums(text: str) -> list[float]:
    """Numbers in a tshark statistics row, with byte units (kB, MiB, ...) applied."""
    pairs = re.findall(r"(\d+(?:\.\d+)?)\s*(bytes|kB|KiB|MB|MiB|GB|GiB)?", text)
    return [float(n) * _UNITS.get(u, 1) for n, u in pairs]


def _addr_port(tok: str) -> tuple[str, int] | None:
    addr, _, port = tok.rpartition(":")
    return (addr.strip("[]"), int(port)) if addr and port.isdigit() else None


def parse_stats(text: str) -> CaptureStats:
    st = CaptureStats()
    section = ""
    m = re.search(r"Duration:\s*([\d.]+)\s*secs", text)
    if m:
        st.seconds = float(m.group(1))
    for line in text.splitlines():
        if "Protocol Hierarchy Statistics" in line:
            section = "phs"
            continue
        if re.search(r"IPv[46] Conversations", line):
            section = "conv"
            continue
        m = re.search(r"(TCP|UDP) Conversations", line)
        if m:
            section = m.group(1).lower()
            continue
        if re.search(r"IPv[46] Endpoints", line):
            section = "endpoints"
            continue
        if line.startswith("=====") or "IO Statistics" in line:
            section = "" if "IO Statistics" in line else section
            continue
        if section == "phs":
            m = re.match(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)", line)
            if m:
                st.protocols.append((m.group(2), len(m.group(1)) // 2, int(m.group(3))))
        elif section == "conv":
            m = re.match(r"^(\S+)\s+<->\s+(\S+)\s+(.*)$", line)
            if m:
                nums = re.findall(r"(\d+(?:\.\d+)?)\s*(bytes|kB|KiB|MB|MiB|GB|GiB)?", m.group(3))
                if len(nums) >= 6:
                    total_frames = int(float(nums[4][0]))
                    total_bytes = int(float(nums[5][0]) * _UNITS.get(nums[5][1], 1))
                    st.conversations.append(Conversation(m.group(1), m.group(2), total_frames, total_bytes))
        elif section in ("tcp", "udp"):
            m = re.match(r"^(\S+)\s+<->\s+(\S+)\s+(.*)$", line)
            a, b = (_addr_port(m.group(1)), _addr_port(m.group(2))) if m else (None, None)
            if a and b:
                n = _nums(m.group(3))
                if len(n) >= 8:
                    st.flows.append(Flow(section, a[0], a[1], b[0], b[1], int(n[2]), int(n[3]), int(n[0]), int(n[1]),
                                         n[6], n[7]))
        elif section == "endpoints":
            m = re.match(r"^(\S+)\s+(\d.*)$", line)
            if m:
                n = _nums(m.group(2))
                if len(n) >= 6:
                    st.endpoints.append(Endpoint(m.group(1), *(int(x) for x in n[:6])))
    if st.protocols:
        st.packets = st.protocols[0][2]
    st.conversations.sort(key=lambda c: -c.bytes)
    return st


# ---- findings ----

_CLEAR_FIX = {
    "FTP": "Switch to SFTP (part of SSH) or FTPS, and turn plain FTP off on the server.",
    "Telnet": "Disable Telnet on the device and use SSH instead.",
    "POP3": "Use POP3 over TLS (port 995) in the mail client and disable plain port 110 on the server.",
    "IMAP": "Use IMAP over TLS (port 993) in the mail client and disable plain port 143 on the server.",
    "SMTP AUTH": "Require STARTTLS before AUTH (or use port 465/587 with TLS) and refuse AUTH on unencrypted "
                 "connections.",
    "HTTP Basic auth": "Serve the admin page over HTTPS only (redirect HTTP to HTTPS); Basic auth over plain HTTP "
                       "sends the password with every request.",
    "HTTP login form": "Serve the login page and its form target over HTTPS only (redirect HTTP to HTTPS, add HSTS).",
}


def _sev_for(e: Event) -> str:
    return e.severity or "High"


def findings(events: list[Event], labels: dict[str, str] | None = None, source: str = "capture") -> list[Finding]:
    """Group events into findings. Devices are IP addresses (they merge with nmap hosts)."""
    labels = labels or {}

    def lab(ip):
        return labels.get(ip, ip)

    def clients(evs):
        cs = sorted({e.client for e in evs if e.client})
        return ", ".join(lab(c) for c in cs[:8]) + (f" and {len(cs) - 8} more" if len(cs) > 8 else "")

    def n(evs):
        return sum(e.count for e in evs)

    out: list[Finding] = []
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        groups[(e.kind, e.server if e.kind not in ("name_broadcast", "wpad", "upnp", "tls_client", "plain_dns")
                else e.client, e.proto)].append(e)
    src = f"Traffic audit ({source})"
    for (kind, dev, proto), evs in sorted(groups.items()):
        port = evs[0].port
        common = dict(device=dev, device_label=lab(dev), port=port, source=src, confidence="seen on the network")
        if kind == "cleartext_login":
            sev = max((_sev_for(e) for e in evs), key=lambda s: -SEV_WEIGHT[s])
            snmp = proto.startswith("SNMP")
            details = sorted({e.detail for e in evs if e.detail})
            out.append(Finding(
                kind="traffic", title=(f"Traffic: {proto} community string sent unencrypted" if snmp else
                                       f"Traffic: password sent unencrypted ({proto})"),
                severity=sev,
                description=(f"Unencrypted {proto} {'requests' if snmp else 'login commands'} to {lab(dev)} "
                             f"({port}) from {clients(evs)} were readable on the network "
                             f"({n(evs)} packet{'s' if n(evs) != 1 else ''})."
                             + (f" ({'; '.join(details[:4])})" if details else "") +
                             "\n\nWatchtower saw the login commands but does not record or show the user names "
                             "or passwords. Anyone else who can see this traffic can read them."),
                technique=("**Network sniffing:** on shared Wi-Fi, a compromised device, or a switch port mirror, "
                           "an attacker collects passwords sent without encryption with tools like Wireshark."),
                remediation=(_CLEAR_FIX.get(proto) or
                             ("Use SNMPv3 with authPriv (authentication + encryption), or disable SNMP if nothing "
                              "uses it; at minimum replace the default community." if snmp else
                              "Switch to the encrypted version of the protocol.")),
                service=f"{port} {proto}", attck=["T1040", "T1552"] if not snmp else ["T1040", "T1602.001"],
                weight=SEV_WEIGHT[sev], **common))
        elif kind == "smb1":
            out.append(Finding(
                kind="traffic", title="Traffic: SMBv1 in use", severity="High",
                description=f"SMB version 1 traffic to {lab(dev)} from {clients(evs)} ({n(evs)} packet(s)).",
                technique=("SMBv1 is the protocol behind EternalBlue / WannaCry (MS17-010). It has no protection "
                           "against tampering and is deprecated by Microsoft."),
                remediation=("Disable SMBv1 on the server (Windows: `Disable-WindowsOptionalFeature -Online "
                             "-FeatureName SMB1Protocol`; Samba: `server min protocol = SMB2_10`) and update any "
                             "old client that still needs it."),
                service=f"{port} SMB", attck=["T1210"], weight=SEV_WEIGHT["High"], **common))
        elif kind in ("name_broadcast", "wpad"):
            if kind == "wpad":
                sev, title = "Medium", "Traffic: looks up WPAD (automatic proxy discovery)"
                tech = ("**WPAD spoofing:** any device on the network can answer the 'wpad' lookup and become this "
                        "computer's web proxy, seeing and changing its web traffic.")
                fix = ("Turn off 'Automatically detect settings' in the OS proxy settings (Windows: Settings > "
                       "Network > Proxy), unless your network really uses WPAD.")
            elif proto == "mDNS":
                sev, title = "Info", "Traffic: uses mDNS / Bonjour"
                tech = ("mDNS (Bonjour/Avahi) announces and finds devices on the local network. It's normal for "
                        "printers, Apple devices and Chromecasts, and it tells anyone on the network what they are.")
                fix = "No change needed on a home network. Disable it on servers that don't need discovery."
            else:
                sev, title = "Medium", f"Traffic: broadcasts {proto} name lookups"
                tech = ("**LLMNR/NBT-NS poisoning:** when normal DNS can't answer, Windows asks the whole network. "
                        "Any device can answer 'that's me', and the computer then sends it a Windows login "
                        "(NTLM hash) that can be cracked or relayed. This is exactly what the tool Responder does.")
                fix = ("Disable LLMNR (Group Policy: Computer Configuration > Administrative Templates > Network > "
                       "DNS Client > Turn off multicast name resolution) and NetBIOS over TCP/IP (network adapter "
                       "> IPv4 > Advanced > WINS > Disable NetBIOS). On Linux: `LLMNR=no` in "
                       "/etc/systemd/resolved.conf.")
            names = sorted({e.detail for e in evs if e.detail})
            out.append(Finding(
                kind="traffic", title=title, severity=sev,
                description=(f"{lab(dev)} sent {n(evs)} {proto} quer{'y' if n(evs) == 1 else 'ies'}"
                             + (f" for: {', '.join(names[:10])}" if names else "") + "."),
                technique=tech, remediation=fix, service=f"{port} {proto}",
                attck=["T1557.001"] if sev != "Info" else ["T1046"], weight=SEV_WEIGHT[sev], **common))
        elif kind == "upnp":
            out.append(Finding(
                kind="traffic", title="Traffic: advertises UPnP (SSDP)", severity="Low",
                description=f"{lab(dev)} announced itself with SSDP NOTIFY ({n(evs)} time(s)).",
                technique=("UPnP lets programs on the network change the device's settings without a password; on a "
                           "router that means opening ports to the internet. Malware uses it to expose itself."),
                remediation=("On the router, turn UPnP off unless a game console or app needs it. On other devices, "
                             "disable UPnP/DLNA in their settings if you don't use media sharing."),
                service=f"{port} SSDP", attck=["T1046"], weight=SEV_WEIGHT["Low"], **common))
        elif kind in ("tls_server", "weak_cipher"):
            sev = (evs[0].severity or "High") if kind == "weak_cipher" else ("High" if proto == "SSL 3.0" else "Medium")
            snis = sorted({e.detail for e in evs if e.detail})
            out.append(Finding(
                kind="traffic", title=(f"Traffic: server negotiated {proto}" if kind == "tls_server" else
                                       f"Traffic: server chose a {proto}"),
                severity=sev,
                description=(f"{lab(dev)} completed TLS handshakes using {proto} with {clients(evs)}"
                             + (f" (server name: {', '.join(snis[:4])})" if snis else "") + "."),
                technique=("Old TLS versions and broken ciphers let an attacker in the middle downgrade or decrypt "
                           "the connection (POODLE, BEAST, SWEET32, RC4 biases)."),
                remediation=("Allow only TLS 1.2 and 1.3 with modern AEAD ciphers on the server; update the "
                             "firmware/software if it can't. Run the TLS audit in Host Audit for the full list."),
                service="TLS", attck=["T1557", "T1040"], weight=SEV_WEIGHT[sev], **common))
        elif kind == "tls_client":
            out.append(Finding(
                kind="traffic", title=f"Traffic: client only supports {proto}", severity="Low",
                description=(f"{lab(dev)} offered at most {proto} when connecting to "
                             f"{', '.join(sorted({lab(e.server) for e in evs}))}."),
                technique="A client stuck on old TLS can't use modern protection and is often unpatched software.",
                remediation="Update the software or device; if it can't be updated, isolate it on its own network.",
                service="TLS", attck=["T1557"], weight=SEV_WEIGHT["Low"], **common))
        elif kind == "plain_dns":
            resolvers = sorted({e.server for e in evs})
            public = [r for r in resolvers if _is_public(r)]
            out.append(Finding(
                kind="traffic", title="Traffic: unencrypted DNS lookups", severity="Info",
                description=(f"{lab(dev)} sent {n(evs)} plain DNS quer{'y' if n(evs) == 1 else 'ies'} to "
                             f"{', '.join(resolvers)}."
                             + (f" {', '.join(public)} {'is a' if len(public) == 1 else 'are'} public resolver(s) "
                                "instead of your router: some devices hard-code one, which bypasses any filtering "
                                "you set up." if public else "")),
                technique="Plain DNS shows every site a device visits to anyone on the path, and can be spoofed.",
                remediation=("Normal on most home networks. For privacy, enable DNS over HTTPS/TLS in the browser "
                             "or router."),
                service=f"{port} DNS", attck=["T1040"], weight=0, **common))
    return out


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast)
    except ValueError:
        return False


# ---- history (What Changed) ----

def event_keys(events: list[Event]) -> dict[str, str]:
    """Stable identity of the things a capture showed -> human title."""
    out = {}
    for f in findings(events):
        out[f"{f.device}|{f.title}"] = f"{f.severity}: {f.title} ({f.device})"
    return out


def diff_captures(old: list[Event], new: list[Event]):
    """Changes between two captures, as history_diff.Change records."""
    from watchtower.core.history_diff import Change, sort_changes
    a, b = event_keys(old), event_keys(new)
    out = []
    for k in sorted(b.keys() - a.keys()):
        sev = b[k].split(":")[0]
        out.append(Change("alert" if sev in ("Critical", "High", "Medium") else "notice", "traffic",
                          k.split("|")[0], "New in traffic", b[k]))
    for k in sorted(a.keys() - b.keys()):
        out.append(Change("good", "traffic", k.split("|")[0], "Not seen this time", a[k]))
    return sort_changes(out)


# ---- serialization ----

def events_to_json(events: list[Event]) -> str:
    return json.dumps([asdict(e) for e in events])


def events_from_json(text: str) -> list[Event]:
    return [Event(**d) for d in json.loads(text or "[]")]


def stats_to_json(st: CaptureStats) -> str:
    return json.dumps(asdict(st))


def stats_from_json(text: str) -> CaptureStats:
    d = json.loads(text or "{}")
    if not d:
        return CaptureStats()
    return CaptureStats(d.get("packets", 0), d.get("seconds", 0.0), [tuple(p) for p in d.get("protocols", [])],
                        [Conversation(**c) for c in d.get("conversations", [])],
                        [Endpoint(**e) for e in d.get("endpoints", [])], [Flow(**f) for f in d.get("flows", [])],
                        d.get("activity", {}), d.get("start_epoch"), d.get("local_nets", []))


# ---- running an analysis (shared by the tab and scheduled captures) ----

@dataclass
class Analysis:
    events: list[Event]
    stats: CaptureStats
    error: str = ""


def unreadable_reason(pcap: str) -> str:
    """Why Watchtower itself can't read a capture file ("" if it can)."""
    import os
    try:
        with open(pcap, "rb") as f:
            f.read(1)
        return ""
    except FileNotFoundError:
        return f"The capture file no longer exists: {pcap}"
    except PermissionError:
        owner = ""
        try:
            import pwd
            owner = pwd.getpwuid(os.stat(pcap).st_uid).pw_name
        except (ImportError, KeyError, OSError):
            pass
        return (f"Watchtower can't read {pcap}" + (f" (it belongs to '{owner}')" if owner else "") +
                ". If dumpcap is installed setuid root, files it writes belong to root: reinstall it with "
                "capabilities instead (sudo dpkg-reconfigure wireshark-common, answer Yes), or fix the owner with "
                f"sudo chown $USER {pcap}")
    except OSError as exc:
        return f"Can't read {pcap}: {exc}"


def analyze_pcap(runner, pcap: str, target: str | None = None, local_nets: list[str] | None = None) -> Analysis:
    """Run tshark (fields + statistics) on a capture file. Blocking. Watchtower opens the file
    and pipes it to tshark, so AppArmor path rules on tshark don't matter. The tshark output is
    parsed in memory only; CommandRunner logs commands, not output."""
    if not tshark_binary():
        return Analysis([], CaptureStats(), "tshark is not installed (sudo apt install tshark).")
    why = unreadable_reason(pcap)
    if why:
        return Analysis([], CaptureStats(), why)
    res = runner.run(fields_argv(), purpose="Traffic audit: analyze capture (tshark)", target=target,
                     timeout=1800, stdin_file=pcap)
    if res.exit_code != 0 and not res.stdout.strip():
        err = (res.stderr.strip().splitlines() or [f"tshark exit {res.exit_code}"])[-1]
        return Analysis([], CaptureStats(), f"tshark couldn't read the capture: {err}")
    events = parse_fields(res.stdout)
    st = parse_stats(runner.run(stats_argv(), purpose="Traffic audit: statistics (tshark)", target=target,
                                timeout=1800, stdin_file=pcap).stdout)
    st.local_nets = list(local_nets or [])
    act = runner.run(activity_argv(), purpose="Traffic audit: who each device is and what it asked for (tshark)",
                     target=target, timeout=1800, stdin_file=pcap)
    st.activity = parse_activity(act.stdout, st.local_nets)
    first = runner.run(first_packet_argv(), purpose="Traffic audit: capture start time (tshark)", target=target,
                       timeout=120, stdin_file=pcap)
    try:
        st.start_epoch = float(first.stdout.split()[0])
    except (IndexError, ValueError):
        st.start_epoch = None
    return Analysis(events, st)


def capture_dir():
    from watchtower.core.platform_utils import data_dir
    d = data_dir() / "captures"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def new_capture_path(interface: str) -> str:
    from datetime import datetime
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return str(capture_dir() / f"{stamp}-{re.sub(r'[^A-Za-z0-9_.-]', '_', interface)}.pcapng")


def monitor_interfaces(runner) -> set[str]:
    """Wireless interfaces currently in monitor mode (empty if iw isn't available)."""
    try:
        from watchtower.core import interfaces
        return {w.name for w in interfaces.list_wireless(runner) if w.in_monitor_mode}
    except Exception:  # noqa: BLE001 - iw missing / not Linux: nothing is in monitor mode
        return set()


def capture_error(stderr: str, exit_code: int) -> str:
    """A plain-language reason a capture failed."""
    text = stderr or ""
    if re.search(r"permission|Operation not permitted|don't have permission", text, re.I):
        return ("No permission to capture. Grant it once: Settings > Dependency Check > 'Grant capabilities' "
                "(covers dumpcap), or add yourself to the 'wireshark' group and log in again.")
    if re.search(r"no such device|doesn't exist|There is no device", text, re.I):
        return "That interface doesn't exist (anymore). Pick another one."
    if re.search(r"syntax error|can't parse filter|Invalid capture filter", text, re.I):
        return "The capture filter isn't valid BPF syntax. Example: host 192.168.1.10 and port 80"
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    return lines[-1][:300] if lines else f"dumpcap exited with code {exit_code}"


def capture_permission() -> tuple[bool | None, str]:
    """Best-effort check, without running anything, whether dumpcap can capture.
    (True, why) / (False, why) / (None, why) when it can't be told (e.g. Windows: Npcap decides)."""
    import os
    import stat
    import sys

    path = capture_binary()
    if not path:
        return False, "dumpcap is not installed (sudo apt install tshark)."
    if not sys.platform.startswith("linux"):
        return None, "Capture permission is handled by Npcap / the OS."
    if os.geteuid() == 0:
        return True, "Running as root."
    real = os.path.realpath(path)
    try:
        if os.getxattr(real, "security.capability"):
            return True, "dumpcap has packet-capture capabilities."
    except OSError:
        pass
    try:
        if os.stat(real).st_mode & stat.S_ISUID:
            return True, "dumpcap is installed setuid for capturing."
    except OSError:
        pass
    return False, ("dumpcap doesn't have permission to capture yet. Click 'Allow capturing' once (it runs "
                   "setcap on dumpcap after asking for your password).")


DURATIONS = {"30 seconds": 30, "1 minute": 60, "2 minutes": 120, "5 minutes": 300, "15 minutes": 900,
             "30 minutes": 1800, "1 hour": 3600}


def local_interfaces() -> list[str]:
    """Interface names without running anything (Linux/macOS); [] if unavailable."""
    import socket
    try:
        return [name for _i, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        return []
