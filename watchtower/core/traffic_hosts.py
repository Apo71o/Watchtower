"""Per-device rundown of a traffic capture: for every IP address, who it is and what it did.

Built from tshark's endpoint/conversation tables and the activity pass (traffic_audit.CaptureStats),
the capture's findings, and (optionally) nmap results for the same addresses. Pure functions,
no Qt, so the Traffic Audit tab, the Findings tab and the report share them.

Only metadata is shown: addresses, ports, byte counts, DNS names, TLS server names (SNI) and
HTTP host + path (query strings dropped). Never payloads, cookies or credentials.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone

from watchtower.core import traffic_audit as ta
from watchtower.core.findings_engine import SEV_RANK, Finding

# Names for ports /etc/services may not know (or names it gets less clearly).
PORT_NAMES = {
    (53, "udp"): "DNS", (53, "tcp"): "DNS", (67, "udp"): "DHCP", (68, "udp"): "DHCP",
    (80, "tcp"): "HTTP (web, unencrypted)", (443, "tcp"): "HTTPS (web)", (443, "udp"): "QUIC (encrypted web)",
    (853, "tcp"): "DNS over TLS", (21, "tcp"): "FTP (unencrypted)", (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet (unencrypted)", (25, "tcp"): "SMTP (mail)",
    (110, "tcp"): "POP3 (mail, unencrypted)", (143, "tcp"): "IMAP (mail, unencrypted)", (993, "tcp"): "IMAPS (mail)",
    (995, "tcp"): "POP3S (mail)", (587, "tcp"): "SMTP submission", (123, "udp"): "NTP (time)",
    (137, "udp"): "NetBIOS names", (139, "tcp"): "NetBIOS/SMB", (445, "tcp"): "SMB (file sharing)",
    (161, "udp"): "SNMP", (1900, "udp"): "SSDP (UPnP discovery)", (5353, "udp"): "mDNS (Bonjour)",
    (5355, "udp"): "LLMNR", (3389, "tcp"): "RDP (remote desktop)", (5900, "tcp"): "VNC", (8080, "tcp"): "HTTP alt",
    (8443, "tcp"): "HTTPS alt", (1883, "tcp"): "MQTT (IoT messaging)", (8883, "tcp"): "MQTT over TLS",
    (554, "tcp"): "RTSP (camera video)", (5000, "tcp"): "UPnP/web", (8123, "tcp"): "Home Assistant",
    (631, "tcp"): "IPP (printing)", (9100, "tcp"): "printer (raw)", (3478, "udp"): "STUN (calls/video)",
}
_EPHEMERAL = 32768


def port_name(port: int, proto: str) -> str:
    if (port, proto) in PORT_NAMES:
        return PORT_NAMES[(port, proto)]
    try:
        return socket.getservbyport(port, proto)
    except (OSError, OverflowError):
        return ""


def server_side(f: ta.Flow) -> tuple[str, int, str, int]:
    """(server, server_port, client, client_port): the side on the well-known / lower port serves."""
    a_known = (f.a_port, f.proto) in PORT_NAMES or f.a_port < 1024
    b_known = (f.b_port, f.proto) in PORT_NAMES or f.b_port < 1024
    if b_known and not a_known:
        return f.b, f.b_port, f.a, f.a_port
    if a_known and not b_known:
        return f.a, f.a_port, f.b, f.b_port
    if f.b_port <= f.a_port:
        return f.b, f.b_port, f.a, f.a_port
    return f.a, f.a_port, f.b, f.b_port


@dataclass
class Peer:
    address: str
    packets: int = 0
    bytes: int = 0


@dataclass
class Service:
    peer: str            # the server (for services used) or the client (for services offered)
    port: int
    proto: str
    name: str
    connections: int = 0
    bytes: int = 0


@dataclass
class HostRundown:
    ip: str
    label: str = ""                  # nmap label if scanned, else ip
    local: bool = True               # on your network
    macs: list[str] = field(default_factory=list)
    vendor: str = ""                 # maker from the MAC address
    names: list[str] = field(default_factory=list)   # DHCP / mDNS / nmap host names
    os_hint: str = ""                # DHCP vendor class (e.g. "MSFT 5.0", "android-dhcp-13")
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    bytes_received: int = 0
    peers: list[Peer] = field(default_factory=list)
    services_used: list[Service] = field(default_factory=list)
    services_offered: list[Service] = field(default_factory=list)
    dns: dict = field(default_factory=dict)
    sites: dict = field(default_factory=dict)       # TLS server names
    http: dict = field(default_factory=dict)        # "METHOD host/path"
    findings: list[Finding] = field(default_factory=list)
    first: float | None = None                      # seconds into the capture
    last: float | None = None
    open_ports: list[str] = field(default_factory=list)   # from nmap, if this address was scanned
    seen_in_traffic: bool = True                    # False: only known from a ping/nmap scan
    local_nets: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        name = self.names[0] if self.names else ""
        if self.label and self.label != self.ip:
            return self.label
        return f"{self.ip} ({name})" if name else self.ip

    @property
    def outside_peers(self) -> list[Peer]:
        return [p for p in self.peers if where(p.address, self.local_nets) == "internet"]

    @property
    def unicast_peers(self) -> list[Peer]:
        return [p for p in self.peers if ta.is_unicast(p.address)]


def where(ip: str, local_nets: list[str] | None = None) -> str:
    if not ta.is_unicast(ip):
        return "broadcast (your network)"
    return "your network" if ta.is_lan(ip, local_nets) else "internet"


def rundown(stats: ta.CaptureStats, events: list[ta.Event] | None = None, labels: dict | None = None,
            nmap_hosts: dict | None = None, extra_devices: list[str] | None = None) -> list[HostRundown]:
    """Every unicast address in the capture (plus `extra_devices`, e.g. found by a ping scan), local
    devices first, then outside addresses; each sorted by traffic volume."""
    labels = labels or {}
    nmap_hosts = nmap_hosts or {}
    nets = stats.local_nets
    hosts: dict[str, HostRundown] = {}

    def get(ip: str) -> HostRundown:
        if ip not in hosts:
            hosts[ip] = HostRundown(ip, labels.get(ip, ip), ta.is_lan(ip, nets), local_nets=list(nets))
        return hosts[ip]

    for e in stats.endpoints:
        if not ta.is_unicast(e.address):
            continue
        h = get(e.address)
        h.packets_sent, h.bytes_sent = e.tx_packets, e.tx_bytes
        h.packets_received, h.bytes_received = e.rx_packets, e.rx_bytes
    peers: dict[str, dict[str, Peer]] = {}
    for c in stats.conversations:
        for me, other in ((c.a, c.b), (c.b, c.a)):
            if ta.is_unicast(me):
                p = peers.setdefault(me, {}).setdefault(other, Peer(other))
                p.packets += c.frames
                p.bytes += c.bytes
    for ip, ps in peers.items():
        get(ip).peers = sorted(ps.values(), key=lambda p: -p.bytes)
    used: dict[tuple, Service] = {}
    offered: dict[tuple, Service] = {}
    for f in stats.flows:
        server, sport, client, _cport = server_side(f)
        nbytes = f.bytes_ab + f.bytes_ba
        for ip, t in ((client, f.start), (client, f.start + f.duration), (server, f.start),
                      (server, f.start + f.duration)):
            if ta.is_unicast(ip):
                h = get(ip)
                h.first = t if h.first is None else min(h.first, t)
                h.last = t if h.last is None else max(h.last, t)
        name = port_name(sport, f.proto)
        if ta.is_unicast(client):
            s = used.setdefault((client, server, sport, f.proto), Service(server, sport, f.proto, name))
            s.connections += 1
            s.bytes += nbytes
        if ta.is_unicast(server):
            s = offered.setdefault((server, client, sport, f.proto), Service(client, sport, f.proto, name))
            s.connections += 1
            s.bytes += nbytes
    for (ip, *_), s in used.items():
        get(ip).services_used.append(s)
    for (ip, *_), s in offered.items():
        get(ip).services_offered.append(s)
    for ip, act in (stats.activity or {}).items():
        if not ta.is_unicast(ip):
            continue
        h = get(ip)
        h.macs = act.get("macs", [])
        h.vendor = act.get("vendor", "")
        h.names = list(act.get("names", []))
        h.os_hint = act.get("dhcp_vendor", "")
        h.dns, h.sites, h.http = act.get("dns", {}), act.get("sni", {}), act.get("http", {})
        for k in ("first", "last"):
            if act.get(k) is not None:
                cur = getattr(h, k)
                setattr(h, k, act[k] if cur is None else (min if k == "first" else max)(cur, act[k]))
    for ip in extra_devices or []:
        if ip not in hosts:
            get(ip).seen_in_traffic = False
    for ip, (host, _scan) in nmap_hosts.items():
        if ip in hosts:
            h = hosts[ip]
            h.label = host.label
            for n in host.hostnames:
                if n not in h.names:
                    h.names.append(n)
            if host.mac and not h.macs:
                h.macs = [host.mac.lower()]
            if host.vendor and not h.vendor:
                h.vendor = host.vendor
            h.open_ports = [f"{p.portid}/{p.protocol} {p.service}".strip() for p in host.ports
                            if p.state.startswith("open")]
    for f in ta.findings(events or [], labels):
        if f.device in hosts:
            hosts[f.device].findings.append(f)
    for h in hosts.values():
        h.services_used.sort(key=lambda s: -s.bytes)
        h.services_offered.sort(key=lambda s: -s.bytes)
        h.findings.sort(key=lambda f: SEV_RANK[f.severity])
    return sorted(hosts.values(), key=lambda h: (not h.local, not h.seen_in_traffic,
                                                 -(h.bytes_sent + h.bytes_received), h.ip))


# ---- text ----

def size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _clock(stats: ta.CaptureStats, rel: float | None) -> str:
    if rel is None:
        return ""
    if stats.start_epoch:
        return datetime.fromtimestamp(stats.start_epoch + rel, timezone.utc).strftime("%H:%M:%S UTC")
    return f"{rel:.0f} s in"


def _c(v) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


def _top(d: dict, n: int = 15) -> list[tuple[str, int]]:
    return sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


SEV_ICON = {"Critical": "🔴", "High": "🔴", "Medium": "🟠", "Low": "🟡", "Info": "🔵"}


def summary_line(h: HostRundown) -> str:
    """One sentence a non-expert can read."""
    if not h.seen_in_traffic:
        return "Answered the network scan but sent no traffic while Watchtower was listening."
    bits = [f"sent {size(h.bytes_sent)} and received {size(h.bytes_received)}"]
    if h.unicast_peers:
        outside = len(h.outside_peers)
        bits.append(f"talked to {len(h.unicast_peers)} address(es)"
                    + (f", {outside} on the internet" if outside else ""))
    if h.dns:
        bits.append(f"looked up {len(h.dns)} name(s)")
    if h.services_offered:
        ports = sorted({f"{s.port}/{s.proto}" for s in h.services_offered})
        bits.append("served " + ", ".join(ports[:5]) + (" …" if len(ports) > 5 else ""))
    return "This device " + "; ".join(bits) + "."


def host_markdown(h: HostRundown, stats: ta.CaptureStats, labels: dict | None = None) -> str:
    labels = labels or {}

    def lab(ip):
        return labels.get(ip, ip)

    place = "on your network" if h.local else "outside your network (internet)"
    lines = [f"## {h.title}", "", f"*{place}* · {summary_line(h)}", "", "### Who it is", "",
             "| What | Value |", "|---|---|", f"| Address | {h.ip} |"]
    if h.names:
        lines.append(f"| Name(s) | {_c(', '.join(h.names))} |")
    if h.macs:
        lines.append(f"| MAC address | {_c(', '.join(h.macs))} |")
    if h.vendor:
        lines.append(f"| Maker (from MAC) | {_c(h.vendor)} |")
    if h.os_hint:
        lines.append(f"| System hint (DHCP) | {_c(h.os_hint)} |")
    if h.first is not None:
        lines.append(f"| Active | {_clock(stats, h.first)} – {_clock(stats, h.last)} |")
    lines.append(f"| Traffic | sent {size(h.bytes_sent)} ({h.packets_sent} packets), received "
                 f"{size(h.bytes_received)} ({h.packets_received} packets) |")
    if h.open_ports:
        lines.append(f"| Open ports (nmap) | {_c(', '.join(h.open_ports[:12]))} |")
    lines.append("")
    if h.findings:
        lines += ["### Problems seen", ""]
        lines += [f"- {SEV_ICON[f.severity]} **{f.severity}:** {f.title.removeprefix('Traffic: ')}" for f in h.findings]
        lines += ["", "*Details and fixes are under **What was found** and in the Findings tab.*", ""]
    if h.services_used:
        lines += ["### Services it used", "", "| Server | Service | Connections | Data |", "|---|---|---|---|"]
        for s in h.services_used[:20]:
            lines.append(f"| {_c(lab(s.peer))} | {s.port}/{s.proto} {_c(s.name)} | {s.connections} | {size(s.bytes)} |")
        lines.append("")
    if h.services_offered:
        lines += ["### Services it offered to others", "", "| Port | Service | Used by | Connections |",
                  "|---|---|---|---|"]
        for s in h.services_offered[:20]:
            lines.append(f"| {s.port}/{s.proto} | {_c(s.name)} | {_c(lab(s.peer))} | {s.connections} |")
        lines.append("")
    if h.dns:
        lines += ["### Names it looked up (DNS)", "", "| Name | Times |", "|---|---|"]
        lines += [f"| {_c(n)} | {k} |" for n, k in _top(h.dns, 25)]
        lines.append("")
    if h.sites:
        lines += ["### Encrypted sites it connected to (TLS server name)", "", "| Site | Connections |", "|---|---|"]
        lines += [f"| {_c(n)} | {k} |" for n, k in _top(h.sites, 25)]
        lines.append("")
    if h.http:
        lines += ["### Unencrypted web requests (HTTP)", "", "| Request | Times |", "|---|---|"]
        lines += [f"| `{_c(n)}` | {k} |" for n, k in _top(h.http, 25)]
        lines += ["", "*Query strings are not shown; they often contain session tokens.*", ""]
    if h.peers:
        lines += ["### Who it talked to", "", "| Address | Where | Packets | Data |", "|---|---|---|---|"]
        for p in h.peers[:20]:
            lines.append(f"| {_c(lab(p.address))} | {where(p.address, stats.local_nets)} | {p.packets} | "
                         f"{size(p.bytes)} |")
        lines.append("")
    return "\n".join(lines)


def host_brief(rows: list[dict], ip: str) -> list[str]:
    """Markdown lines for the Findings device pane: what the newest capture(s) saw this address do."""
    out: list[str] = []
    for row in rows:
        st = ta.stats_from_json(row.get("stats_json"))
        hs = [h for h in rundown(st) if h.ip == ip]
        if not hs:
            continue
        h = hs[0]
        src = row["source"].partition(":")[2].rsplit("/", 1)[-1]
        out += [f"### Traffic seen ({src})", "", summary_line(h), ""]
        if h.sites or h.dns:
            top = [n for n, _ in _top(h.sites or h.dns, 6)]
            out += [f"Top {'sites' if h.sites else 'names looked up'}: {', '.join(top)}", ""]
        if h.services_offered:
            out += ["Offered: " + ", ".join(sorted({f'{s.port}/{s.proto} {s.name}'.strip() for s in
                                                    h.services_offered})[:8]), ""]
    return out


# ---- finding quiet devices (opt-in nmap ping scan of the local network) ----

MAX_PING_PREFIX = 22      # at most a /22 (1,022 addresses); bigger networks must be scanned from Scan a Target


def interface_networks(runner, iface: str) -> list[str]:
    """The networks (CIDR) an interface is on, e.g. ['192.168.1.0/24'] (runs `ip -j addr`, Linux)."""
    from watchtower.core import interfaces
    try:
        addrs = interfaces.local_addresses(runner).get(iface, [])
    except Exception:  # noqa: BLE001 - no `ip` command / not Linux
        return []
    out = []
    for cidr in addrs:
        net = interfaces.network_of(cidr)
        if net not in out and not net.startswith(("127.", "fe80:", "::1")):
            out.append(net)
    return out


def ping_scan_networks(local_nets: list[str], authorized: list[str]) -> tuple[list[str], str]:
    """IPv4 networks that may be ping-scanned, or a reason why none can be."""
    import ipaddress

    from watchtower.core.targets import in_scope
    v4 = [n for n in local_nets if ipaddress.ip_network(n).version == 4]
    if not v4:
        return [], "Watchtower doesn't know this interface's network (no IPv4 address)."
    big = [n for n in v4 if ipaddress.ip_network(n).prefixlen < MAX_PING_PREFIX]
    if big:
        return [], (f"{big[0]} is too large for a quick sweep (more than /{MAX_PING_PREFIX}); scan it from "
                    "Scan a Target instead.")
    out = [n for n in v4 if in_scope(n, authorized)]
    if not out:
        return [], (f"{v4[0]} isn't in your authorized targets. Add it in Scan a Target (Add one of my "
                    "subnets…) to allow this.")
    return out, ""


def ping_scan(runner, scans, authorized: list[str], net: str) -> tuple[int | None, str]:
    """Run `nmap -sn` (Ping scan profile) on an authorized network and store it like any scan.
    Returns (scan id or None, status text)."""
    import tempfile
    from pathlib import Path

    from watchtower.core import deps, nmap_runner
    from watchtower.core.runner import format_command
    nmap = deps.find_binary("nmap")
    if not nmap:
        return None, "nmap is not installed"
    out = Path(tempfile.mkdtemp(prefix="watchtower-ping-")) / "scan.xml"
    try:
        cmd = nmap_runner.build(nmap, net, "Ping scan", xml_path=str(out), authorized=authorized)
    except ValueError as exc:          # ScopeError included
        return None, str(exc)
    sid = scans.start("nmap", net, format_command(cmd.argv))
    try:
        r = runner.run(cmd.argv, purpose="Traffic audit: find quiet devices (nmap ping scan)", target=net,
                       timeout=900)
        xml = out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""
    finally:
        out.unlink(missing_ok=True)
        out.parent.rmdir()
    scans.finish(sid, r.exit_code, xml)
    if not xml:
        return sid, f"ping scan of {net} failed (nmap exit {r.exit_code})"
    up = sum(1 for h in nmap_runner.parse_xml(xml).hosts if h.status == "up")
    return sid, f"{up} device(s) answered the ping scan of {net}"


def devices_from_scans(scans_with_output: list[dict], local_nets: list[str]) -> dict:
    """Newest nmap result per address inside `local_nets` (or private ranges): address -> (Host, scan)."""
    from watchtower.core.findings_engine import latest_hosts
    return {a: hs for a, hs in latest_hosts(scans_with_output).items()
            if ta.is_lan(a, local_nets) and hs[0].status == "up"}
