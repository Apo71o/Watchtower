"""nmap integration: build the command, keep it in scope, parse the XML.

Any nmap option can be used (profiles, checkboxes, or free-form extra
arguments). The one thing enforced is scope: every target in the final
command, including any typed into the extra arguments, must be covered by the
user's authorized-target list. Options that make nmap pick or contact hosts
outside the command line (-iL, -iR, -b, --resume) are refused because their
targets can't be checked.
"""

from __future__ import annotations

import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlparse

from watchtower.core import deps
from watchtower.core.platform_utils import is_elevated, is_linux, is_windows
from watchtower.core.targets import in_scope, parse_target

# nmap's standard scan profiles (the ones Zenmap ships with), with what each does.
PROFILES: dict[str, tuple[list[str], str]] = {
    "Intense scan": (["-T4", "-A", "-v"],
                     "Top 1000 TCP ports with OS detection (-O), version detection (-sV), default NSE "
                     "scripts (-sC) and traceroute (-A), at aggressive timing (-T4). A good all-round "
                     "look at a host. Needs root for the OS-detection part."),
    "Intense scan plus UDP": (["-sS", "-sU", "-T4", "-A", "-v"],
                              "Intense scan, plus the top 1000 UDP ports (DNS, SNMP, NTP, ...). UDP "
                              "scanning is slow because closed UDP ports often don't answer. Needs root."),
    "Intense scan, all TCP ports": (["-p", "1-65535", "-T4", "-A", "-v"],
                                    "Intense scan across all 65535 TCP ports, so services on unusual "
                                    "ports aren't missed. Takes much longer."),
    "Intense scan, no ping": (["-T4", "-A", "-v", "-Pn"],
                              "Intense scan that skips host discovery (-Pn) and treats the target as up. "
                              "Use when a firewall blocks pings and nmap would otherwise report the host down."),
    "Ping scan": (["-sn"],
                  "Host discovery only (-sn): which addresses are up, with no port scan. Fast way to "
                  "inventory a subnet."),
    "Quick scan": (["-T4", "-F"],
                   "Top 100 TCP ports (-F) at aggressive timing. Fastest useful port scan, no versions."),
    "Quick scan plus": (["-sV", "-T4", "-O", "-F", "--version-light"],
                        "Top 100 TCP ports with light version detection and OS detection. Needs root for -O."),
    "Quick traceroute": (["-sn", "--traceroute"],
                         "Host discovery plus the network path (routers) to each host, without a port scan. "
                         "Needs root."),
    "Regular scan": ([],
                     "nmap with no options: host discovery, then the top 1000 TCP ports. SYN scan when "
                     "privileged, otherwise TCP connect scan. No version detection."),
    "Slow comprehensive scan": (["-sS", "-sU", "-T4", "-A", "-v", "-PE", "-PP", "-PS80,443", "-PA3389",
                                 "-PU40125", "-PY", "-g", "53", "--script", "default or (discovery and safe)"],
                                "Everything in Intense plus UDP, extra host-discovery probes (ICMP echo/"
                                "timestamp, TCP SYN/ACK, UDP, SCTP), source port 53 to slip past naive "
                                "firewalls, and the default + safe discovery scripts. Thorough and slow. "
                                "Needs root."),
    "Custom (only my options)": ([], "No preset: just the scan type, checkboxes and extra arguments you choose."),
}

# nmap's port-scan techniques, by their names in the nmap manual.
SCAN_TYPES: dict[str, tuple[str | None, str]] = {
    "Default (nmap chooses)": (None, "SYN scan if nmap has raw-socket privileges, otherwise TCP connect scan."),
    "TCP SYN scan (-sS)": ("-sS", "\"Half-open\" scan: sends SYN, reads SYN/ACK (open) or RST (closed), never "
                           "completes the handshake. Fast and the most common scan. Needs root."),
    "TCP connect scan (-sT)": ("-sT", "Completes a full TCP connection through the OS, like any client "
                               "would. No privileges needed, but slower and logged by more services."),
    "UDP scan (-sU)": ("-sU", "Sends UDP probes; an ICMP port-unreachable means closed, silence means "
                       "open|filtered. Finds DNS, SNMP, NTP, TFTP. Slow. Needs root."),
    "TCP ACK scan (-sA)": ("-sA", "Doesn't find open ports: maps firewall rules, showing which ports are "
                           "filtered vs unfiltered. Needs root."),
    "TCP Window scan (-sW)": ("-sW", "Like ACK scan, but reads the TCP window size of RSTs, which on some "
                              "systems reveals open ports. Needs root."),
    "TCP Maimon scan (-sM)": ("-sM", "Sends FIN/ACK; some BSD-derived stacks drop it for open ports. Niche. "
                              "Needs root."),
    "TCP Null scan (-sN)": ("-sN", "Sends a packet with no TCP flags. Per RFC 793, closed ports answer RST and "
                            "open ports stay silent. Can slip past stateless filters; unreliable against "
                            "Windows. Needs root."),
    "TCP FIN scan (-sF)": ("-sF", "Same idea as Null scan, with just the FIN flag set. Needs root."),
    "TCP Xmas scan (-sX)": ("-sX", "Same idea as Null scan, with FIN, PSH and URG set (\"lit up like a "
                            "Christmas tree\"). Needs root."),
    "SCTP INIT scan (-sY)": ("-sY", "SYN-scan equivalent for SCTP (telecom signalling, some VoIP). Needs root."),
    "SCTP COOKIE ECHO scan (-sZ)": ("-sZ", "Stealthier SCTP scan; can't tell open from filtered. Needs root."),
    "IP protocol scan (-sO)": ("-sO", "Finds which IP protocols (TCP, UDP, ICMP, GRE, ...) the host supports, "
                               "rather than ports. Needs root."),
}


# Options whose following token is a value, not a target.
VALUE_OPTIONS = {
    "-p", "-e", "-S", "-D", "-g", "-T", "-oN", "-oX", "-oG", "-oA", "-oS", "-oM", "-sI",
    "--script", "--script-args", "--script-args-file", "--script-help", "--datadir", "--stylesheet",
    "--servicedb", "--versiondb", "--dns-servers", "--source-port", "--data", "--data-string",
    "--data-length", "--ttl", "--max-retries", "--host-timeout", "--scan-delay", "--max-scan-delay",
    "--min-rate", "--max-rate", "--min-parallelism", "--max-parallelism", "--min-hostgroup",
    "--max-hostgroup", "--initial-rtt-timeout", "--min-rtt-timeout", "--max-rtt-timeout",
    "--top-ports", "--port-ratio", "--version-intensity", "--exclude", "--excludefile",
    "--exclude-ports", "--mtu", "--spoof-mac", "--proxies", "--proxy", "--stats-every", "--max-os-tries",
    "--script-timeout", "--ip-options",
}
# Option values that are themselves hosts nmap will contact: also scope-checked.
HOST_VALUE_OPTIONS = {"-sI", "--proxies", "--proxy"}
REFUSED = {
    "-iL": "reads targets from a file, which Watchtower can't check against your authorized list",
    "-iR": "picks random internet hosts",
    "-b": "FTP bounce makes a third-party FTP server connect for you",
    "--resume": "resumes a saved scan whose targets Watchtower can't check",
}
ROOT_OPTIONS = {"-sS", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sY", "-sZ", "-sO", "-O", "-A",
                "--traceroute", "-PE", "-PP", "-PM", "-PO", "-PY", "-PU", "-PR", "--send-eth", "-D", "-S",
                "-f", "--mtu", "--spoof-mac", "--data", "--data-string", "--data-length", "--badsum", "--ttl"}


class ScopeError(ValueError):
    pass


def _hosts_in_value(opt: str, value: str) -> list[str]:
    if opt == "-sI":                       # zombie[:probeport]
        return [value.rsplit(":", 1)[0] if value.count(":") == 1 else value]
    hosts = []
    for url in value.split(","):           # --proxies http://host:port,socks4://host:port
        parsed = urlparse(url if "://" in url else f"x://{url}")
        if parsed.hostname:
            hosts.append(parsed.hostname)
    return hosts


def split_extra(extra: str) -> tuple[list[str], list[str], list[str]]:
    """Split free-form extra arguments into (options, extra_targets, other_hosts).
    other_hosts are hosts named in option values that nmap contacts (idle-scan
    zombie, proxies); they must be in scope too but aren't scan targets."""
    try:
        tokens = shlex.split(extra, posix=not is_windows())
    except ValueError as exc:
        raise ValueError(f"Could not parse extra arguments: {exc}") from exc
    opts: list[str] = []
    targets: list[str] = []
    others: list[str] = []
    pending: str | None = None
    for tok in tokens:
        if pending is not None:
            opts.append(tok)
            if pending in HOST_VALUE_OPTIONS:
                others += _hosts_in_value(pending, tok)
            pending = None
            continue
        if tok.startswith("-"):
            base, _, inline = tok.partition("=")
            for bad, why in REFUSED.items():
                if base == bad or (bad in ("-iL", "-iR") and tok.startswith(bad)):
                    raise ScopeError(f"{bad} is not allowed: it {why}.")
            opts.append(tok)
            if base in HOST_VALUE_OPTIONS and inline:
                others += _hosts_in_value(base, inline)
            elif tok in VALUE_OPTIONS or tok in HOST_VALUE_OPTIONS:
                pending = tok
            continue
        targets.append(tok)
    if pending is not None:
        raise ValueError(f"Option {pending} needs a value.")
    return opts, targets, others


@dataclass
class NmapCommand:
    argv: list[str]
    targets: list[str]
    needs_root: bool
    privileged_flag: bool


def profile_is_ping_only(profile: str) -> bool:
    return "-sn" in PROFILES.get(profile, ([], ""))[0]


def _drop_port_selection(args: list[str]) -> list[str]:
    """Remove -F / --top-ports N / -p X so an all-ports option can replace them."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("--top-ports", "-p"):
            skip = True
            continue
        if a == "-F" or (a.startswith("-p") and a not in ("-p",) and not a.startswith("-P")):
            continue
        out.append(a)
    return out


def build(nmap: str, target: str, profile: str, *, scan_type: str | None = None, vuln: bool = False,
          os_detect: bool = False, all_ports: bool = False, extra: str = "", xml_path: str = "-",
          authorized: list[str] | None = None) -> NmapCommand:
    """Raises ScopeError if any target isn't covered by `authorized`."""
    main_targets = target.split()
    if not main_targets:
        raise ValueError("Enter a target (IP, CIDR, range or hostname).")
    opts, extra_targets, other_hosts = split_extra(extra)
    targets = main_targets + extra_targets
    for t in targets + other_hosts:
        try:
            parse_target(t)
        except ValueError as exc:
            raise ScopeError(f"{exc}. (If this is the value of an nmap option, Watchtower didn't "
                             f"recognize that option; write it as --option=value.)") from exc
        if authorized is not None and not in_scope(t, authorized):
            raise ScopeError(f"{t} is not covered by your authorized targets. Add it (or a network "
                             f"containing it) to the list first.")
    args = list(PROFILES.get(profile, ([], ""))[0])
    flag = SCAN_TYPES.get(scan_type or "", (None, ""))[0]
    if flag and "-sn" not in args:
        # a TCP technique replaces the profile's TCP one; -sU and -sO can sit alongside
        tcp = {"-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX"}
        if flag in tcp:
            args = [a for a in args if a not in tcp]
        if flag not in args:
            args.insert(0, flag)
    user_ports = any(o == "-p" or (o.startswith("-p") and not o.startswith("-P")) for o in opts)
    if user_ports:
        args = _drop_port_selection(args)   # nmap rejects -F/--top-ports together with -p
    elif all_ports and "-sn" not in args:
        args = _drop_port_selection(args) + ["-p-"]
    if os_detect and "-A" not in args and "-O" not in args:
        args.append("-O")
    if vuln:
        args += ["--script", "vuln"]
    args += opts
    # Without privileges nmap silently falls back to a connect scan (-sT); these options fail outright.
    needs_root = any(a in ROOT_OPTIONS or a.split("=", 1)[0] in ROOT_OPTIONS for a in args)
    privileged = False
    if is_linux() and not is_elevated() and deps.has_file_capabilities(nmap):
        privileged = True
    argv = [nmap, *(["--privileged"] if privileged else []), *args,
            "-oX", xml_path, "--stats-every", "15s", *targets]
    return NmapCommand(argv, targets, needs_root and not privileged and not is_elevated(), privileged)


# ---- XML parsing ----

@dataclass
class Script:
    id: str
    output: str


@dataclass
class Port:
    protocol: str
    portid: int
    state: str
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    devicetype: str = ""
    ostype: str = ""
    cpes: list[str] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)

    @property
    def version_string(self) -> str:
        return " ".join(x for x in (self.product, self.version, f"({self.extrainfo})" if self.extrainfo else "")
                        if x)


@dataclass
class Host:
    address: str
    status: str = ""
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    os_matches: list[tuple[str, int]] = field(default_factory=list)   # (name, accuracy)
    ports: list[Port] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    closed_summary: str = ""   # e.g. "997 closed tcp ports (reset)"

    @property
    def label(self) -> str:
        return f"{self.address} ({self.hostnames[0]})" if self.hostnames else self.address


@dataclass
class ScanResult:
    args: str = ""
    start: str = ""
    finished: str = ""
    summary: str = ""
    hosts: list[Host] = field(default_factory=list)


def _scripts(el) -> list[Script]:
    return [Script(s.get("id", ""), s.get("output", "").strip()) for s in el.findall("script")]


def parse_xml(text: str) -> ScanResult:
    """Parse nmap -oX output. Tolerates a truncated file from a cancelled scan."""
    text = text.strip()
    if not text:
        return ScanResult()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        if "</host>" not in text:
            return ScanResult()
        root = ET.fromstring(text[: text.rindex("</host>") + 7] + "</nmaprun>")
    res = ScanResult(args=root.get("args", ""), start=root.get("startstr", ""))
    fin = root.find("runstats/finished")
    if fin is not None:
        res.finished, res.summary = fin.get("timestr", ""), fin.get("summary", "")
    for h in root.findall("host"):
        host = Host(address="")
        st = h.find("status")
        host.status = st.get("state", "") if st is not None else ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and not host.address:
                host.address = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                host.mac, host.vendor = a.get("addr", ""), a.get("vendor", "")
        host.hostnames = [n.get("name", "") for n in h.findall("hostnames/hostname") if n.get("name")]
        host.os_matches = [(m.get("name", ""), int(m.get("accuracy", "0") or 0)) for m in h.findall("os/osmatch")]
        for ep in h.findall("ports/extraports"):
            host.closed_summary = f"{ep.get('count')} {ep.get('state')} ports"
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            port = Port(
                protocol=p.get("protocol", ""), portid=int(p.get("portid", "0")),
                state=state.get("state", "") if state is not None else "",
                reason=state.get("reason", "") if state is not None else "",
                scripts=_scripts(p),
            )
            if svc is not None:
                port.service = svc.get("name", "")
                port.product, port.version = svc.get("product", ""), svc.get("version", "")
                port.extrainfo, port.tunnel = svc.get("extrainfo", ""), svc.get("tunnel", "")
                port.devicetype, port.ostype = svc.get("devicetype", ""), svc.get("ostype", "")
                port.cpes = [c.text or "" for c in svc.findall("cpe")]
            host.ports.append(port)
        hs = h.find("hostscript")
        if hs is not None:
            host.scripts = _scripts(hs)
        res.hosts.append(host)
    return res
