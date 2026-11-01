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

PROFILES: dict[str, list[str]] = {
    "Quick (top 1000 TCP ports + versions)": ["-sV", "-T4"],
    "Ping sweep (which hosts are up)": ["-sn"],
    "Full TCP (all 65535 ports + versions)": ["-sV", "-p-", "-T4"],
    "Intense (versions, OS, default scripts, traceroute)": ["-A", "-T4"],
    "Top UDP ports": ["-sU", "--top-ports", "100", "-T4"],
    "Custom (only my extra arguments)": [],
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


def build(nmap: str, target: str, profile: str, *, vuln: bool = False, os_detect: bool = False,
          all_ports: bool = False, extra: str = "", xml_path: str = "-",
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
    args = list(PROFILES.get(profile, []))
    if all_ports and "-p-" not in args and not any(o.startswith("-p") and o != "-p-" for o in opts):
        args = [a for a in args if a != "--top-ports"] + ["-p-"]
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
                port.cpes = [c.text or "" for c in svc.findall("cpe")]
            host.ports.append(port)
        hs = h.find("hostscript")
        if hs is not None:
            host.scripts = _scripts(hs)
        res.hosts.append(host)
    return res
