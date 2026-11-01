"""Turn nmap results into normalized findings with remediation.

Three sources, all offline:
  1. bundled dataset (watchtower/data/vulns.json): product + version -> CVE
  2. exposure rules: risky services being reachable at all (telnet, Docker API, ...)
  3. nmap's own NSE vuln scripts: any "VULNERABLE" output becomes a finding
Wi-Fi findings come from core.wep_wpa_advisor. Every finding has remediation text.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from watchtower.core.nmap_runner import Host, Port, ScanResult, parse_xml

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    device: str                  # host address or Wi-Fi BSSID
    device_label: str            # "192.168.1.5 (nas.lan)" / "Home Lab (AA:BB:...)"
    kind: str                    # "service" | "exposure" | "nse" | "wifi"
    title: str
    severity: str
    description: str
    remediation: str
    service: str = ""            # "22/tcp ssh OpenSSH 8.9p1"
    port: str = ""               # "22/tcp"
    version: str = ""
    cve_id: str = ""
    cvss: float | None = None
    attck: list[str] = field(default_factory=list)
    technique: str = ""          # plain-language explanation of the relevant attack technique
    confidence: str = "confirmed"  # "confirmed" | "probable (version match)"
    weight: float = 0            # risk-score contribution beyond CVSS (see risk_scoring)
    source: str = ""             # "dataset" | "rule" | "nmap NSE: <script>" | "wifi advisor"
    patched: bool = False        # fixed by a distro security update (excluded from risk score)
    cve_info: dict = field(default_factory=dict)   # dataset entry: cwe, disclosed, fixed_in, distro_fixes, ...
    patch_check: dict = field(default_factory=dict)  # distro/revision detection + verdict (see distro_patch_status)
    product: str = ""            # nmap product name of the affected service (for remediation)
    exploits: list[dict] = field(default_factory=list)  # public Metasploit modules for its CVEs (names only)

    @property
    def key(self) -> str:
        return f"{self.device}|{self.port}|{self.cve_id or self.title}"


def severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "Info"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


SEV_WEIGHT = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1, "Info": 0}


# ---- version comparison ----

def version_key(v: str) -> tuple:
    """'8.9p1' -> ((0,8),(0,9),(1,'p'),(0,1)). Numbers compare numerically; a
    letter suffix sorts after the bare number (8.9 < 8.9p1)."""
    parts = re.findall(r"\d+|[A-Za-z]+", v)
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts)


def clean_version(v: str) -> str | None:
    """nmap versions look like '8.9p1 Ubuntu 3ubuntu0.10' or '3.X - 4.X'. Return the
    leading upstream version, or None when nmap only gave a range/wildcard."""
    if not v:
        return None
    first = v.split()[0]
    if " - " in v or not re.match(r"^\d[\w.~+-]*$", first) or re.search(r"(^|\.)[xX](\.|$)", first):
        return None
    return first


_DISTRO_RE = re.compile(r"\b(Ubuntu|Debian)[ -]+([0-9][\w.+~:-]*)", re.IGNORECASE)


def detect_distro(version: str, extrainfo: str = "") -> tuple[str, str] | None:
    """'8.9p1 Ubuntu 3ubuntu0.10' -> ('Ubuntu', '3ubuntu0.10'). Debian-family
    sshd banners carry the package revision; most other services (Apache's
    '(Ubuntu)') only name the distro, giving ('Ubuntu', '')."""
    m = _DISTRO_RE.search(version or "")
    if m:
        return m.group(1).capitalize(), m.group(2)
    for text in (version, extrainfo):
        m2 = re.search(r"\b(Ubuntu|Debian)\b", text or "", re.IGNORECASE)
        if m2:
            return m2.group(1).capitalize(), ""
    return None


def distro_patch_status(entry: dict, version: str, extrainfo: str = "") -> dict:
    """Did the distro backport the fix? Returns a dict with keys:
    verdict: 'patched' | 'vulnerable' | 'unknown' | 'upstream' (no distro marker),
    distro, revision, upstream, advisory, fixed_revision, release, explanation."""
    upstream = clean_version(version) or ""
    found = detect_distro(version, extrainfo)
    out = {"verdict": "upstream", "upstream": upstream, "distro": "", "revision": ""}
    if not found:
        out["explanation"] = ("No distribution marker in the banner, so this looks like an upstream build: the "
                              "version comparison applies directly.")
        return out
    distro, revision = found
    out.update(distro=distro, revision=revision, verdict="unknown")
    fixes = [f for f in entry.get("distro_fixes", []) if f["distro"] == distro and f["upstream"] == upstream]
    if not revision:
        out["explanation"] = (f"The service says it's {distro}'s package, but its banner doesn't include the "
                              f"package revision, so Watchtower can't tell whether {distro}'s security update is "
                              "installed. "
                              "Check on the host itself (see below).")
        return out
    if not fixes:
        out["explanation"] = (f"{distro} package revision {revision}: Watchtower's advisory list has no "
                              f"{distro} fix recorded for upstream {upstream}. The release may be unaffected, "
                              "unsupported, or simply not in the list. Check the security tracker links below.")
        return out
    fix = fixes[0]
    out.update(advisory=fix["advisory"], fixed_revision=fix["fixed_revision"], release=fix["release"],
               package=fix.get("package", ""))
    if version_key(revision) >= version_key(fix["fixed_revision"]):
        out["verdict"] = "patched"
        out["explanation"] = (f"{distro} {fix['release']} fixed this in {fix.get('package', 'the')} package "
                              f"{upstream}-{fix['fixed_revision']} ({fix['advisory']}). This host reports revision "
                              f"{revision}, which is the same or newer, so the fix is installed even though the "
                              f"upstream version number ({upstream}) is in the vulnerable range.")
    else:
        out["verdict"] = "vulnerable"
        out["explanation"] = (f"{distro} {fix['release']} fixed this in package revision {fix['fixed_revision']} "
                              f"({fix['advisory']}). This host reports {revision}, which is older: the security "
                              "update is not installed.")
    return out


def in_range(v: str, lo: str, hi: str) -> bool:
    k = version_key(v)
    return (not lo or k >= version_key(lo)) and (not hi or k < version_key(hi))


@lru_cache(maxsize=1)
def dataset() -> list[dict]:
    text = resources.files("watchtower.data").joinpath("vulns.json").read_text(encoding="utf-8")
    return json.loads(text)["entries"]


def match_dataset(product: str, version: str) -> list[dict]:
    v = clean_version(version)
    if not product or not v:
        return []
    hits = []
    for e in dataset():
        if not re.search(e["product"], product, re.IGNORECASE):
            continue
        if v in e.get("exact", []) or any(in_range(v, lo, hi) for lo, hi in e.get("ranges", [])):
            hits.append(e)
    return hits


# ---- exposure rules ----

@dataclass
class Rule:
    match: object               # callable(Port) -> bool
    title: str
    severity: str
    description: str
    remediation: str
    attck: list[str]


def _svc(*names):
    return lambda p: p.service in names


def _port(*nums, proto="tcp"):
    return lambda p: p.portid in nums and p.protocol == proto


RULES: list[Rule] = [
    Rule(lambda p: p.service == "telnet" or _port(23)(p), "Telnet enabled", "High",
         "Telnet sends usernames, passwords and the whole session in cleartext; anyone on the path can read "
         "them. Embedded devices with telnet often also have weak or default logins.",
         "Disable telnet and use SSH. On routers/IoT, turn telnet off in the admin UI or update the firmware.",
         ["T1040", "T1021", "T1110.001"]),
    Rule(lambda p: p.service in ("exec", "login", "shell") or _port(512, 513, 514)(p), "r-services (rsh/rlogin/rexec)",
         "High", "Legacy BSD remote services trust hostnames and send credentials in cleartext.",
         "Disable rsh/rlogin/rexec entirely; use SSH.", ["T1021", "T1040"]),
    Rule(lambda p: p.service == "ftp" and p.tunnel != "ssl", "Plain FTP (cleartext)", "Medium",
         "FTP sends logins and files unencrypted.",
         "Use SFTP (over SSH) or FTPS instead, or restrict FTP to a trusted network segment.", ["T1040"]),
    Rule(lambda p: p.service == "docker" or _port(2375)(p), "Docker API exposed without TLS", "Critical",
         "An unauthenticated Docker Engine API gives full control of the host: anyone who can reach it can start "
         "a privileged container that mounts the host filesystem.",
         "Bind the Docker API to the Unix socket only, or require mutual TLS (port 2376) and firewall it.",
         ["T1610", "T1190"]),
    Rule(lambda p: p.service in ("ms-wbt-server",) or _port(3389)(p), "Remote Desktop (RDP) exposed", "Medium",
         "RDP is a frequent target for password guessing and has had wormable bugs (BlueKeep).",
         "Limit RDP to a VPN or specific hosts, require Network Level Authentication, keep Windows patched.",
         ["T1021.001", "T1110"]),
    Rule(lambda p: p.service.startswith("vnc") or (5900 <= p.portid <= 5906 and p.protocol == "tcp"),
         "VNC exposed", "Medium",
         "VNC often uses weak 8-character passwords or none, and many servers don't encrypt the session.",
         "Tunnel VNC over SSH or a VPN, set a strong password, and bind it to localhost where possible.",
         ["T1021.005", "T1110"]),
    Rule(lambda p: p.service in ("microsoft-ds", "netbios-ssn"), "SMB file sharing reachable", "Low",
         "SMB exposes shares and has a long history of remote-code-execution bugs (EternalBlue). Run nmap's "
         "smb-vuln-* scripts (--script vuln) to check specific issues.",
         "Disable SMBv1, require SMB signing, keep the OS patched and only expose SMB to the LAN.", ["T1021.002"]),
    Rule(lambda p: p.service == "snmp" or _port(161, proto="udp")(p), "SNMP service reachable", "Medium",
         "SNMP v1/v2c uses cleartext community strings (often 'public'/'private') that can expose device "
         "configuration, interfaces, ARP tables and more. Host Audit (step 6) checks read access.",
         "Disable SNMP if unused; otherwise use SNMPv3 with authPriv and restrict which hosts may query it.",
         ["T1602.001"]),
    Rule(lambda p: p.service in ("redis",) or _port(6379)(p), "Redis exposed", "High",
         "Redis has no authentication by default; network access often means reading/writing all data and, "
         "via CONFIG SET, writing files (e.g. SSH keys) on the host.",
         "Bind Redis to localhost, enable protected-mode and requirepass/ACLs.", ["T1190"]),
    Rule(lambda p: p.service in ("mongodb", "mongod") or _port(27017)(p), "MongoDB exposed", "High",
         "Older MongoDB defaults allowed unauthenticated access; exposed instances are routinely wiped and ransomed.",
         "Enable authentication, bind to localhost or a private interface, firewall port 27017.", ["T1190"]),
    Rule(lambda p: _port(9200)(p), "Elasticsearch HTTP API exposed", "High",
         "Elasticsearch without security enabled lets anyone read and delete indices.",
         "Enable Elasticsearch security (auth + TLS) and firewall port 9200.", ["T1190"]),
    Rule(lambda p: p.service == "memcache" or _port(11211)(p) or _port(11211, proto="udp")(p), "Memcached exposed",
         "Medium", "Memcached has no authentication; data is readable, and UDP memcached is abused for "
         "DDoS amplification.", "Bind memcached to localhost and disable UDP (-U 0).", ["T1190"]),
    Rule(lambda p: p.service in ("mysql", "postgresql", "ms-sql-s", "oracle-tns"), "Database port exposed",
         "Medium", "A database listening on the network invites password guessing and exploitation of server bugs.",
         "Bind the database to localhost or the app network only and use strong, unique credentials.",
         ["T1190", "T1110"]),
    Rule(lambda p: p.service == "upnp" or _port(1900, proto="udp")(p), "UPnP exposed", "Low",
         "UPnP lets devices open firewall ports automatically and has had many implementation bugs in routers.",
         "Disable UPnP on the router unless something specifically needs it.", ["T1190"]),
    Rule(lambda p: p.service == "http" and p.tunnel != "ssl", "Web service over plain HTTP", "Low",
         "Admin interfaces (routers, cameras, NAS) on plain HTTP send their login unencrypted.",
         "Enable HTTPS on the device and disable the HTTP listener, or restrict access to a management network.",
         ["T1040"]),
]


def _service_label(p: Port) -> str:
    return f"{p.portid}/{p.protocol} {p.service} {p.version_string}".strip()


def mark_patched(f: Finding) -> None:
    f.patched = True
    f.severity = "Info"
    f.weight = 0
    f.confidence = f"patched by {f.patch_check.get('distro', 'distro')} security update"
    f.title = f"{f.title} (fixed by {f.patch_check.get('distro', 'distro')} update)"


def unmark_patched(f: Finding) -> None:
    """An nmap script actively confirmed the issue: the version check was wrong."""
    if not f.patched:
        return
    f.patched = False
    f.severity = severity_from_cvss(f.cvss)
    f.weight = SEV_WEIGHT[f.severity]
    f.title = f.title.rsplit(" (fixed by", 1)[0]


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_CVSS_RE = re.compile(r"CVSSv?\d?:?\s*([\d.]+)")
_RISK_RE = re.compile(r"Risk factor:\s*(\w+)", re.IGNORECASE)


def nse_findings(device: str, label: str, port: Port | None, scripts) -> list[Finding]:
    out = []
    for s in scripts:
        if "VULNERABLE" not in s.output.upper() or "NOT VULNERABLE" in s.output.upper():
            continue
        lines = [ln.strip() for ln in s.output.splitlines() if ln.strip()]
        title = next((ln for ln in lines if ln.upper() not in ("VULNERABLE:", "LIKELY VULNERABLE:")
                      and not ln.upper().startswith("STATE")), s.id)
        cves = sorted(set(_CVE_RE.findall(s.output)))
        cvss_m = _CVSS_RE.search(s.output)
        cvss = float(cvss_m.group(1)) if cvss_m else None
        risk = _RISK_RE.search(s.output)
        sev = (risk.group(1).capitalize() if risk and risk.group(1).capitalize() in SEVERITIES
               else severity_from_cvss(cvss) if cvss else "High")
        likely = "LIKELY VULNERABLE" in s.output.upper()
        out.append(Finding(
            device=device, device_label=label, kind="nse", title=title[:160], severity=sev,
            description=s.output.strip(),
            remediation="Apply the vendor patch or upgrade referenced in the script output above; look up the "
                        "CVE for fixed versions. If the service isn't needed, disable it or firewall the port.",
            service=_service_label(port) if port else "", port=f"{port.portid}/{port.protocol}" if port else "",
            cve_id=", ".join(cves), cvss=cvss, attck=["T1210"],
            confidence="probable (nmap: likely vulnerable)" if likely else "confirmed by nmap script",
            weight=SEV_WEIGHT.get(sev, 0), source=f"nmap NSE: {s.id}", product=port.product if port else ""))
    return out


def host_findings(host: Host) -> list[Finding]:
    out: list[Finding] = []
    dev, label = host.address, host.label
    open_ports = [p for p in host.ports if p.state.startswith("open")]
    for p in open_ports:
        for e in match_dataset(p.product, p.version):
            sev = severity_from_cvss(e["cvss"])
            check = distro_patch_status(e, p.version, p.extrainfo)
            f = Finding(
                device=dev, device_label=label, kind="service", title=e["title"], severity=sev,
                description=e["description"], remediation=e["remediation"], service=_service_label(p),
                port=f"{p.portid}/{p.protocol}", version=p.version, cve_id=e["cve"], cvss=e["cvss"],
                attck=["T1190", "T1210"], confidence="probable (version match)",
                weight=SEV_WEIGHT[sev], source="dataset", cve_info=e, patch_check=check, product=p.product)
            if check["verdict"] == "patched":
                mark_patched(f)
            elif check["verdict"] == "vulnerable":
                f.confidence = f"likely vulnerable ({check['distro']} security update not installed)"
            elif check["verdict"] == "unknown":
                f.confidence = f"probable ({check['distro']} may have backported the fix; verify on the host)"
            out.append(f)
        for r in RULES:
            try:
                hit = r.match(p)
            except Exception:
                hit = False
            if hit:
                out.append(Finding(
                    device=dev, device_label=label, kind="exposure", title=r.title, severity=r.severity,
                    description=r.description, remediation=r.remediation, service=_service_label(p),
                    port=f"{p.portid}/{p.protocol}", attck=list(r.attck), weight=SEV_WEIGHT[r.severity],
                    source="rule", product=p.product))
        out += nse_findings(dev, label, p, p.scripts)
    out += nse_findings(dev, label, None, host.scripts)
    if len(open_ports) > 25:
        out.append(Finding(
            device=dev, device_label=label, kind="exposure",
            title=f"Large attack surface ({len(open_ports)} open ports)",
            severity="Low", description="Every listening service is something to patch and something to attack.",
            remediation="Disable services you don't use and firewall the rest to the hosts that need them.",
            attck=["T1046"], weight=1, source="rule"))
    return out


def latest_hosts(scans: list[dict]) -> dict[str, tuple[Host, dict]]:
    """Newest result per host address across stored scans, preferring the newest
    scan that actually has port data for that host. `scans` newest-first, each
    with 'raw_output' (nmap XML) and 'id'/'started'."""
    best: dict[str, tuple[Host, dict]] = {}
    for scan in scans:
        res: ScanResult = parse_xml(scan.get("raw_output") or "")
        for h in res.hosts:
            if h.status != "up" or not h.address:
                continue
            cur = best.get(h.address)
            if cur is None or (not cur[0].ports and h.ports):
                best[h.address] = (h, scan)
    return best
