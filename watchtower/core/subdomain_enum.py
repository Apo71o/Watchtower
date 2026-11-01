"""Passive subdomain discovery for a domain you own.

"Passive" means nothing is sent to the domain's own servers: the names come
from public third-party data sets (Certificate Transparency logs, passive-DNS
and search APIs). Backends:

  subfinder   passive by design (it has no brute-force or active mode)
  amass       only with `enum -passive`; refused if this amass build doesn't
              have that flag (newer releases removed it, and their default
              enumeration is active: DNS brute forcing, zone transfers, ...)
  crt.sh      built in: one HTTPS request to crt.sh's CT-log search
              (no tool needed)

Results are names only; Watchtower doesn't resolve or probe them.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

from watchtower.core import deps
from watchtower.core.findings_engine import SEV_WEIGHT, Finding
from watchtower.core.targets import normalize_domain

CRTSH_URL = "https://crt.sh/"
BACKENDS = ("subfinder", "amass", "crt.sh")
# Labels that usually mean something that shouldn't be advertised publicly.
SENSITIVE = re.compile(
    r"(^|[.-])(dev|devel|staging|stage|stg|test|testing|qa|uat|sandbox|preprod|beta|old|legacy|backup|bak|"
    r"admin|administrator|internal|intranet|corp|private|vpn|remote|rdp|citrix|jenkins|gitlab|git|svn|jira|"
    r"confluence|grafana|kibana|prometheus|elastic|phpmyadmin|pma|db|database|mysql|sql|postgres|redis|mongo|"
    r"ftp|sftp|ssh|portainer|proxmox|pve|esxi|vcenter|idrac|ilo|ipmi|nas|router|firewall|unifi|pfsense|"
    r"opnsense|webmin|cpanel|plesk|k8s|kubernetes|docker|registry|vault|ldap|ad|dc\d*|mgmt|management)"
    r"($|[.-]|\d)", re.I)


@dataclass
class Subdomain:
    name: str
    sources: list[str] = field(default_factory=list)

    @property
    def sensitive(self) -> bool:
        return bool(SENSITIVE.search(self.name.split(".")[0])) or bool(
            SENSITIVE.search(".".join(self.name.split(".")[:-2])))


def available(amass_help: str | None = None) -> dict[str, str]:
    """backend -> "" if usable, else the reason it isn't. amass_help is the
    output of `amass enum -h` (checked for the -passive flag) when known."""
    out = {"subfinder": "" if deps.find_binary("subfinder") else
           "subfinder is not installed (https://github.com/projectdiscovery/subfinder)"}
    if not deps.find_binary("amass"):
        out["amass"] = "amass is not installed (https://github.com/owasp-amass/amass)"
    elif amass_help is not None and not amass_supports_passive(amass_help):
        out["amass"] = ("this amass version has no -passive flag, so Watchtower can't guarantee a passive-only "
                        "run; use subfinder or crt.sh instead")
    else:
        out["amass"] = ""
    out["crt.sh"] = ""
    return out


def amass_supports_passive(help_text: str) -> bool:
    return bool(re.search(r"(^|\s)-passive\b", help_text or ""))


def amass_help_argv() -> list[str]:
    a = deps.find_binary("amass")
    if not a:
        raise RuntimeError("amass is not installed")
    return [a, "enum", "-h"]


def build_argv(backend: str, domain: str, out_file: str, max_minutes: int = 10) -> list[str]:
    domain = normalize_domain(domain)
    if backend == "subfinder":
        b = deps.find_binary("subfinder")
        if not b:
            raise RuntimeError("subfinder is not installed")
        return [b, "-d", domain, "-silent", "-json", "-o", out_file, "-max-time", str(int(max_minutes))]
    if backend == "amass":
        b = deps.find_binary("amass")
        if not b:
            raise RuntimeError("amass is not installed")
        return [b, "enum", "-passive", "-d", domain, "-o", out_file, "-timeout", str(int(max_minutes))]
    raise ValueError(f"{backend} isn't a subprocess backend")


def crtsh_params(domain: str) -> dict[str, str]:
    return {"q": f"%.{normalize_domain(domain)}", "output": "json"}


# ---- parsing ----

def _clean(name: str, domain: str) -> str | None:
    n = name.strip().strip(".").lower()
    if n.startswith("*."):
        n = n[2:]
    if n != domain and not n.endswith("." + domain):
        return None
    try:
        return normalize_domain(n)
    except ValueError:
        return None


def _merge(pairs, domain: str) -> list[Subdomain]:
    by: dict[str, Subdomain] = {}
    for name, src in pairs:
        n = _clean(name, domain)
        if not n:
            continue
        s = by.setdefault(n, Subdomain(n))
        if src and src not in s.sources:
            s.sources.append(src)
    return sorted(by.values(), key=lambda s: (s.name.count("."), s.name))


def parse_subfinder(text: str, domain: str) -> list[Subdomain]:
    """subfinder -json: one {"host": ..., "input": ..., "source": ...} per line
    (plain host names per line without -json)."""
    domain = normalize_domain(domain)
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            src = d.get("source") or ""
            srcs = d.get("sources") or ([src] if src else [])
            for s in srcs or [""]:
                pairs.append((d.get("host", ""), s))
        else:
            pairs.append((line.split(",")[0], ""))
    return _merge(pairs, domain)


def parse_amass(text: str, domain: str) -> list[Subdomain]:
    """amass -o output: v3 writes one name per line; v4 writes graph lines like
    'www.example.com (FQDN) --> a_record --> 192.0.2.1 (IPAddress)'."""
    domain = normalize_domain(domain)
    pairs = []
    for line in text.splitlines():
        for m in re.finditer(r"([A-Za-z0-9*_.-]+)(?:\s+\(FQDN\))?", line):
            tok = m.group(1)
            if "." in tok and not re.fullmatch(r"[\d.]+", tok):
                pairs.append((tok, "amass"))
    return _merge(pairs, domain)


def parse_crtsh(text: str, domain: str) -> list[Subdomain]:
    """crt.sh ?output=json: list of certificate entries; name_value holds the
    certificate's names separated by newlines."""
    domain = normalize_domain(domain)
    data = json.loads(text or "[]")
    pairs = []
    for e in data:
        for n in str(e.get("name_value", "")).split("\n"):
            pairs.append((n, "crt.sh"))
        cn = e.get("common_name")
        if cn:
            pairs.append((cn, "crt.sh"))
    return _merge(pairs, domain)


# ---- findings ----

def findings(domain: str, subs: list[Subdomain], backend: str) -> list[Finding]:
    domain = normalize_domain(domain)
    others = [s for s in subs if s.name != domain]
    if not others:
        return []
    out = []
    listing = ", ".join(s.name for s in others[:60]) + (f" … and {len(others) - 60} more" if len(others) > 60 else "")
    out.append(Finding(
        device=domain, device_label=domain, kind="subdomain",
        title=f"Subdomains: {len(others)} name(s) publicly discoverable", severity="Info",
        description=(f"These names were found in public data sources by {backend}, without contacting your "
                     f"servers: {listing}.\n\nThis is what anyone can learn about your domain in seconds."),
        remediation=("Review the list: remove DNS records for anything retired (stale records can lead to "
                     "subdomain takeover), and make sure everything still listed is meant to be reachable and is "
                     "kept up to date."),
        technique=("**Reconnaissance:** attackers start by listing a domain's names from Certificate Transparency "
                   "logs and passive DNS to find forgotten or less-protected hosts."),
        service="public DNS / CT logs", port="dns", attck=["T1596.003", "T1590.002"], confidence="public data",
        weight=0, source=f"Passive subdomain enumeration ({backend})"))
    sens = [s for s in others if s.sensitive]
    if sens:
        names = ", ".join(s.name for s in sens[:40]) + (" …" if len(sens) > 40 else "")
        out.append(Finding(
            device=domain, device_label=domain, kind="subdomain",
            title=f"Subdomains: {len(sens)} sensitive-looking name(s) publicly listed", severity="Low",
            description=(f"Names that suggest admin, development, backup or infrastructure systems appear in "
                         f"public data: {names}. Their existence is now known to anyone; check they aren't "
                         "reachable from the internet unless they need to be."),
            remediation=("For internal systems: don't publish them in public DNS, and use a wildcard certificate or "
                         "an internal CA so their names don't get logged in Certificate Transparency. Put admin and "
                         "dev systems behind a VPN or an access proxy, and remove records for retired hosts."),
            technique=("Admin panels, staging copies and build servers are often less hardened than production; "
                       "a list of their names tells attackers exactly where to look."),
            service="public DNS / CT logs", port="dns", attck=["T1596.003", "T1590.002"],
            confidence="name-based heuristic", weight=SEV_WEIGHT["Low"],
            source=f"Passive subdomain enumeration ({backend})"))
    return out


def subs_to_json(subs: list[Subdomain]) -> str:
    return json.dumps([asdict(s) for s in subs])


def subs_from_json(text: str) -> list[Subdomain]:
    return [Subdomain(**d) for d in json.loads(text or "[]")]
