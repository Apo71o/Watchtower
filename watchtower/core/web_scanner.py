"""Nikto web-server scan of one authorized URL (subprocess, XML output).

Nikto requests thousands of known paths (default files, admin pages, backup
files, outdated software signatures) and reports what it finds. Watchtower runs
it with two of its plugins/test groups switched off, to keep the non-negotiable
"no login attempts, no attacks" rule:

  -Plugins "@@DEFAULT;-auth"  nikto's `auth` plugin tries default user names and
                              passwords on login realms it finds. Removed.
  -Tuning x6                  test group 6 is "Denial of Service". Removed.

Everything else is nikto's normal scan. XML output works across nikto 2.1.x
and 2.5 (JSON doesn't exist in 2.1.5, still Ubuntu 24.04's package).
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass

from watchtower.core import deps
from watchtower.core.findings_engine import SEV_WEIGHT, Finding
from watchtower.core.targets import parse_url

SAFE_PLUGINS = "@@DEFAULT;-auth"
SAFE_TUNING = "x6"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


@dataclass
class NiktoItem:
    id: str
    method: str
    uri: str
    description: str
    osvdb: str = ""
    references: str = ""
    severity: str = "Low"
    category: str = ""      # header / cookie / disclosure / outdated / exposure / vulnerability / info
    cves: str = ""


def binary() -> str | None:
    return deps.find_binary("nikto", "nikto.pl")


def build_argv(url: str, out_xml: str, max_minutes: int = 30) -> list[str]:
    u = parse_url(url)
    nikto = binary()
    if not nikto:
        raise RuntimeError("nikto is not installed (sudo apt install nikto).")
    argv = [nikto, "-h", u.url, "-Format", "xml", "-output", out_xml, "-ask", "no", "-nointeractive",
            "-Plugins", SAFE_PLUGINS, "-Tuning", SAFE_TUNING, "-maxtime", f"{int(max_minutes) * 60}s"]
    if u.scheme == "https":
        argv.append("-ssl")
    return argv


# ---- parsing ----

def parse_xml(text: str) -> list[NiktoItem]:
    """Items from nikto -Format xml (2.1.x: <niktoscan><scandetails><item>;
    2.5 wraps several <niktoscan> in <niktoscans>). Tolerates a file cut short
    by cancel/maxtime by falling back to a per-item regex."""
    items = []
    try:
        root = ET.fromstring(text)
        for it in root.iter("item"):
            items.append(_item(it.get("id", ""), it.get("method", ""), it.get("osvdbid", ""),
                               (it.findtext("uri") or "").strip(), (it.findtext("description") or "").strip(),
                               (it.findtext("references") or "").strip()))
    except ET.ParseError:
        for m in re.finditer(r"<item\b([^>]*)>(.*?)</item>", text, re.S):
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            body = m.group(2)
            items.append(_item(attrs.get("id", ""), attrs.get("method", ""), attrs.get("osvdbid", ""),
                               _tag(body, "uri"), _tag(body, "description"), _tag(body, "references")))
    return items


def _tag(body: str, name: str) -> str:
    t = re.search(rf"<{name}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{name}>", body, re.S)
    return t.group(1).strip() if t else ""


def _item(iid, method, osvdb, uri, desc, refs) -> NiktoItem:
    sev, cat = classify(desc, iid)
    cves = ", ".join(sorted({c.upper() for c in _CVE_RE.findall(desc + " " + refs)}))
    if cves and SEV_RANK_LOCAL[sev] > SEV_RANK_LOCAL["Medium"]:
        sev, cat = "Medium", "vulnerability"
    return NiktoItem(iid, method, uri, desc, "" if osvdb in ("", "0") else osvdb, refs, sev, cat, cves)


SEV_RANK_LOCAL = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# (pattern on the description, severity, category). First match wins.
_RULES: list[tuple[str, str, str]] = [
    (r"remote (code|command) execution|command injection|shellshock|backdoor|arbitrary (code|command)", "High",
     "vulnerability"),
    (r"sql injection|directory traversal|path traversal|arbitrary file|file inclusion|local file|remote file|\brfi\b",
     "High", "vulnerability"),
    (r"default account|default password|default credentials", "High", "vulnerability"),
    (r"phpinfo|server-status|server-info|/\.git\b|\.git/|\.svn|\.env\b|\.htpasswd|web\.config|database|\.sql\b|"
     r"backup|\.bak\b|config(uration)? file|phpmyadmin|admin (login|page|interface)", "Medium", "exposure"),
    (r"cross[- ]site scripting|\bxss\b|vulnerab|exploit|allows? (an )?attacker|denial of service", "Medium",
     "vulnerability"),
    (r"outdated|appears to be (old|out of date)|end of life|eol", "Medium", "outdated"),
    (r"directory indexing|directory listing|index of", "Medium", "exposure"),
    (r"x-frame-options|x-xss-protection|x-content-type-options|strict-transport-security|content-security-policy|"
     r"header is not (present|defined|set)|uncommon header", "Info", "header"),
    (r"cookie .* (without|created without)|httponly|secure flag", "Info", "cookie"),
    (r"retrieved x-powered-by|server banner|server: |server leaks|inode|etag|via header", "Info", "disclosure"),
    (r"http (methods|trace)|trace method|allowed http methods|webdav|put method|delete method", "Low", "exposure"),
]


def classify(description: str, item_id: str = "") -> tuple[str, str]:
    d = description.lower()
    for pat, sev, cat in _RULES:
        if re.search(pat, d):
            return sev, cat
    return "Low", "info"


# ---- findings ----

REMEDIATION = {
    "vulnerability": ("Update the web application / server to the current version from its vendor, and remove "
                      "example scripts or components you don't use. Check the references for the specific fix."),
    "exposure": ("Remove the file or page from the web root, or block it in the server configuration (e.g. nginx "
                 "`location ~ /\\.(git|svn|env) { deny all; }`, Apache `Require all denied`). Disable directory "
                 "listing (nginx `autoindex off;`, Apache `Options -Indexes`) and status pages, or restrict them "
                 "to localhost. Admin interfaces should only be reachable from your management network or VPN."),
    "outdated": "Update the server software to the current supported release (your distro's package or the vendor).",
    "header": "See the Header audit findings for this URL: they cover the same headers with exact settings.",
    "cookie": "See the Header audit findings for this URL: they cover cookie flags with exact settings.",
    "disclosure": ("Hide version details (nginx `server_tokens off;`, Apache `ServerTokens Prod`, PHP "
                   "`expose_php = Off`) and keep the software updated."),
    "info": "Review the item; if the resource shouldn't be public, remove it or restrict access to it.",
}
TECHNIQUE = {
    "vulnerability": "**Exploit public-facing application:** known flaws in web software are found by exactly this "
                     "kind of scan and then exploited with public code.",
    "exposure": "**Information gathering:** forgotten files (backups, .git, phpinfo, status pages) leak source code, "
                "credentials, internal paths and versions that make the next step easy.",
    "outdated": "Old versions have published vulnerabilities; attackers match the version banner against them.",
}


def findings(url: str, items: list[NiktoItem]) -> list[Finding]:
    u = parse_url(url)
    out = []
    for i in items:
        if i.id in ("999990",) or "no cgi directories found" in i.description.lower():
            continue
        title = re.sub(r"^(OSVDB-\d+:\s*)", "", i.description).strip()
        title = (title[:110] + "…") if len(title) > 110 else title
        refs = ([f"OSVDB {i.osvdb}"] if i.osvdb else []) + ([i.references] if i.references else [])
        out.append(Finding(
            device=u.url, device_label=u.url, kind="web",
            title=f"Nikto: {title}", severity=i.severity,
            description=(f"{i.description}\n\nRequest: {i.method or 'GET'} {i.uri or '/'}"
                         + (f"\n\nReferences: {'; '.join(refs)}" if refs else "")
                         + "\n\nNikto has no severity ratings; Watchtower rated this from its description."),
            remediation=REMEDIATION.get(i.category, REMEDIATION["info"]), technique=TECHNIQUE.get(i.category, ""),
            service=f"{u.port}/tcp {u.scheme}", port=f"{u.port}/tcp", cve_id=i.cves,
            attck=["T1190"] if i.category in ("vulnerability", "outdated") else ["T1595.003", "T1592"],
            confidence="reported by nikto", weight=SEV_WEIGHT.get(i.severity, 0), source="Web scan (nikto)"))
    return out


def items_to_json(items: list[NiktoItem]) -> str:
    return json.dumps([asdict(i) for i in items])


def items_from_json(text: str) -> list[NiktoItem]:
    return [NiktoItem(**d) for d in json.loads(text or "[]")]
