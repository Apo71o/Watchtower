"""Live CVE lookups from the NIST National Vulnerability Database (opt-in).

This is the only place Watchtower makes network requests of its own, and only
when the user enables it in Settings. Every request is reported through the
`on_request` callback (the GUI logs it as Event.NETWORK_REQUEST and shows it
in the Command Console). Results are cached for a week.

Lookups use the CPE identifiers nmap's version detection reports
(e.g. cpe:/a:openbsd:openssh:8.9p1) via the NVD CVE API 2.0
`virtualMatchString` parameter. Only CPEs that include a version are queried;
without one every CVE ever filed for the product would match.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from watchtower.core.findings_engine import SEV_WEIGHT, Finding, detect_distro, severity_from_cvss
from watchtower.core.nmap_runner import Host

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 200
MAX_RESULTS = 1000
DELAY_NO_KEY = 6.5    # NVD: 5 requests per rolling 30 s without an API key
DELAY_WITH_KEY = 0.7  # 50 per 30 s with one


class NvdError(RuntimeError):
    pass


def cpe22_to_23(cpe: str) -> str | None:
    """'cpe:/a:openbsd:openssh:8.9p1' -> 'cpe:2.3:a:openbsd:openssh:8.9p1'. None without a version."""
    m = re.match(r"^cpe:/([aho]):([^:]+):([^:]+):([^:]+)", cpe or "")
    if not m or not m.group(4) or m.group(4) in ("-", "*"):
        return None
    part, vendor, product, version = m.groups()
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}"


def host_cpes(hosts: list[Host]) -> set[str]:
    out = set()
    for h in hosts:
        for p in h.ports:
            if p.state.startswith("open"):
                for c in p.cpes:
                    c23 = cpe22_to_23(c)
                    if c23:
                        out.add(c23)
    return out


def _cvss(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0] if entries else None)
        if primary:
            data = primary.get("cvssData", {})
            return data.get("baseScore"), f"{data.get('version', key)} {data.get('vectorString', '')}".strip()
    return None, ""


def parse_response(data: dict) -> list[dict]:
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score, vector = _cvss(c.get("metrics", {}))
        cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")})
        refs = c.get("references", [])
        out.append({
            "id": c.get("id", ""), "description": desc, "cvss": score, "vector": vector,
            "cwe": ", ".join(cwes), "published": (c.get("published") or "")[:10],
            "references": [r["url"] for r in refs[:12] if r.get("url")],
            "exploit_refs": [r["url"] for r in refs if "Exploit" in (r.get("tags") or [])][:5],
        })
    return out


@dataclass
class NvdClient:
    session: object                      # requests.Session-like (get(url, params, headers, timeout))
    api_key: str = ""
    on_request: object = None            # callback(url: str, params: dict) -> None, for logging
    sleep: object = time.sleep
    _last: float = 0.0

    def _throttle(self):
        delay = DELAY_WITH_KEY if self.api_key else DELAY_NO_KEY
        wait = self._last + delay - time.monotonic()
        if self._last and wait > 0:
            self.sleep(wait)
        self._last = time.monotonic()

    def fetch(self, cpe23: str) -> list[dict]:
        results: list[dict] = []
        start = 0
        while True:
            params = {"virtualMatchString": cpe23, "resultsPerPage": PAGE, "startIndex": start}
            self._throttle()
            if self.on_request:
                self.on_request(API, params)
            headers = {"apiKey": self.api_key} if self.api_key else {}
            try:
                resp = self.session.get(API, params=params, headers=headers, timeout=30)
            except Exception as exc:
                raise NvdError(f"Couldn't reach NVD: {exc}") from exc
            if resp.status_code in (403, 429):
                raise NvdError(f"NVD rate limit reached (HTTP {resp.status_code}). Wait a minute, or add a free "
                               "API key in Settings for 10x higher limits.")
            if resp.status_code == 404:
                return results
            if resp.status_code != 200:
                raise NvdError(f"NVD returned HTTP {resp.status_code}")
            data = resp.json()
            results += parse_response(data)
            total = data.get("totalResults", 0)
            start += data.get("resultsPerPage", PAGE) or PAGE
            if start >= total or start >= MAX_RESULTS:
                return results


def findings_for_host(host: Host, cache: dict[str, list[dict]]) -> list[Finding]:
    out = []
    for p in host.ports:
        if not p.state.startswith("open"):
            continue
        distro = detect_distro(p.version, p.extrainfo)
        for c in p.cpes:
            c23 = cpe22_to_23(c)
            for cve in cache.get(c23 or "", []):
                sev = severity_from_cvss(cve["cvss"]) if cve["cvss"] is not None else "Medium"
                f = Finding(
                    device=host.address, device_label=host.label, kind="nvd",
                    title=f"{cve['id']}: {p.product or p.service} {p.version.split()[0] if p.version else ''}".strip(),
                    severity=sev, description=cve["description"] or "(no description on NVD yet)",
                    remediation=(f"Update {p.product or p.service} to a version NVD doesn't list as affected (see the "
                                 "NVD entry's 'Known Affected Software Configurations' for the fixed version). "
                                 "Linux distributions often fix CVEs without changing the version number; check "
                                 "the Ubuntu/Debian tracker links and `apt changelog <package> | grep CVE-...`."),
                    service=f"{p.portid}/{p.protocol} {p.service} {p.version_string}".strip(),
                    port=f"{p.portid}/{p.protocol}", version=p.version, cve_id=cve["id"], cvss=cve["cvss"],
                    attck=["T1190", "T1210"], product=p.product, source=f"NVD ({c23})",
                    confidence="probable (NVD version match)", weight=SEV_WEIGHT[sev],
                    cve_info={"cwe": cve.get("cwe"), "disclosed": cve.get("published"), "vector": cve.get("vector"),
                              "references": cve.get("references", []), "exploit_refs": cve.get("exploit_refs", [])},
                )
                if distro:
                    f.unverified = True
                    f.weight = 0
                    f.confidence = (f"unverified: {distro[0]} package; NVD matched the upstream version and "
                                    f"{distro[0]} may have backported the fix")
                out.append(f)
    return out
