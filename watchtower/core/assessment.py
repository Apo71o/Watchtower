"""Gather findings from stored scan results and seen networks, and rank devices.
Pure functions over plain data so the Findings tab and the report export
(step 9) share them."""

from __future__ import annotations

from dataclasses import dataclass, field

from watchtower.core import (
    default_creds,
    domain_audit,
    exploit_xref,
    header_audit,
    nvd,
    snmp_audit,
    subdomain_enum,
    tls_audit,
    traffic_audit,
    web_scanner,
)
from watchtower.core.findings_engine import SEV_RANK, Finding, host_findings, latest_hosts, unmark_patched
from watchtower.core.risk_scoring import DeviceRisk, rank
from watchtower.core.wep_wpa_advisor import wifi_findings


@dataclass
class Assessment:
    findings: list[Finding]
    risks: list[DeviceRisk]
    hosts_assessed: int
    networks_assessed: int
    hosts: dict = field(default_factory=dict)      # address -> (nmap Host, scan row)
    networks: dict = field(default_factory=dict)   # BSSID -> network row
    web: dict = field(default_factory=dict)        # URL -> {kind: host_audits row} (Web Audit)
    domains: dict = field(default_factory=dict)    # domain -> {kind: host_audits row} (Domain Audit)
    captures: list = field(default_factory=list)   # newest capture row per source (Traffic Audit)

    def risk_for(self, device: str) -> DeviceRisk | None:
        return next((r for r in self.risks if r.device == device), None)

    def scope_summary(self) -> str:
        """'3 host(s), 1 web URL(s) and 2 Wi-Fi network(s)' (web/domain parts only when present)."""
        parts = [f"{self.hosts_assessed} host(s)", f"{self.networks_assessed} Wi-Fi network(s)"]
        if self.web:
            parts.append(f"{len(self.web)} web URL(s)")
        if self.domains:
            parts.append(f"{len(self.domains)} domain(s)")
        if self.captures:
            parts.append(f"{len(self.captures)} traffic capture(s)")
        return ", ".join(parts[:-1]) + " and " + parts[-1]

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEV_RANK}
        for f in self.findings:
            c[f.severity] += 1
        return c


def audit_findings(row: dict, label: str) -> list[Finding]:
    """Findings from one stored Host Audit result (host_audits row)."""
    if row["kind"] == "tls":
        return tls_audit.findings(row["host"], label, row["port"], tls_audit.issues_from_json(row["result_json"]),
                                  row.get("tool") or "TLS audit")
    if row["kind"] == "snmp":
        return snmp_audit.findings(row["host"], label, snmp_audit.attempts_from_json(row["result_json"]),
                                   row.get("port") or 161)
    if row["kind"] == "headers":
        return header_audit.findings(row["host"], header_audit.result_from_json(row["result_json"])[1])
    if row["kind"] == "nikto":
        return web_scanner.findings(row["host"], web_scanner.items_from_json(row["result_json"]))
    if row["kind"] == "email":
        rep = domain_audit.report_from_json(row["result_json"])
        return domain_audit.findings(row["host"], rep) if rep else []
    if row["kind"] == "subdomains":
        return subdomain_enum.findings(row["host"], subdomain_enum.subs_from_json(row["result_json"]),
                                       row.get("tool") or "passive sources")
    return []


WEB_KINDS = ("headers", "nikto")
DOMAIN_KINDS = ("email", "subdomains")
HOST_KINDS = ("tls", "snmp")


EXPLOIT_WEIGHT = 5   # a public exploit module makes a finding more urgent


def assess(scans: list[dict], networks: list[dict], include_unauthorized_wifi: bool = False,
           host_audits: list[dict] | None = None, exploit_index: dict | None = None,
           nvd_cache: dict | None = None, captures: list[dict] | None = None) -> Assessment:
    findings: list[Finding] = []
    open_ports: dict[str, int] = {}
    hosts = latest_hosts(scans)
    for addr, (host, _scan) in hosts.items():
        findings += host_findings(host)
        findings += default_creds.findings(host)
        if nvd_cache:
            findings += nvd.findings_for_host(host, nvd_cache)
        open_ports[addr] = sum(1 for p in host.ports if p.state.startswith("open"))
    web: dict[str, dict] = {}
    domains: dict[str, dict] = {}
    for row in host_audits or []:
        label = hosts[row["host"]][0].label if row["host"] in hosts else row["host"]
        findings += audit_findings(row, label)
        if row["kind"] in WEB_KINDS:
            web.setdefault(row["host"], {})[row["kind"]] = row
        elif row["kind"] in DOMAIN_KINDS:
            domains.setdefault(row["host"], {})[row["kind"]] = row
    labels = {a: h.label for a, (h, _s) in hosts.items()}
    for cap in captures or []:
        src = cap["source"].split(":", 1)
        name = src[1].rsplit("/", 1)[-1] if src[0] == "file" else f"live capture on {src[-1]}"
        findings += traffic_audit.findings(traffic_audit.events_from_json(cap.get("events_json")), labels, name)
    nets = [n for n in networks if include_unauthorized_wifi or n.get("authorized")]
    for n in nets:
        findings += wifi_findings(n)
    # list every assessed network / URL / domain, even with no findings
    risks_extra = {n["bssid"]: 0 for n in nets} | {k: 0 for k in (*web, *domains)}
    # de-duplicate (the same CVE can be reported by the dataset and an NSE script)
    seen: dict[str, Finding] = {}
    for f in findings:
        prev = seen.get(f.key)
        if prev is None:
            seen[f.key] = f
        elif f.kind == "nse" and prev.kind != "nse":
            # nmap's script actively confirmed what the version match suspected
            unmark_patched(prev)
            prev.confidence = "confirmed by nmap script"
            prev.source += f" + {f.source}"
    findings = sorted(seen.values(), key=lambda f: (SEV_RANK[f.severity], -(f.cvss or 0), f.device_label))
    for f in findings:
        if f.cve_id:
            f.exploits = exploit_xref.lookup(f.cve_id, exploit_index)
            if f.exploits and not f.patched:
                f.weight += EXPLOIT_WEIGHT
    risks = rank(findings, {**risks_extra, **open_ports})
    for r in risks:
        if r.device in web:
            r.kind = "web"
        elif r.device in domains:
            r.kind = "domain"
        elif r.device in risks_extra and not r.findings:
            r.kind = "wifi"
            n = next(x for x in nets if x["bssid"] == r.device)
            r.label = f"{n.get('ssid') or '(hidden)'} ({n['bssid']})"
    return Assessment(findings, risks, len(hosts), len(nets), hosts, {n["bssid"]: n for n in nets}, web, domains,
                      list(captures or []))
