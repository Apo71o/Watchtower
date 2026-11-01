"""Gather findings from stored scan results and seen networks, and rank devices.
Pure functions over plain data so the Findings tab and the report export
(step 9) share them."""

from __future__ import annotations

from dataclasses import dataclass, field

from watchtower.core import default_creds, snmp_audit, tls_audit
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

    def risk_for(self, device: str) -> DeviceRisk | None:
        return next((r for r in self.risks if r.device == device), None)

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
    return []


def assess(scans: list[dict], networks: list[dict], include_unauthorized_wifi: bool = False,
           host_audits: list[dict] | None = None) -> Assessment:
    findings: list[Finding] = []
    open_ports: dict[str, int] = {}
    hosts = latest_hosts(scans)
    for addr, (host, _scan) in hosts.items():
        findings += host_findings(host)
        findings += default_creds.findings(host)
        open_ports[addr] = sum(1 for p in host.ports if p.state.startswith("open"))
    for row in host_audits or []:
        label = hosts[row["host"]][0].label if row["host"] in hosts else row["host"]
        findings += audit_findings(row, label)
    nets = [n for n in networks if include_unauthorized_wifi or n.get("authorized")]
    for n in nets:
        findings += wifi_findings(n)
    risks_extra = {n["bssid"]: 0 for n in nets}   # list every assessed network, even with no findings
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
    risks = rank(findings, {**risks_extra, **open_ports})
    for r in risks:
        if r.device in risks_extra and not r.findings:
            r.kind = "wifi"
            n = next(x for x in nets if x["bssid"] == r.device)
            r.label = f"{n.get('ssid') or '(hidden)'} ({n['bssid']})"
    return Assessment(findings, risks, len(hosts), len(nets), hosts, {n["bssid"]: n for n in nets})
