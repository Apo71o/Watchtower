"""Gather findings from stored scan results and seen networks, and rank devices.
Pure functions over plain data so the Findings tab and the report export
(step 9) share them."""

from __future__ import annotations

from dataclasses import dataclass

from watchtower.core.findings_engine import SEV_RANK, Finding, host_findings, latest_hosts
from watchtower.core.risk_scoring import DeviceRisk, rank
from watchtower.core.wep_wpa_advisor import wifi_findings


@dataclass
class Assessment:
    findings: list[Finding]
    risks: list[DeviceRisk]
    hosts_assessed: int
    networks_assessed: int

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEV_RANK}
        for f in self.findings:
            c[f.severity] += 1
        return c


def assess(scans: list[dict], networks: list[dict], include_unauthorized_wifi: bool = False) -> Assessment:
    findings: list[Finding] = []
    open_ports: dict[str, int] = {}
    hosts = latest_hosts(scans)
    for addr, (host, _scan) in hosts.items():
        findings += host_findings(host)
        open_ports[addr] = sum(1 for p in host.ports if p.state.startswith("open"))
    nets = [n for n in networks if include_unauthorized_wifi or n.get("authorized")]
    for n in nets:
        findings += wifi_findings(n)
    # de-duplicate (the same CVE can be reported by the dataset and an NSE script)
    seen: dict[str, Finding] = {}
    for f in findings:
        prev = seen.get(f.key)
        if prev is None:
            seen[f.key] = f
        elif f.kind == "nse" and prev.kind != "nse":
            # nmap's script actively confirmed what the version match suspected
            prev.confidence = "confirmed by nmap script"
            prev.source += f" + {f.source}"
    findings = sorted(seen.values(), key=lambda f: (SEV_RANK[f.severity], -(f.cvss or 0), f.device_label))
    return Assessment(findings, rank(findings, open_ports), len(hosts), len(nets))
