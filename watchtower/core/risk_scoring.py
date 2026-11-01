"""Per-device risk score, 0-100, for the Top Risks view.

score = 6 x worst CVSS (0-60)
      + sum of finding weights (severity bonus for service findings; encryption
        weakness / WPS / default SSID weights for Wi-Fi findings), capped at 70
      + 1 per open port, capped at 15
capped at 100. A triage aid, not a formal metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from watchtower.core.findings_engine import SEV_RANK, Finding


@dataclass
class DeviceRisk:
    device: str
    label: str
    kind: str                 # "host" | "wifi"
    score: int
    worst: str
    findings: list[Finding] = field(default_factory=list)
    open_ports: int = 0


def score(findings: list[Finding], open_ports: int = 0) -> int:
    worst_cvss = max((f.cvss for f in findings if f.cvss is not None), default=0.0)
    weights = min(70.0, sum(f.weight for f in findings))
    return int(round(min(100.0, 6 * worst_cvss + weights + min(15, open_ports))))


def rank(findings: list[Finding], open_ports: dict[str, int] | None = None) -> list[DeviceRisk]:
    open_ports = open_ports or {}
    by_dev: dict[str, list[Finding]] = {}
    for f in findings:
        by_dev.setdefault(f.device, []).append(f)
    for dev in open_ports:
        by_dev.setdefault(dev, [])
    out = []
    for dev, fs in by_dev.items():
        kind = "wifi" if any(f.kind == "wifi" for f in fs) else "host"
        label = fs[0].device_label if fs else dev
        worst = min((f.severity for f in fs), key=lambda s: SEV_RANK[s], default="Info")
        out.append(DeviceRisk(dev, label, kind, score(fs, open_ports.get(dev, 0)), worst, fs, open_ports.get(dev, 0)))
    out.sort(key=lambda d: (-d.score, SEV_RANK[d.worst], d.label))
    return out
