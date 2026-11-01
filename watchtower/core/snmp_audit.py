"""Read-only SNMP check: does a community string grant read access?

Only SNMP GET requests for a handful of system-group OIDs (sysDescr, sysName,
...) are sent, with snmpget. No SET, no walk of the whole MIB, no pivoting.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

from watchtower.core import deps
from watchtower.core.findings_engine import Finding

DEFAULT_COMMUNITIES = ["public", "private"]
SYS_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
}
_COMMUNITY_RE = re.compile(r"^[\x21-\x7e]{1,64}$")
_LINE_RE = re.compile(r"^\.?([\d.]+) = (?:[\w-]+: )?(.*)$")


@dataclass
class SnmpAttempt:
    version: str          # "1" | "2c"
    community: str
    responded: bool
    values: dict = field(default_factory=dict)   # name -> value
    error: str = ""


def valid_community(c: str) -> bool:
    return bool(_COMMUNITY_RE.match(c))


def build_argv(host: str, community: str, version: str = "2c", port: int = 161) -> list[str]:
    if version not in ("1", "2c"):
        raise ValueError(version)
    if not valid_community(community):
        raise ValueError(f"invalid community string: {community!r}")
    snmpget = deps.find_binary("snmpget")
    if not snmpget:
        raise RuntimeError("snmpget is not installed (sudo apt install snmp).")
    agent = f"udp6:[{host}]:{port}" if ":" in host else f"udp:{host}:{port}"
    return [snmpget, "-v", version, "-c", community, "-t", "2", "-r", "1", "-On", agent, *SYS_OIDS]


def parse_snmpget(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = _LINE_RE.match(line.strip())
        if m and m.group(1) in SYS_OIDS:
            val = m.group(2).strip().strip('"')
            if val and not val.startswith(("No Such", "No more")):
                out[SYS_OIDS[m.group(1)]] = val
    return out


def attempt_from_output(version: str, community: str, exit_code: int, output: str) -> SnmpAttempt:
    values = parse_snmpget(output)
    err = "" if values else (output.strip().splitlines()[-1] if output.strip() else f"exit {exit_code}")
    return SnmpAttempt(version, community, bool(values), values, err[:200])


def findings(host: str, label: str, attempts: list[SnmpAttempt], port: int = 161) -> list[Finding]:
    out = []
    readable = [a for a in attempts if a.responded]
    by_comm: dict[str, list[SnmpAttempt]] = {}
    for a in readable:
        by_comm.setdefault(a.community, []).append(a)
    for comm, atts in by_comm.items():
        versions = ", ".join(f"v{a.version}" for a in atts)
        leaked = atts[0].values
        leak_txt = "; ".join(f"{k}: {v}" for k, v in leaked.items())
        default = comm in DEFAULT_COMMUNITIES
        sev = "High" if default else "Low"
        extra = ""
        if comm == "private":
            extra = (" 'private' is conventionally the read-WRITE community. Watchtower never sends SET requests, "
                     "so write access wasn't tested, but assume someone could change this device's configuration.")
        out.append(Finding(
            device=host, device_label=label, kind="snmp",
            title=(f"SNMP readable with default community '{comm}'" if default else
                   f"SNMP readable with community '{comm}' (cleartext v1/v2c)"),
            severity=sev,
            description=(f"SNMP {versions} on UDP {port} answered GET requests using the community string "
                         f"'{comm}'. It disclosed: {leak_txt or '(values returned)'}.{extra}"),
            technique=("**SNMP v1/v2c community strings** are plaintext passwords sent in every packet. With read "
                       "access, an attacker can walk the device's MIB: interface and routing tables, ARP cache "
                       "(every device on the LAN), running processes and installed software, sometimes user names "
                       "and configuration. Default communities are the first thing scanners try."),
            remediation=("Disable SNMP if nothing uses it. Otherwise switch to SNMPv3 with authPriv (authentication "
                         "+ encryption), remove the 'public'/'private' communities, restrict which hosts may query "
                         "it (ACL), and limit the view to the system group."),
            service=f"{port}/udp snmp", port=f"{port}/udp", attck=["T1602.001", "T1040"],
            confidence="confirmed (device answered)", weight=15 if default else 3,
            source="SNMP audit (snmpget, read-only)"))
    return out


def attempts_to_json(attempts: list[SnmpAttempt]) -> str:
    return json.dumps([asdict(a) for a in attempts])


def attempts_from_json(text: str) -> list[SnmpAttempt]:
    return [SnmpAttempt(**d) for d in json.loads(text or "[]")]
