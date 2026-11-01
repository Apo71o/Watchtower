"""Default-credential fingerprinting (report only).

Matches what nmap learned about a host against a bundled list of device types
known to ship with published default logins. It never connects to anything
and never tries a password.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources

from watchtower.core.findings_engine import Finding
from watchtower.core.nmap_runner import Host


@lru_cache(maxsize=1)
def fingerprints() -> list[dict]:
    text = resources.files("watchtower.data").joinpath("default_creds.json").read_text(encoding="utf-8")
    entries = json.loads(text)["entries"]
    for e in entries:
        e["_re"] = re.compile(e["match"], re.IGNORECASE)
    return entries


def fingerprint_text(host: Host) -> list[tuple[str, str]]:
    """(where, text) pairs describing the host, for matching and for showing why it matched."""
    out = []
    if host.hostnames:
        out.append(("hostname", " ".join(host.hostnames)))
    if host.vendor:
        out.append(("MAC vendor", host.vendor))
    for name, _acc in host.os_matches[:2]:
        out.append(("OS guess", name))
    for p in host.ports:
        if not p.state.startswith("open"):
            continue
        where = f"{p.portid}/{p.protocol}"
        banner = " ".join(x for x in (p.product, p.version, p.extrainfo, p.devicetype, p.ostype) if x)
        if banner:
            out.append((where, banner))
        for s in p.scripts:
            if s.id in ("http-title", "http-server-header", "banner", "ssh-hostkey", "upnp-info", "snmp-sysdescr"):
                out.append((f"{where} {s.id}", s.output.strip()[:300]))
    return out


def match(host: Host) -> list[tuple[dict, str, str]]:
    """-> [(entry, where, evidence)] one per matching fingerprint."""
    hits = []
    texts = fingerprint_text(host)
    for e in fingerprints():
        for where, text in texts:
            m = e["_re"].search(text)
            if m:
                hits.append((e, where, text))
                break
    return hits


def findings(host: Host) -> list[Finding]:
    out = []
    for e, where, evidence in match(host):
        creds = ", ".join(f"{u} / {p}" for u, p in e["credentials"])
        out.append(Finding(
            device=host.address, device_label=host.label, kind="default_creds",
            title=f"{e['vendor']} {e['model']}: ships with default credentials", severity="Medium",
            description=(f"This host looks like a {e['vendor']} {e['model']} (matched in {where}: "
                         f"“{evidence[:160]}”). That device type ships with the default login **{creds}** "
                         f"for {e['services']}. {e['note']} Watchtower did not try to log in; this is a "
                         "fingerprint match, so check whether the default was ever changed."),
            technique=("**Default accounts:** factory logins are printed in public manuals and baked into "
                       "automated tools and botnets (Mirai spread through IoT devices by trying a list of about 60 "
                       "default logins over telnet). If the default still works, anyone who can reach the "
                       "service owns the device."),
            remediation=("Log in and change the password to a long unique one (password manager). Disable or rename "
                         "default accounts where possible, turn off remote management interfaces you don't use "
                         "(telnet, WAN-side admin), and update the firmware."),
            service=where, attck=["T1078.001"], confidence="fingerprint match (login not attempted)",
            weight=15, source="default-credentials fingerprints"))
    return out
