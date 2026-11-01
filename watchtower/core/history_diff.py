"""What changed between two scans of the same target, or two Wi-Fi snapshots.

Levels: "alert" (likely needs action: a port opened, a new finding, a new access
point using your network's name), "notice" (worth a look), "good" (something got
fixed or closed), "info".
"""

from __future__ import annotations

from dataclasses import dataclass

from watchtower.core import default_creds
from watchtower.core.findings_engine import host_findings, version_key
from watchtower.core.nmap_runner import Host, ScanResult

LEVELS = ["alert", "notice", "good", "info"]
LEVEL_RANK = {lv: i for i, lv in enumerate(LEVELS)}

# Stronger is later; used to tell a downgrade from an upgrade.
SECURITY_RANK = {"Open": 0, "OWE": 1, "WEP": 1, "WPA": 2, "WPA/WPA2": 3, "WPA2": 4, "WPA2/WPA3": 5, "WPA3": 6}


@dataclass
class Change:
    level: str
    category: str      # host / port / service / os / finding / wifi
    device: str
    title: str
    detail: str = ""


def _open_ports(h: Host) -> dict[str, object]:
    return {f"{p.portid}/{p.protocol}": p for p in h.ports if p.state.startswith("open")}


def _finding_titles(h: Host) -> dict[str, str]:
    out = {}
    for f in host_findings(h) + default_creds.findings(h):
        if not f.patched:
            out[f.key] = f"{f.severity}: {f.title}" + (f" ({f.port})" if f.port else "")
    return out


def diff_hosts(old: Host | None, new: Host | None) -> list[Change]:
    if old is None and new is None:
        return []
    dev = (new or old).address
    label = (new or old).label
    if old is None:
        ports = ", ".join(_open_ports(new)) or "no open ports"
        return [Change("notice", "host", dev, f"New host: {label}", f"Open: {ports}")] + [
            Change("alert", "finding", dev, "New finding", t) for t in _finding_titles(new).values()]
    if new is None:
        return [Change("notice", "host", dev, f"Host no longer responds: {label}",
                       "It may be off, moved to another address, or now blocking the scan.")]
    out: list[Change] = []
    a, b = _open_ports(old), _open_ports(new)
    for port in sorted(set(b) - set(a), key=_port_key):
        p = b[port]
        out.append(Change("alert", "port", dev, f"Port opened: {port}",
                          f"{p.service} {p.version_string}".strip()))
    for port in sorted(set(a) - set(b), key=_port_key):
        out.append(Change("good", "port", dev, f"Port closed: {port}", f"was {a[port].service}".strip()))
    for port in sorted(set(a) & set(b), key=_port_key):
        pa, pb = a[port], b[port]
        if pa.service != pb.service or pa.product != pb.product:
            out.append(Change("notice", "service", dev, f"Different service on {port}",
                              f"{pa.service} {pa.product} → {pb.service} {pb.product}".strip()))
        elif pa.version != pb.version and pa.version and pb.version:
            up = version_key(pb.version) > version_key(pa.version)
            out.append(Change("good" if up else "notice", "service", dev,
                              f"{pb.product or pb.service} {'updated' if up else 'version changed'} on {port}",
                              f"{pa.version} → {pb.version}"))
    os_a = old.os_matches[0][0] if old.os_matches else ""
    os_b = new.os_matches[0][0] if new.os_matches else ""
    if os_a and os_b and os_a != os_b:
        out.append(Change("info", "os", dev, "OS guess changed", f"{os_a} → {os_b}"))
    if old.mac and new.mac and old.mac != new.mac:
        out.append(Change("alert", "host", dev, "Different device at this address (MAC changed)",
                          f"{old.mac} {old.vendor} → {new.mac} {new.vendor}"))
    fa, fb = _finding_titles(old), _finding_titles(new)
    out += [Change("alert", "finding", dev, "New finding", fb[k]) for k in fb.keys() - fa.keys()]
    out += [Change("good", "finding", dev, "Resolved", fa[k]) for k in fa.keys() - fb.keys()]
    return out


def diff_scans(old: ScanResult, new: ScanResult) -> list[Change]:
    """Compare two scans of the same target (only hosts that were up count)."""
    a = {h.address: h for h in old.hosts if h.status == "up"}
    b = {h.address: h for h in new.hosts if h.status == "up"}
    out: list[Change] = []
    for addr in sorted(set(a) | set(b), key=_addr_key):
        out += diff_hosts(a.get(addr), b.get(addr))
    return sort_changes(out)


def diff_wifi(old: dict[str, dict], new: dict[str, dict], authorized_ssids: set[str] = frozenset(),
              authorized_bssids: set[str] = frozenset()) -> list[Change]:
    """Compare two Wi-Fi snapshots (bssid -> observation row)."""
    out: list[Change] = []
    for bssid in sorted(set(new) - set(old)):
        n = new[bssid]
        ssid = n.get("ssid") or "(hidden)"
        if n.get("ssid") and n["ssid"] in authorized_ssids and bssid not in authorized_bssids:
            out.append(Change(
                "alert", "wifi", bssid, f"New access point using your network name “{ssid}”",
                f"{n.get('security')} on channel {n.get('channel')}. If you didn't add a new access point or "
                "mesh node, this could be an evil twin imitating your network. Compare it with your router's "
                "BSSIDs; if it isn't yours, find its location by signal strength."))
        else:
            out.append(Change("info", "wifi", bssid, f"New network nearby: {ssid}",
                              f"{n.get('security')} · ch {n.get('channel')}"))
    for bssid in sorted(set(old) - set(new)):
        o = old[bssid]
        mine = bssid in authorized_bssids
        out.append(Change("notice" if mine else "info", "wifi", bssid,
                          f"{'Your network' if mine else 'Network'} not seen: {o.get('ssid') or '(hidden)'}",
                          "Out of range, switched off, or on a channel this scan didn't cover."))
    for bssid in sorted(set(old) & set(new)):
        o, n = old[bssid], new[bssid]
        mine = bssid in authorized_bssids
        ssid = n.get("ssid") or o.get("ssid") or "(hidden)"
        if o.get("security") != n.get("security") and o.get("security") and n.get("security"):
            ra, rb = SECURITY_RANK.get(_base(o["security"]), 3), SECURITY_RANK.get(_base(n["security"]), 3)
            level = "alert" if rb < ra and mine else ("good" if rb > ra else "notice")
            out.append(Change(level, "wifi", bssid, f"Security changed on {ssid}",
                              f"{o['security']} → {n['security']}" + (" (weaker)" if rb < ra else "")))
        if o.get("wps") == 0 and n.get("wps") == 1:
            out.append(Change("alert" if mine else "info", "wifi", bssid, f"WPS turned on: {ssid}",
                              "Often re-enabled by firmware updates or a factory reset."))
        elif o.get("wps") == 1 and n.get("wps") == 0:
            out.append(Change("good", "wifi", bssid, f"WPS turned off: {ssid}"))
        if o.get("ssid") and n.get("ssid") and o["ssid"] != n["ssid"]:
            out.append(Change("notice", "wifi", bssid, "Network renamed", f"{o['ssid']} → {n['ssid']}"))
        if o.get("channel") and n.get("channel") and o["channel"] != n["channel"] and mine:
            out.append(Change("info", "wifi", bssid, f"Channel changed on {ssid}", f"{o['channel']} → {n['channel']}"))
    return sort_changes(out)


def sort_changes(changes: list[Change]) -> list[Change]:
    return sorted(changes, key=lambda c: (LEVEL_RANK[c.level], c.device, c.title))


def summary(changes: list[Change]) -> str:
    if not changes:
        return "No changes."
    counts = {lv: sum(1 for c in changes if c.level == lv) for lv in LEVELS}
    return ", ".join(f"{n} {lv}" for lv, n in counts.items() if n)


def _base(sec: str) -> str:
    return sec.replace("-Enterprise", "")


def _port_key(p: str):
    num, _, proto = p.partition("/")
    return (proto, int(num))


def _addr_key(a: str):
    try:
        import ipaddress
        return (0, int(ipaddress.ip_address(a)))
    except ValueError:
        return (1, a)
