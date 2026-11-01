"""Wireless interface discovery and mode switching (Linux).

Discovery is read-only (`iw dev`, `iw list`, `ip -j addr`, /sys). Switching
an interface between managed and monitor mode is returned as a deps.Plan for
the GUI to show and confirm, since it needs root and drops the Wi-Fi
connection on that adapter.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from watchtower.core import deps
from watchtower.core.platform_utils import require_linux
from watchtower.core.runner import CommandRunner

IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


@dataclass
class WirelessInterface:
    name: str
    phy: str
    mac: str = ""
    mode: str = ""             # managed / monitor / AP / ...
    ssid: str = ""             # connected network, if any
    channel: int | None = None
    freq: int | None = None
    driver: str = ""
    supported_modes: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)   # CIDRs, e.g. 192.168.1.23/24

    @property
    def monitor_capable(self) -> bool:
        return "monitor" in self.supported_modes

    @property
    def in_monitor_mode(self) -> bool:
        return self.mode == "monitor"


def parse_iw_dev(text: str) -> list[dict]:
    out: list[dict] = []
    phy = ""
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if m := re.match(r"^phy#(\d+)", line):
            phy = f"phy{m.group(1)}"
            cur = None
            continue
        if line.startswith("Unnamed/non-netdev interface"):
            cur = None   # P2P-device etc.: not a usable interface; don't merge into the previous one
            continue
        if m := re.match(r"^Interface (\S+)", line):
            cur = {"name": m.group(1), "phy": phy}
            out.append(cur)
            continue
        if cur is None:
            continue
        if m := re.match(r"^addr (\S+)", line):
            cur["mac"] = m.group(1).upper()
        elif m := re.match(r"^ssid (.*)$", line):
            cur["ssid"] = m.group(1)
        elif m := re.match(r"^type (\S+)", line):
            cur["mode"] = m.group(1)
        elif m := re.match(r"^channel (\d+) \((\d+) MHz\)", line):
            cur["channel"], cur["freq"] = int(m.group(1)), int(m.group(2))
    return out


def parse_iw_list(text: str) -> dict[str, list[str]]:
    """phy name -> supported interface modes."""
    modes: dict[str, list[str]] = {}
    phy = None
    in_modes = False
    for raw in text.splitlines():
        if m := re.match(r"^Wiphy (\S+)", raw):
            phy = m.group(1)
            modes[phy] = []
            in_modes = False
            continue
        if phy is None:
            continue
        if raw.strip() == "Supported interface modes:":
            in_modes = True
            continue
        if in_modes:
            if m := re.match(r"^\s+\* (\S+)", raw):
                modes[phy].append(m.group(1))
            else:
                in_modes = False
    return modes


def parse_ip_addr_json(text: str) -> dict[str, list[str]]:
    """`ip -j addr show` -> interface name -> list of CIDRs (IPv4 and global IPv6)."""
    out: dict[str, list[str]] = {}
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return out
    for iface in data:
        cidrs = []
        for a in iface.get("addr_info", []):
            if a.get("family") == "inet" or (a.get("family") == "inet6" and a.get("scope") == "global"):
                cidrs.append(f"{a['local']}/{a['prefixlen']}")
        out[iface.get("ifname", "")] = cidrs
    return out


def network_of(cidr: str) -> str:
    """192.168.1.23/24 -> 192.168.1.0/24"""
    return str(ipaddress.ip_interface(cidr).network)


def _driver(name: str) -> str:
    link = Path("/sys/class/net") / name / "device" / "driver"
    try:
        return os.path.basename(os.readlink(link))
    except OSError:
        return ""


def local_addresses(runner: CommandRunner) -> dict[str, list[str]]:
    ip = deps.find_binary("ip")
    if not ip:
        return {}
    res = runner.run([ip, "-j", "addr", "show"], purpose="list local IP addresses", timeout=15)
    return parse_ip_addr_json(res.stdout) if res.ok else {}


def list_wireless(runner: CommandRunner) -> list[WirelessInterface]:
    require_linux("Wireless interface detection")
    iw = deps.find_binary("iw")
    if not iw:
        raise deps_missing("iw")
    dev = runner.run([iw, "dev"], purpose="list wireless interfaces", timeout=15)
    phys = runner.run([iw, "list"], purpose="read wireless capabilities (monitor-mode support)", timeout=15)
    modes = parse_iw_list(phys.stdout)
    addrs = local_addresses(runner)
    result = []
    for d in parse_iw_dev(dev.stdout):
        wi = WirelessInterface(**d)
        wi.supported_modes = modes.get(wi.phy, [])
        wi.driver = _driver(wi.name)
        wi.addresses = addrs.get(wi.name, [])
        result.append(wi)
    return result


class ToolMissing(RuntimeError):
    pass


def deps_missing(key: str) -> ToolMissing:
    tool = next((t for t in deps.TOOLS if t.key == key), None)
    hint = deps.install_hint(tool) if tool else ""
    return ToolMissing(f"'{key}' is not installed. {hint}".strip())


def set_mode_plan(iface: str, mode: str) -> deps.Plan:
    """Root script that switches `iface` to monitor or managed mode. When
    NetworkManager is present it is told to leave the interface alone while in
    monitor mode, and to manage it again afterwards."""
    if not IFNAME_RE.match(iface):
        raise ValueError(f"invalid interface name: {iface!r}")
    if mode not in ("monitor", "managed"):
        raise ValueError(mode)
    ip = deps.find_binary("ip") or "/usr/sbin/ip"
    iw = deps.find_binary("iw") or "/usr/sbin/iw"
    nmcli = deps.find_binary("nmcli")
    cmds = []
    if nmcli and mode == "monitor":
        cmds.append(f"{nmcli} device set {iface} managed no")
    cmds += [f"{ip} link set {iface} down", f"{iw} dev {iface} set type {mode}", f"{ip} link set {iface} up"]
    if nmcli and mode == "managed":
        cmds.append(f"{nmcli} device set {iface} managed yes")
    script = " && ".join(cmds)
    return deps.Plan([deps.Step(f"Switch {iface} to {mode} mode", ["/bin/sh", "-c", script], True, script)], [])
