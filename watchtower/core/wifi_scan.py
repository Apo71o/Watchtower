"""Nearby Wi-Fi network discovery.

Two ways to look:
  * managed scan (nmcli, else iwlist): the same scan your OS does to fill its
    Wi-Fi menu. Works with any adapter, no mode change.
  * monitor-mode listening (airodump-ng): fully passive; also sees client
    stations and networks on every channel. Needs a monitor-capable adapter.
Output files are CSV only (no packet capture is written).
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from watchtower.core import deps
from watchtower.core.interfaces import IFNAME_RE, deps_missing
from watchtower.core.platform_utils import is_elevated, require_linux
from watchtower.core.runner import CommandResult, CommandRunner

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


@dataclass
class AccessPoint:
    bssid: str
    ssid: str = ""
    channel: int | None = None
    freq: int | None = None
    signal_dbm: int | None = None
    signal_pct: int | None = None
    security: str = ""        # normalized: Open / WEP / WPA / WPA2 / WPA3 / WPA2/WPA3 / OWE (+ "-Enterprise")
    cipher: str | None = None
    auth: str | None = None   # PSK / SAE / MGT / OPN / OWE
    wps: int | None = None
    raw_security: str = ""
    source: str = ""
    in_use: bool = False


@dataclass
class Station:
    mac: str
    bssid: str | None = None
    power: int | None = None
    packets: int | None = None
    probes: list[str] = field(default_factory=list)


def channel_from_freq(freq: int | None) -> int | None:
    if not freq:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def freq_from_channel(ch: int | None) -> int | None:
    """Assumes channels 1-14 are 2.4 GHz and 32-177 are 5 GHz (airodump-ng's CSV has no frequency)."""
    if not ch:
        return None
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    if 32 <= ch <= 177:
        return 5000 + 5 * ch
    return None


def pct_from_dbm(dbm: int | None) -> int | None:
    if dbm is None or dbm >= 0:
        return None
    return max(0, min(100, 2 * (dbm + 100)))


def normalize_security(tokens: str, auth: str | None = None) -> str:
    t = tokens.upper().replace("WPA1", "WPA")
    if not t.strip() or t.strip() in ("OPN", "--", "NONE"):
        return "OWE" if auth and "OWE" in auth.upper() else "Open"
    if "WEP" in t and "WPA" not in t:
        return "WEP"
    parts = []
    for name in ("WPA", "WPA2", "WPA3"):
        if re.search(rf"\b{name}\b", t):
            parts.append(name)
    sec = "/".join(parts) or t.strip()
    if "802.1X" in t or (auth and "MGT" in auth.upper()):
        sec += "-Enterprise"
    return sec


# ---- nmcli ----

NMCLI_FIELDS = "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY"


def split_terse(line: str) -> list[str]:
    """nmcli -t escapes ':' and '\\' inside values with a backslash."""
    out, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def parse_nmcli(text: str) -> list[AccessPoint]:
    aps = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = split_terse(line)
        if len(f) < 7 or not MAC_RE.match(f[1]):
            continue
        freq = int(re.sub(r"\D", "", f[4]) or 0) or None
        sec = f[6]
        aps.append(AccessPoint(
            bssid=f[1].upper(), ssid=f[2], channel=int(f[3]) if f[3].isdigit() else channel_from_freq(freq),
            freq=freq, signal_pct=int(f[5]) if f[5].isdigit() else None,
            security=normalize_security(sec), auth="MGT" if "802.1X" in sec else
            ("SAE" if "WPA3" in sec else ("PSK" if "WPA" in sec else ("OPN" if not sec.strip() else None))),
            raw_security=sec, source="nmcli", in_use=f[0].strip() == "*",
        ))
    return aps


# ---- iwlist ----

def _ie_has_wps(hexdata: str) -> bool:
    # Vendor-specific IE (0xDD), OUI 00:50:F2 type 4 = Wi-Fi Protected Setup
    h = hexdata.upper()
    return h.startswith("DD") and h[4:12] == "0050F204"


def parse_iwlist(text: str) -> list[AccessPoint]:
    aps: list[AccessPoint] = []
    cells = re.split(r"\n\s*Cell \d+ - ", "\n" + text)
    for cell in cells[1:]:
        m = re.match(r"Address: (\S+)", cell)
        if not m:
            continue
        ap = AccessPoint(bssid=m.group(1).upper(), source="iwlist", wps=0)
        enc_on = False
        ies: list[str] = []
        auths: set[str] = set()
        ciphers: set[str] = set()
        for raw in cell.splitlines():
            line = raw.strip()
            if mm := re.match(r'ESSID:"(.*)"$', line):
                ap.ssid = mm.group(1)
            elif mm := re.match(r"Channel:(\d+)", line):
                ap.channel = int(mm.group(1))
            elif mm := re.match(r"Frequency:([\d.]+) GHz", line):
                ap.freq = round(float(mm.group(1)) * 1000)
            elif mm := re.search(r"Signal level=(-?\d+) dBm", line):
                ap.signal_dbm = int(mm.group(1))
            elif mm := re.search(r"Quality=(\d+)/(\d+)", line):
                ap.signal_pct = round(100 * int(mm.group(1)) / int(mm.group(2)))
            elif line.startswith("Encryption key:"):
                enc_on = line.endswith("on")
            elif mm := re.match(r"IE: IEEE 802\.11i/WPA2", line):
                ies.append("WPA2")
            elif mm := re.match(r"IE: WPA Version", line):
                ies.append("WPA")
            elif mm := re.match(r"IE: Unknown: ([0-9A-Fa-f]+)", line):
                if _ie_has_wps(mm.group(1)):
                    ap.wps = 1
            elif mm := re.match(r"Authentication Suites \(\d+\) : (.+)", line):
                auths.update(mm.group(1).split())
            elif mm := re.match(r"Pairwise Ciphers \(\d+\) : (.+)", line):
                ciphers.update(mm.group(1).split())
        if ap.channel is None:
            ap.channel = channel_from_freq(ap.freq)
        if ap.signal_dbm is not None:
            ap.signal_pct = pct_from_dbm(ap.signal_dbm)
        if "SAE" in auths and "WPA2" in ies:
            ies = [i for i in ies if i != "WPA2"] + ["WPA3"] + (["WPA2"] if "PSK" in auths else [])
        raw = " ".join(ies) if ies else ("WEP" if enc_on else "")
        ap.auth = "MGT" if "802.1x" in {a.lower() for a in auths} else \
            ("SAE" if "SAE" in auths else ("PSK" if "PSK" in auths else ("OPN" if not enc_on else None)))
        ap.raw_security = raw
        ap.security = normalize_security(raw, ap.auth)
        ap.cipher = " ".join(sorted(ciphers)) or None
        aps.append(ap)
    return aps


# ---- airodump-ng CSV ----

def _int(s: str) -> int | None:
    s = s.strip()
    try:
        return int(s)
    except ValueError:
        return None


def parse_airodump_csv(text: str) -> tuple[list[AccessPoint], list[Station]]:
    aps: list[AccessPoint] = []
    stations: list[Station] = []
    section = None
    for line in text.replace("\r", "").splitlines():
        if not line.strip():
            continue
        if line.startswith("BSSID,"):
            section = "ap"
            continue
        if line.startswith("Station MAC,"):
            section = "sta"
            continue
        if section == "ap":
            f = line.split(",", 13)
            if len(f) < 14 or not MAC_RE.match(f[0].strip()):
                continue
            essid = f[13].rsplit(",", 1)[0].strip()
            privacy, cipher, auth = f[5].strip(), f[6].strip(), f[7].strip()
            power = _int(f[8])
            dbm = power if power is not None and power < 0 and power != -1 else None
            ch = _int(f[3])
            aps.append(AccessPoint(
                bssid=f[0].strip().upper(), ssid=essid if not essid.startswith("\\x00") else "",
                channel=ch if ch and ch > 0 else None, freq=freq_from_channel(ch if ch and ch > 0 else None),
                signal_dbm=dbm, signal_pct=pct_from_dbm(dbm),
                security=normalize_security(privacy, auth), cipher=cipher or None, auth=auth or None,
                raw_security=privacy, source="airodump-ng",
            ))
        elif section == "sta":
            f = line.split(",", 6)
            if len(f) < 6 or not MAC_RE.match(f[0].strip()):
                continue
            bssid = f[5].strip()
            probes = [p.strip() for p in f[6].split(",") if p.strip()] if len(f) > 6 else []
            power = _int(f[3])
            stations.append(Station(
                mac=f[0].strip().upper(), bssid=bssid.upper() if MAC_RE.match(bssid) else None,
                power=power if power is not None and power < 0 and power != -1 else None,
                packets=_int(f[4]), probes=probes,
            ))
    return aps, stations


# ---- running scans ----

def managed_scan_argv(iface: str | None = None) -> tuple[list[str], str]:
    nmcli = deps.find_binary("nmcli")
    if nmcli:
        argv = [nmcli, "-t", "-f", NMCLI_FIELDS, "device", "wifi", "list", "--rescan", "yes"]
        if iface:
            argv += ["ifname", iface]
        return argv, "nmcli"
    iwlist = deps.find_binary("iwlist")
    if iwlist:
        if not iface:
            raise ValueError("Choose an interface (iwlist needs one).")
        return [iwlist, iface, "scan"], "iwlist"
    raise deps_missing("nmcli")


def managed_scan(runner: CommandRunner, iface: str | None = None) -> list[AccessPoint]:
    require_linux("Nearby network scan")
    argv, tool = managed_scan_argv(iface)
    res = runner.run(argv, purpose=f"nearby network scan ({tool})", target=iface, timeout=60)
    if not res.ok:
        raise RuntimeError(f"{tool} failed (exit {res.exit_code}): {res.output.strip()[-500:]}")
    return parse_nmcli(res.stdout) if tool == "nmcli" else parse_iwlist(res.stdout)


@dataclass
class AirodumpRun:
    argv: list[str]
    out_dir: Path
    needs_password: bool


def airodump_argv(iface: str, seconds: int, band: str = "bg", channels: str = "") -> AirodumpRun:
    """airodump-ng for `seconds`, CSV output only. `timeout` sends SIGINT so
    airodump-ng flushes its final CSV. Wrapped in pkexec when the binary has
    neither root nor file capabilities."""
    require_linux("Monitor-mode listening")
    if not IFNAME_RE.match(iface):
        raise ValueError(f"invalid interface name: {iface!r}")
    if band and not re.fullmatch(r"[abg]{1,3}", band):
        raise ValueError(f"invalid band: {band!r}")
    if channels and not re.fullmatch(r"[0-9,\-]{1,64}", channels):
        raise ValueError(f"invalid channel list: {channels!r}")
    airodump = deps.find_binary("airodump-ng")
    if not airodump:
        raise deps_missing("airodump-ng")
    timeout = deps.find_binary("timeout") or "/usr/bin/timeout"
    out_dir = Path(tempfile.mkdtemp(prefix="watchtower-airodump-"))
    os.chmod(out_dir, 0o755)
    argv = [timeout, "--signal=INT", "--kill-after=5", str(int(seconds)), airodump,
            "--write-interval", "1", "--output-format", "csv", "-w", str(out_dir / "scan")]
    if channels:
        argv += ["--channel", channels]
    elif band:
        argv += ["--band", band]
    argv.append(iface)
    needs_pw = not is_elevated() and not deps.has_file_capabilities(airodump)
    return AirodumpRun(argv, out_dir, needs_pw)


def read_airodump_output(run: AirodumpRun) -> tuple[list[AccessPoint], list[Station]]:
    try:
        csvs = sorted(run.out_dir.glob("scan-*.csv"))
        if not csvs:
            return [], []
        return parse_airodump_csv(csvs[-1].read_text(encoding="utf-8", errors="replace"))
    finally:
        shutil.rmtree(run.out_dir, ignore_errors=True)


def airodump_ok(res: CommandResult) -> bool:
    # timeout(1) exits 124 when it had to stop the command: the normal case here.
    return res.exit_code in (0, 124, 130, -2)
