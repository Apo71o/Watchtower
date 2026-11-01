"""Platform detection. Every module that shells out to an OS-specific tool
checks here first so it can fail with a clear message instead of a raw
subprocess error.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class OS(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    OTHER = "other"


def current_os() -> OS:
    if sys.platform.startswith("linux"):
        return OS.LINUX
    if sys.platform in ("win32", "cygwin"):
        return OS.WINDOWS
    if sys.platform == "darwin":
        return OS.MACOS
    return OS.OTHER


def is_linux() -> bool:
    return current_os() is OS.LINUX


def is_windows() -> bool:
    return current_os() is OS.WINDOWS


def is_debian_like() -> bool:
    """True on Debian, Ubuntu, Kali, Mint, Raspberry Pi OS, etc."""
    if not is_linux():
        return False
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            fields[key.strip()] = val.strip().strip('"')
    ids = {fields.get("ID", "")} | set(fields.get("ID_LIKE", "").split())
    return "debian" in ids or "ubuntu" in ids


def is_elevated() -> bool:
    """Root on POSIX, Administrator on Windows."""
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def supports_wifi_radio() -> bool:
    """Passive monitor-mode recon needs Linux driver support. Windows does
    not expose this to userspace reliably, so the feature is Linux-only."""
    return is_linux()


WIFI_UNSUPPORTED_REASON = (
    "Passive Wi-Fi recon needs monitor mode, which depends on Linux Wi-Fi "
    "driver support that Windows does not expose to userspace. Use a Debian "
    "machine, VM (with a USB Wi-Fi adapter passed through), or spare hardware "
    "running Debian for this feature. Everything else in Watchtower works here."
)


class PlatformUnsupported(RuntimeError):
    """Raised when a feature cannot run on this OS. The message is meant to be
    shown to the user as-is."""


def require_linux(feature: str) -> None:
    if not is_linux():
        raise PlatformUnsupported(
            f"{feature} is only available on Linux (detected: {platform.system()})."
        )


def relaunch_as_admin(args: list[str] | None = None) -> bool:
    """Windows: start a new elevated copy of Watchtower (UAC prompt). Returns
    True if the elevated process was started; the caller should then quit."""
    if not is_windows():
        return False
    import subprocess
    exe = sys.executable.replace("python.exe", "pythonw.exe")
    params = subprocess.list2cmdline(["-m", "watchtower", *(args or [])])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)  # type: ignore[attr-defined]
    return rc > 32


def which(tool: str) -> str | None:
    return shutil.which(tool)


@dataclass(frozen=True)
class PlatformInfo:
    os: OS
    system: str
    release: str
    machine: str
    python: str
    debian_like: bool
    elevated: bool
    wifi_radio_supported: bool

    def summary(self) -> str:
        distro = " (Debian family)" if self.debian_like else ""
        return (
            f"{self.system} {self.release}{distro}, {self.machine}, "
            f"Python {self.python}" + (", running as administrator/root" if self.elevated else "")
        )


def platform_info() -> PlatformInfo:
    return PlatformInfo(
        os=current_os(),
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        python=platform.python_version(),
        debian_like=is_debian_like(),
        elevated=is_elevated(),
        wifi_radio_supported=supports_wifi_radio(),
    )


def data_dir() -> Path:
    """Per-user data directory. WATCHTOWER_HOME overrides (used by tests)."""
    override = os.environ.get("WATCHTOWER_HOME")
    if override:
        path = Path(override)
    elif is_windows():
        path = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Watchtower"
    elif current_os() is OS.MACOS:
        path = Path.home() / "Library" / "Application Support" / "Watchtower"
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        path = Path(base) / "watchtower"
    path.mkdir(parents=True, exist_ok=True)
    return path
