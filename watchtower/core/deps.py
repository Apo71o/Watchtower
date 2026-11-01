"""External tool dependency checker.

Watchtower orchestrates existing tools; it does not bundle them. This module
detects which are present (with versions), and for missing ones produces the
exact install command to show the user. Nothing is installed without an
explicit confirmation in the GUI.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from watchtower.core.platform_utils import OS, current_os, is_linux, is_windows
from watchtower.core.runner import CommandRunner, CommandUnavailable, format_command

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)")


@dataclass
class Tool:
    key: str                        # stable id used by features ("nmap", "sslyze", ...)
    name: str                       # display name
    purpose: str                    # what Watchtower uses it for
    platforms: tuple[OS, ...]
    binaries: tuple[str, ...] = ()  # any one of these on PATH counts as present
    version_args: tuple[str, ...] = ("--version",)
    python_module: str | None = None  # alternatively satisfied by an importable module
    apt_package: str | None = None
    winget_id: str | None = None
    manual_url: str | None = None   # for tools with no clean package-manager story
    optional: bool = False
    needs_raw_sockets: bool = False  # candidate for the setcap step on Linux
    note: str = ""


@dataclass
class ToolStatus:
    tool: Tool
    present: bool
    path: str | None = None
    version: str | None = None
    detail: str = ""
    install_hint: str = ""
    extra: dict = field(default_factory=dict)


TOOLS: list[Tool] = [
    Tool("nmap", "Nmap", "Host discovery, port/service/version detection, optional --script vuln.",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("nmap",), ("--version",),
         apt_package="nmap", winget_id="Insecure.Nmap",
         manual_url="https://nmap.org/download.html", needs_raw_sockets=True),
    Tool("npcap", "Npcap driver", "Packet capture driver nmap needs on Windows for SYN scans and OS detection.",
         (OS.WINDOWS,), manual_url="https://npcap.com/#download",
         note="Bundled with the official Nmap installer; tick the Npcap box during setup."),
    Tool("iw", "iw", "Lists wireless interfaces and whether they support monitor mode.",
         (OS.LINUX,), ("iw",), ("--version",), apt_package="iw"),
    Tool("nmcli", "nmcli (NetworkManager)", "Managed-mode scan of nearby networks without monitor mode.",
         (OS.LINUX,), ("nmcli",), ("--version",), apt_package="network-manager", optional=True),
    Tool("iwlist", "iwlist (wireless-tools)", "Legacy managed-mode scan; fallback when nmcli is absent.",
         (OS.LINUX,), ("iwlist",), ("--version",), apt_package="wireless-tools", optional=True),
    Tool("airodump-ng", "airodump-ng", "Passive monitor-mode listing of APs and clients (listen-only).",
         (OS.LINUX,), ("airodump-ng",), ("--help",), apt_package="aircrack-ng", needs_raw_sockets=True,
         note="The aircrack-ng package ships several tools; Watchtower only ever runs airodump-ng, read-only."),
    Tool("sslyze", "SSLyze", "TLS configuration audit (protocols, ciphers, certificates).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("sslyze",), ("--help",), python_module="sslyze",
         manual_url="https://github.com/nabla-c0d3/sslyze", optional=True,
         note="Python package: install into Watchtower's venv with  pip install sslyze"),
    Tool("testssl", "testssl.sh", "Alternative TLS audit backend.",
         (OS.LINUX, OS.MACOS), ("testssl", "testssl.sh"), ("--version",), apt_package="testssl.sh",
         optional=True),
    Tool("snmp", "Net-SNMP (snmpget/snmpwalk)", "Read-only SNMP GET queries to check for exposed community strings.",
         (OS.LINUX, OS.MACOS), ("snmpget",), ("-V",), apt_package="snmp", optional=True),
    Tool("msfconsole", "Metasploit Framework",
         "Cross-reference only: looks up module NAMES matching a service version. Never launches anything.",
         (OS.LINUX, OS.WINDOWS), ("msfconsole",), ("--version",),
         manual_url="https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html",
         optional=True),
    Tool("nuclei", "Nuclei", "Optional template-based vulnerability matching for findings.",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("nuclei",), ("-version",),
         winget_id="ProjectDiscovery.Nuclei", manual_url="https://github.com/projectdiscovery/nuclei/releases",
         optional=True),
    Tool("weasyprint", "WeasyPrint", "Optional PDF export of reports (HTML export works without it).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("weasyprint",), ("--version",), python_module="weasyprint",
         apt_package="weasyprint", optional=True),
]


def tools_for_platform(os_: OS | None = None) -> list[Tool]:
    os_ = os_ or current_os()
    return [t for t in TOOLS if os_ in t.platforms]


def _npcap_installed() -> bool:
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return (root / "System32" / "Npcap").is_dir()


def _extract_version(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip():
            m = _VERSION_RE.search(line)
            if m:
                return m.group(1)
    return None


def install_hint(tool: Tool, os_: OS | None = None) -> str:
    os_ = os_ or current_os()
    if os_ is OS.LINUX and tool.apt_package:
        return f"sudo apt install {tool.apt_package}"
    if os_ is OS.WINDOWS and tool.winget_id:
        return f"winget install {tool.winget_id}"
    if tool.python_module and not tool.apt_package:
        return f"pip install {tool.python_module}   (inside Watchtower's venv)"
    if tool.manual_url:
        return f"Download: {tool.manual_url}"
    return "See INSTALL.md"


def check_tool(tool: Tool, runner: CommandRunner | None = None) -> ToolStatus:
    hint = install_hint(tool)
    if tool.key == "npcap":
        ok = _npcap_installed()
        return ToolStatus(tool, ok, detail="driver found" if ok else "", install_hint=hint)

    path = next((p for p in (shutil.which(b) for b in tool.binaries) if p), None)
    if path:
        version = None
        if runner is not None:
            try:
                res = runner.run([path, *tool.version_args], purpose=f"dependency check: {tool.name} version",
                                 timeout=20)
                version = _extract_version(res.output)
            except CommandUnavailable:
                pass
        return ToolStatus(tool, True, path=path, version=version, install_hint=hint)

    if tool.python_module and importlib.util.find_spec(tool.python_module) is not None:
        version = None
        try:
            from importlib.metadata import version as pkg_version
            version = pkg_version(tool.python_module)
        except Exception:
            pass
        return ToolStatus(tool, True, path=f"python module '{tool.python_module}'", version=version,
                          install_hint=hint)

    return ToolStatus(tool, False, install_hint=hint)


def check_all(runner: CommandRunner | None = None) -> list[ToolStatus]:
    return [check_tool(t, runner) for t in tools_for_platform()]


class DependencyState:
    """What features can use. Features call .available("nmap") etc. and gray
    themselves out with .reason("nmap") as the tooltip when False."""

    def __init__(self, statuses: list[ToolStatus] | None = None):
        self.statuses: dict[str, ToolStatus] = {s.tool.key: s for s in (statuses or [])}

    def update(self, statuses: list[ToolStatus]) -> None:
        self.statuses = {s.tool.key: s for s in statuses}

    def available(self, key: str) -> bool:
        s = self.statuses.get(key)
        return bool(s and s.present)

    def reason(self, key: str) -> str:
        s = self.statuses.get(key)
        if s is None:
            return f"requires {key}, which is not supported on this platform"
        if s.present:
            return ""
        return f"requires {s.tool.name}, not installed ({s.install_hint})"


# ---- install / privilege plans (always shown to the user and confirmed) ----

def apt_install_argv(missing: list[ToolStatus]) -> list[str] | None:
    pkgs = sorted({s.tool.apt_package for s in missing if s.tool.apt_package})
    if not pkgs:
        return None
    return ["apt-get", "install", "-y", *pkgs]


def winget_install_argvs(missing: list[ToolStatus]) -> list[list[str]]:
    return [["winget", "install", "--exact", "--id", s.tool.winget_id]
            for s in missing if s.tool.winget_id]


def setcap_argvs(statuses: list[ToolStatus]) -> list[list[str]]:
    """Linux only: grant raw-socket capabilities to specific binaries instead of
    running the whole GUI as root."""
    out = []
    for s in statuses:
        if s.present and s.tool.needs_raw_sockets and s.path and not s.path.startswith("python"):
            real = os.path.realpath(s.path)
            out.append(["setcap", "cap_net_raw,cap_net_admin+eip", real])
    return out


def elevate(argv: list[str]) -> list[str] | None:
    """Wrap argv so it prompts for the admin password graphically (pkexec).
    Returns None if no graphical elevation helper exists; the GUI then shows
    the command to copy into a terminal instead."""
    if is_linux() and shutil.which("pkexec"):
        return ["pkexec", *argv]
    return None


def describe_plan(argvs: list[list[str]], elevated: bool) -> str:
    prefix = "sudo " if elevated and not is_windows() else ""
    return "\n".join(prefix + format_command(a) for a in argvs)
