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
import sys
from dataclasses import dataclass, field
from pathlib import Path

from watchtower.core.platform_utils import OS, current_os, is_elevated, is_linux, is_windows
from watchtower.core.runner import CommandRunner, CommandUnavailable, format_command

_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")
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
    pip_package: str | None = None    # PyPI name when it differs from the module (dnspython -> dns)
    apt_package: str | None = None
    winget_id: str | None = None
    winget_interactive: bool = False  # installer can't run silently (e.g. Npcap free edition)
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
    installable: bool | None = None   # False: this distro has no package for it (None = unknown)


TOOLS: list[Tool] = [
    Tool("nmap", "Nmap", "Host discovery, port/service/version detection, optional --script vuln.",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("nmap",), ("--version",),
         apt_package="nmap", winget_id="Insecure.Nmap",
         manual_url="https://nmap.org/download.html", needs_raw_sockets=True),
    Tool("npcap", "Npcap driver", "Packet capture driver nmap needs on Windows for SYN scans and OS detection.",
         (OS.WINDOWS,), winget_id="Insecure.Npcap", winget_interactive=True,
         manual_url="https://npcap.com/#download",
         note="Its installer opens a window you click through (it cannot install silently)."),
    Tool("iw", "iw", "Lists wireless interfaces and whether they support monitor mode.",
         (OS.LINUX,), ("iw",), ("--version",), apt_package="iw"),
    Tool("nmcli", "nmcli (NetworkManager)", "Managed-mode scan of nearby networks without monitor mode.",
         (OS.LINUX,), ("nmcli",), ("--version",), apt_package="network-manager", optional=True),
    Tool("iwlist", "iwlist (wireless-tools)", "Legacy managed-mode scan. Not needed: nmcli or iw cover it.",
         (OS.LINUX,), ("iwlist",), ("--version",), apt_package="wireless-tools", optional=True,
         note="Obsolete; removed from newer Ubuntu/Debian releases."),
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
    Tool("hashcat", "hashcat", "Password recovery: dictionary attacks on hashes/files you own (Password Tools).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("hashcat",), ("--version",), apt_package="hashcat",
         manual_url="https://hashcat.net/hashcat/", optional=True),
    Tool("john", "John the Ripper", "Alternative password-recovery engine; its *2john tools extract hashes from "
         "ZIP/RAR/Office/PDF files (Password Tools).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("john",), ("--version",), apt_package="john",
         manual_url="https://www.openwall.com/john/", optional=True,
         note="The 'jumbo' build (apt: john, or john-the-ripper on some distros) supports the many extra formats."),
    Tool("zxcvbn", "zxcvbn (Python)", "Pattern-based password strength analysis (Password Tools).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), (), python_module="zxcvbn",
         manual_url="https://pypi.org/project/zxcvbn/", optional=True,
         note="Python package: install into Watchtower's venv with  pip install zxcvbn"),
    Tool("nikto", "Nikto", "Web server scanner for the Web Audit tab (known files, outdated software, misconfig).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("nikto",), ("-Version",), apt_package="nikto",
         manual_url="https://github.com/sullo/nikto", optional=True),
    Tool("subfinder", "subfinder", "Passive subdomain discovery from public sources (CT logs, passive DNS) for a "
         "domain you own (Domain Audit). Never contacts the domain's servers.",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("subfinder",), ("-version",),
         manual_url="https://github.com/projectdiscovery/subfinder/releases", optional=True,
         note="Go binary from the project's releases (or `go install`); not packaged by Ubuntu."),
    Tool("amass", "OWASP Amass", "Alternative passive subdomain source (Domain Audit; only run with -passive).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("amass",), ("-version",), apt_package="amass",
         manual_url="https://github.com/owasp-amass/amass/releases", optional=True,
         note="Watchtower only uses amass builds that still have `enum -passive`."),
    Tool("dnspython", "dnspython (Python)", "DNS lookups of SPF / DKIM / DMARC records (Domain Audit).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), (), python_module="dns", pip_package="dnspython",
         manual_url="https://pypi.org/project/dnspython/", optional=True,
         note="Python package: install into Watchtower's venv with  pip install dnspython"),
    Tool("weasyprint", "WeasyPrint", "Optional PDF export of reports (HTML export works without it).",
         (OS.LINUX, OS.WINDOWS, OS.MACOS), ("weasyprint",), ("--version",), python_module="weasyprint",
         apt_package="weasyprint", optional=True),
]


def _extra_dirs() -> list[Path]:
    """Places tools live that are often missing from a normal user's PATH.
    Debian keeps /usr/sbin out of non-root PATH, and that is exactly where iw,
    airodump-ng and setcap install. On Windows, a fresh Nmap install isn't on
    the PATH of an already-running app until it restarts."""
    if is_windows():
        dirs = [Path(sys.executable).parent]
        for var in ("ProgramFiles(x86)", "ProgramFiles"):
            if os.environ.get(var):
                dirs.append(Path(os.environ[var]) / "Nmap")
        if os.environ.get("LOCALAPPDATA"):
            dirs.append(Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "WinGet" / "Links")
        return dirs
    # Watchtower's own venv (pip-installed tools like sslyze) is often not on PATH either.
    return [Path(sys.executable).parent] + [Path(d) for d in ("/usr/local/sbin", "/usr/sbin", "/sbin",
                                                              "/usr/local/bin", "/snap/bin")]


def find_binary(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for d in _extra_dirs():
        for name in names:
            for candidate in (d / name, d / f"{name}.exe"):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
    return None


def has_file_capabilities(path: str) -> bool:
    """Linux: True if setcap has granted the binary file capabilities."""
    if not is_linux():
        return False
    try:
        os.getxattr(os.path.realpath(path), "security.capability")
        return True
    except (OSError, AttributeError):
        return False


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
        return f"pip install {tool.pip_package or tool.python_module}   (inside Watchtower's venv)"
    if tool.manual_url:
        return f"Download: {tool.manual_url}"
    return "See INSTALL.md"


def check_tool(tool: Tool, runner: CommandRunner | None = None) -> ToolStatus:
    hint = install_hint(tool)
    if tool.key == "npcap":
        ok = _npcap_installed()
        return ToolStatus(tool, ok, detail="driver found" if ok else "", install_hint=hint)

    path = find_binary(*tool.binaries) if tool.binaries else None
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
            version = pkg_version(tool.pip_package or tool.python_module)
        except Exception:
            pass
        return ToolStatus(tool, True, path=f"python module '{tool.python_module}'", version=version,
                          install_hint=hint)

    return ToolStatus(tool, False, install_hint=hint)


def parse_apt_policy(text: str) -> dict[str, bool]:
    """`apt-cache policy a b c` -> {pkg: has an installation candidate}. Packages
    apt has never heard of are simply absent from the output."""
    out: dict[str, bool] = {}
    pkg = None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            pkg = line.rstrip()[:-1]
            out[pkg] = False
        elif pkg and line.strip().startswith("Candidate:"):
            out[pkg] = line.split(":", 1)[1].strip() not in ("(none)", "")
    return out


def apt_availability(packages: list[str], runner: CommandRunner) -> dict[str, bool]:
    """Which packages this machine's apt sources can install (no root needed)."""
    apt_cache = find_binary("apt-cache")
    pkgs = sorted({p for p in packages if _PKG_RE.match(p)})
    if not apt_cache or not pkgs:
        return {}
    try:
        res = runner.run([apt_cache, "policy", *pkgs], purpose="dependency check: which packages are available",
                         timeout=60)
    except CommandUnavailable:
        return {}
    found = parse_apt_policy(res.stdout)
    return {p: found.get(p, False) for p in pkgs}


def check_all(runner: CommandRunner | None = None) -> list[ToolStatus]:
    statuses = [check_tool(t, runner) for t in tools_for_platform()]
    if runner is not None and is_linux():
        missing = [s for s in statuses if not s.present and s.tool.apt_package]
        avail = apt_availability([s.tool.apt_package for s in missing], runner)
        for s in missing:
            if s.tool.apt_package in avail:
                s.installable = avail[s.tool.apt_package]
                if not s.installable:
                    s.install_hint = (f"not available for this OS release (apt has no '{s.tool.apt_package}')"
                                      + (f"; {s.tool.manual_url}" if s.tool.manual_url else ""))
    return statuses


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

    def path(self, key: str) -> str | None:
        """Absolute path of the tool's binary (use this in argv, not the bare name)."""
        s = self.statuses.get(key)
        if s and s.present and s.path and not s.path.startswith("python module"):
            return s.path
        return None

    def reason(self, key: str) -> str:
        s = self.statuses.get(key)
        if s is None:
            return f"requires {key}, which is not supported on this platform"
        if s.present:
            return ""
        return f"requires {s.tool.name}, not installed ({s.install_hint})"


# ---- install / privilege plans (always shown to the user and confirmed) ----


@dataclass
class Step:
    label: str
    argv: list[str]
    elevated: bool = False   # needs root (wrapped with pkexec, or run in a terminal with sudo)
    script: str | None = None  # for elevated shell scripts: the script text, for display / terminal fallback


@dataclass
class Plan:
    steps: list[Step]
    manual: list[str]  # things the user must install by hand (no package-manager route)

    def describe(self) -> str:
        out = []
        for st in self.steps:
            out.append(f"# {st.label}")
            if st.script:
                out.append(("sudo " if st.elevated else "") + f"sh -c {_shquote(st.script)}")
            else:
                out.append(("sudo " if st.elevated and not is_windows() else "") + format_command(st.argv))
        return "\n".join(out)


def _shquote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def apt_script(packages: list[str]) -> str:
    """One root shell script: refresh package lists, then install each package
    separately so one unavailable package doesn't abort the rest."""
    pkgs = sorted({p for p in packages if _PKG_RE.match(p)})
    return (
        'export DEBIAN_FRONTEND=noninteractive; apt-get update; failed=""; '
        f"for p in {' '.join(pkgs)}; do "
        'echo; echo "==> installing $p"; apt-get install -y "$p" || failed="$failed $p"; done; '
        'if [ -n "$failed" ]; then echo; echo "FAILED:$failed"; exit 1; fi; echo; echo "All packages installed."'
    )


def install_plan(missing: list[ToolStatus], python: str | None = None) -> Plan:
    python = python or sys.executable
    steps: list[Step] = []
    manual: list[str] = []
    pip_mods = [s.tool.pip_package or s.tool.python_module for s in missing
                if s.tool.python_module and not (is_linux() and s.tool.apt_package)]
    if is_linux():
        for s in missing:
            if s.tool.apt_package and s.installable is False:
                manual.append(f"{s.tool.name}: skipped, {s.install_hint}")
        pkgs = [s.tool.apt_package for s in missing if s.tool.apt_package and s.installable is not False]
        if pkgs:
            script = apt_script(pkgs)
            steps.append(Step("Install system packages with apt", ["/bin/sh", "-c", script], True, script))
        manual += [f"{s.tool.name}: {s.install_hint}" for s in missing
                   if not s.tool.apt_package and not s.tool.python_module]
    elif is_windows():
        for s in missing:
            if s.tool.winget_id:
                argv = ["winget", "install", "--exact", "--id", s.tool.winget_id, "--source", "winget",
                        "--accept-source-agreements", "--accept-package-agreements"]
                if s.tool.winget_interactive:
                    argv.append("--interactive")
                steps.append(Step(f"Install {s.tool.name}", argv))
            elif not s.tool.python_module:
                manual.append(f"{s.tool.name}: {s.install_hint}")
    if pip_mods:
        steps.append(Step("Install Python packages into Watchtower's environment",
                          [python, "-m", "pip", "install", *pip_mods]))
    return Plan(steps, manual)


def setcap_plan(statuses: list[ToolStatus]) -> Plan:
    """Linux only: grant raw-socket capabilities to specific binaries instead of
    running the whole GUI as root."""
    paths = []
    for s in statuses:
        if s.present and s.tool.needs_raw_sockets and s.path and not s.path.startswith("python"):
            paths.append(os.path.realpath(s.path))
    if not paths:
        return Plan([], [])
    setcap = find_binary("setcap") or "/usr/sbin/setcap"
    script = "; ".join(f"{setcap} cap_net_raw,cap_net_admin+eip {_shquote(p)}" for p in paths)
    return Plan([Step("Grant raw-socket capabilities", ["/bin/sh", "-c", script], True, script)], [])


def elevate(argv: list[str]) -> list[str] | None:
    """Wrap argv to run as root via the graphical password prompt (pkexec).
    Already root: unchanged. No pkexec: None (caller falls back to a terminal)."""
    if is_elevated():
        return argv
    pk = find_binary("pkexec")
    if is_linux() and pk:
        return [pk, *argv]
    return None


# pkexec exit codes meaning "couldn't authenticate" (no polkit agent, dialog dismissed)
PKEXEC_AUTH_FAILED = (126, 127)


_TERMINALS = [
    ("x-terminal-emulator", lambda c: ["-e", "bash", "-c", c]),
    ("gnome-terminal", lambda c: ["--", "bash", "-c", c]),
    ("konsole", lambda c: ["-e", "bash", "-c", c]),
    ("xfce4-terminal", lambda c: ["-x", "bash", "-c", c]),
    ("qterminal", lambda c: ["-e", f"bash -c {_shquote(c)}"]),
    ("mate-terminal", lambda c: ["-x", "bash", "-c", c]),
    ("tilix", lambda c: ["-e", f"bash -c {_shquote(c)}"]),
    ("kitty", lambda c: ["bash", "-c", c]),
    ("alacritty", lambda c: ["-e", "bash", "-c", c]),
    ("xterm", lambda c: ["-e", "bash", "-c", c]),
]


def terminal_argv(root_script: str) -> list[str] | None:
    """Open a terminal window that runs the script with sudo, so the user types
    their password there. Used when no graphical password prompt is available."""
    cmd = (f"sudo sh -c {_shquote(root_script)}; echo; "
           "read -r -p 'Finished. Press Enter to close, then click Re-check in Watchtower. ' _")
    for name, build in _TERMINALS:
        path = find_binary(name)
        if path:
            return [path, *build(cmd)]
    return None
