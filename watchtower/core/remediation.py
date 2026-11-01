"""One-click fixes for findings (remediation only, never exploitation).

For each finding this works out what can actually be automated:
  * on THIS machine: a deps.Plan run as root after confirmation (security
    updates for the affected package, or stopping the service on a risky port)
  * on another Linux host: the same shell commands, to run there over the
    user's own SSH login (in a terminal, so they type their sudo password)
  * on appliances (routers, cameras): open the admin page; steps are in the text
Every action is shown in full before it runs.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field

from watchtower.core import deps
from watchtower.core.findings_engine import Finding

# nmap product -> (Debian/Ubuntu packages to upgrade, systemd unit)
PACKAGES: list[tuple[str, list[str], str]] = [
    (r"^OpenSSH$", ["openssh-server"], "ssh"),
    (r"^Apache httpd$", ["apache2"], "apache2"),
    (r"^nginx$", ["nginx"], "nginx"),
    (r"^vsftpd$", ["vsftpd"], "vsftpd"),
    (r"^ProFTPD$", ["proftpd-core", "proftpd-basic"], "proftpd"),
    (r"^Exim smtpd$", ["exim4-daemon-light", "exim4-daemon-heavy"], "exim4"),
    (r"^dnsmasq$", ["dnsmasq", "dnsmasq-base"], "dnsmasq"),
    (r"^Samba smbd$", ["samba"], "smbd"),
    (r"^Dropbear sshd$", ["dropbear-bin", "dropbear"], "dropbear"),
    (r"^MySQL$", ["mysql-server"], "mysql"),
    (r"^(PostgreSQL|postgresql)", ["postgresql"], "postgresql"),
    (r"^Redis", ["redis-server"], "redis-server"),
    (r"^Memcached", ["memcached"], "memcached"),
    (r"^net-snmp|SNMPv", ["snmpd"], "snmpd"),
]

# Units we refuse to stop automatically (stopping them breaks the machine or the session).
PROTECTED_UNIT_RE = r"^(init\.scope|systemd-.*|dbus.*|NetworkManager.*|user@.*|session-.*|-|)$"

# Exposure findings where "stop the service on that port" is the fix.
DISABLE_TITLES = ("Telnet enabled", "r-services", "Plain FTP", "Redis exposed", "MongoDB exposed",
                  "Memcached exposed", "UPnP exposed", "SNMP service reachable", "SNMP readable",
                  "VNC exposed", "Elasticsearch")


@dataclass
class FixAction:
    kind: str              # "local" | "ssh" | "copy" | "open_url" | "rescan"
    label: str             # button text
    description: str       # what it does / what might break
    plan: deps.Plan | None = None        # local: run via RunPlanDialog
    commands: list[str] = field(default_factory=list)   # ssh/copy: shell commands for the target host
    url: str = ""
    undo: str = ""


def is_local(device: str, local_addresses: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(device)
    except ValueError:
        return device in ("localhost",)
    if ip.is_loopback:
        return True
    return any(str(ipaddress.ip_interface(a).ip) == device for a in local_addresses)


def packages_for(product: str) -> tuple[list[str], str] | None:
    for pat, pkgs, unit in PACKAGES:
        if product and re.search(pat, product, re.IGNORECASE):
            return pkgs, unit
    return None


def _port(f: Finding) -> tuple[int, str] | None:
    m = re.match(r"^(\d+)/(tcp|udp)$", f.port or "")
    return (int(m.group(1)), m.group(2)) if m else None


def upgrade_commands(pkgs: list[str], sudo: bool) -> list[str]:
    s = "sudo " if sudo else ""
    return [f"{s}apt-get update", f"{s}apt-get install --only-upgrade -y {' '.join(pkgs)}"]


def disable_port_script(port: int, proto: str, sudo: bool = False) -> str:
    """Find which systemd unit listens on port/proto, refuse protected units, then disable it.
    Prints the unit so the user sees exactly what was stopped (and how to undo it)."""
    s = "sudo " if sudo else ""
    flag = "t" if proto == "tcp" else "u"
    return (f"pid=$({s}ss -H{flag}lnp 'sport = :{port}' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2); "
            f'if [ -z "$pid" ]; then echo "Nothing is listening on {port}/{proto} any more."; exit 0; fi; '
            'unit=$(ps -o unit= -p "$pid" | tr -d " "); '
            f'echo "Port {port}/{proto} is served by process $pid, systemd unit: ${{unit:-none}}"; '
            f"if echo \"$unit\" | grep -Eq '{PROTECTED_UNIT_RE}'; then "
            'echo "Not a stoppable system service (or a protected one). Stop it manually."; exit 1; fi; '
            f'{s}systemctl disable --now "$unit" && echo && echo "Stopped and disabled $unit. '
            f'Undo with: {s}systemctl enable --now $unit"')


def fixes_for(f: Finding, local: bool, ssh_available: bool = True, gateway: str | None = None) -> list[FixAction]:
    actions: list[FixAction] = []
    host = f.device
    if f.patched:
        return [FixAction("rescan", "Re-scan to verify", "Already fixed by a distribution update.")]
    if f.kind in ("web", "email", "subdomain", "traffic"):
        # Web server config / DNS records / client settings seen in traffic: 'How to fix it' has the exact
        # settings; re-run the audit (or capture again) to verify. No one-click action applies.
        return []

    pkg = packages_for(f.product) if f.kind in ("service", "nse", "exposure", "snmp", "tls") else None
    want_update = pkg and (f.cve_id or f.kind in ("service", "nse", "tls"))
    port = _port(f)
    want_disable = port and any(f.title.startswith(t) for t in DISABLE_TITLES)

    remote_cmds: list[str] = []
    if want_update:
        pkgs, unit = pkg
        if local:
            script = ("export DEBIAN_FRONTEND=noninteractive; apt-get update && "
                      f"apt-get install --only-upgrade -y {' '.join(pkgs)} && echo && "
                      f"echo 'Done. Installed version now:' && "
                      f"(dpkg -l {' '.join(pkgs)} 2>/dev/null | grep ^ii || echo '(not installed on this machine)')")
            actions.append(FixAction(
                "local", f"Install security updates for {pkgs[0]}",
                f"Upgrades {', '.join(pkgs)} to the newest version in your configured apt sources (packages that "
                f"aren't installed are skipped). The package's own scripts normally restart {unit}; existing "
                "connections may drop.",
                plan=deps.Plan([deps.Step(f"Upgrade {', '.join(pkgs)}", ["/bin/sh", "-c", script], True, script)], [])))
        remote_cmds += upgrade_commands(pkgs, sudo=True)
    if want_disable:
        p, proto = port
        if local:
            script = disable_port_script(p, proto)
            actions.append(FixAction(
                "local", f"Stop the service on {p}/{proto}",
                f"Finds the systemd service listening on {p}/{proto}, then stops and disables it (it won't start "
                "at boot). Anything that relies on it stops working. The output shows the undo command.",
                plan=deps.Plan([deps.Step(f"Disable the service on {p}/{proto}", ["/bin/sh", "-c", script], True,
                                          script)], [])))
        remote_cmds.append(disable_port_script(p, proto, sudo=True))

    if remote_cmds and not local:
        if ssh_available and deps.find_binary("ssh"):
            actions.append(FixAction(
                "ssh", "Run fix on host via SSH…",
                f"Opens a terminal that connects to {host} with your SSH login and runs the commands below with "
                "sudo (you type your password there). Only for Linux hosts you administer.",
                commands=remote_cmds))
        actions.append(FixAction("copy", "Copy fix commands",
                                 f"Copies the commands to run on {host} (Debian/Ubuntu).", commands=remote_cmds))
    if f.kind in ("wifi", "default_creds") or (not remote_cmds and f.kind in ("exposure", "tls", "snmp")):
        url = admin_url(f, gateway)
        if url:
            actions.append(FixAction("open_url", "Open admin page",
                                     f"Opens {url} in your browser so you can change the setting described in "
                                     "'How to fix it'.", url=url))
    if f.kind != "wifi":
        actions.append(FixAction("rescan", "Re-scan to verify",
                                 f"Opens Scan a Target for {host} so you can confirm the fix."))
    return actions


def admin_url(f: Finding, gateway: str | None = None) -> str:
    if f.kind == "wifi":
        return f"http://{gateway}/" if gateway else ""
    try:
        ip = ipaddress.ip_address(f.device)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        host = f.device
    p = _port(f)
    if p and p[1] == "tcp" and p[0] in (80, 8080, 8000):
        return f"http://{host}:{p[0]}/" if p[0] != 80 else f"http://{host}/"
    if p and p[1] == "tcp" and (p[0] in (443, 8443) or "https" in f.service or "TLS" in f.service):
        return f"https://{host}:{p[0]}/" if p[0] != 443 else f"https://{host}/"
    return f"http://{host}/"


def ssh_terminal_argv(user: str, host: str, commands: list[str]) -> list[str] | None:
    """A terminal window running the commands on `host` over SSH (-t so sudo can prompt)."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user):
        raise ValueError(f"invalid user name: {user!r}")
    ssh = deps.find_binary("ssh") or "ssh"
    remote = " && ".join(f"( {c} )" for c in commands)
    target = f"{user}@{host}"
    cmd = (f"{shlex.quote(ssh)} -t {shlex.quote(target)} {shlex.quote(remote)}; echo; "
           "read -r -p 'Finished. Press Enter to close, then re-scan in Watchtower. ' _")
    for name, build in deps._TERMINALS:
        path = deps.find_binary(name)
        if path:
            return [path, *build(cmd)]
    return None


def gateway_from_ip_route(text: str) -> str | None:
    m = re.search(r"^default via (\S+)", text or "", re.MULTILINE)
    return m.group(1) if m else None
