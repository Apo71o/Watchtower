import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from watchtower.core import remediation as rm
from watchtower.core.findings_engine import Finding, host_findings
from watchtower.core.nmap_runner import Host, Port, parse_xml

FX = Path(__file__).parent / "fixtures"


def lab_findings():
    return host_findings(parse_xml((FX / "nmap_lab.xml").read_text()).hosts[0])


def test_is_local():
    assert rm.is_local("127.0.0.1", [])
    assert rm.is_local("192.168.1.23", ["192.168.1.23/24"])
    assert not rm.is_local("192.168.1.24", ["192.168.1.23/24"])
    assert not rm.is_local("nas.lan", [])


def test_local_upgrade_fix_for_cve():
    f = next(x for x in lab_findings() if x.cve_id == "CVE-2024-6387")
    acts = {a.kind: a for a in rm.fixes_for(f, local=True)}
    assert set(acts) == {"local", "rescan"}
    step = acts["local"].plan.steps[0]
    assert step.elevated and "apt-get install --only-upgrade -y openssh-server" in step.script
    assert "apt-get update" in step.script


def test_remote_fix_offers_ssh_and_copy(monkeypatch):
    monkeypatch.setattr(rm.deps, "find_binary", lambda *n: "/usr/bin/" + n[0])
    f = next(x for x in lab_findings() if x.title == "Telnet enabled")
    acts = {a.kind: a for a in rm.fixes_for(f, local=False)}
    assert {"ssh", "copy", "rescan"} <= set(acts) and "local" not in acts
    cmds = acts["copy"].commands
    assert len(cmds) == 1 and "sport = :23" in cmds[0] and "sudo systemctl disable --now" in cmds[0]


def test_patched_finding_needs_no_fix():
    h = Host("10.0.0.9", "up", ports=[Port("tcp", 22, "open", service="ssh", product="OpenSSH",
                                           version="8.9p1 Ubuntu 3ubuntu0.13")])
    f = next(x for x in host_findings(h) if x.cve_id == "CVE-2024-6387")
    assert [a.kind for a in rm.fixes_for(f, local=True)] == ["rescan"]


def test_wifi_and_default_creds_open_admin_page():
    wifi = Finding("AA:BB:CC:00:00:01", "Home", "wifi", "WPS enabled", "High", "", "")
    acts = rm.fixes_for(wifi, local=False, gateway="192.168.1.1")
    assert [a.kind for a in acts] == ["open_url"] and acts[0].url == "http://192.168.1.1/"
    assert rm.fixes_for(wifi, local=False, gateway=None) == []
    creds = Finding("10.0.0.7", "cam", "default_creds", "Hikvision: ships with default credentials", "Medium", "",
                    "", port="443/tcp", service="443/tcp https")
    acts = rm.fixes_for(creds, local=False)
    assert acts[0].kind == "open_url" and acts[0].url == "https://10.0.0.7/"


def test_gateway_parse():
    assert rm.gateway_from_ip_route("default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n") == "192.168.1.1"
    assert rm.gateway_from_ip_route("") is None


def test_ssh_terminal_argv_validates_user(monkeypatch):
    monkeypatch.setattr(rm.deps, "find_binary", lambda *n: "/usr/bin/" + n[0] if n[0] in ("ssh", "xterm") else None)
    argv = rm.ssh_terminal_argv("admin", "10.0.0.9", ["sudo apt-get update"])
    assert argv[0] == "/usr/bin/xterm" and "admin@10.0.0.9" in argv[-1] and "-t" in argv[-1]
    with pytest.raises(ValueError):
        rm.ssh_terminal_argv("bad user;rm", "10.0.0.9", ["x"])


@pytest.mark.parametrize("unit,protected", [("systemd-resolved.service", True), ("init.scope", True),
                                           ("-", True), ("NetworkManager.service", True),
                                           ("user@1000.service", True), ("inetutils-inetd.service", False),
                                           ("snmpd.service", False)])
def test_protected_units(unit, protected):
    r = subprocess.run(["grep", "-Eq", rm.PROTECTED_UNIT_RE], input=unit, text=True)
    assert (r.returncode == 0) == protected


@pytest.mark.skipif(not (shutil.which("ss") and sys.platform.startswith("linux")), reason="needs ss (Linux)")
def test_disable_script_refuses_non_service_process():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.8)
        r = subprocess.run(["/bin/sh", "-c", rm.disable_port_script(port, "tcp")], capture_output=True, text=True)
        assert f"Port {port}/tcp is served by process {srv.pid}" in r.stdout
        assert "Not a stoppable system service" in r.stdout and r.returncode == 1
        assert srv.poll() is None            # the process was left alone
    finally:
        srv.terminate()
    r = subprocess.run(["/bin/sh", "-c", rm.disable_port_script(port, "tcp")], capture_output=True, text=True)
    assert "Nothing is listening" in r.stdout and r.returncode == 0


def test_upgrade_script_succeeds_when_package_absent():
    f = next(x for x in lab_findings() if x.cve_id == "CVE-2024-6387")
    script = next(a for a in rm.fixes_for(f, local=True) if a.kind == "local").plan.steps[0].script
    tail = script.split("echo 'Done.", 1)[1]
    r = subprocess.run(["/bin/sh", "-c", "echo 'Done." + tail.replace("openssh-server", "no-such-pkg-xyz")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "not installed on this machine" in r.stdout
