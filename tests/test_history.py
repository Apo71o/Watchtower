import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from watchtower.core import history_diff as hd
from watchtower.core import scheduler
from watchtower.core.nmap_runner import Host, Port, parse_xml

FX = Path(__file__).parent / "fixtures"


def host(ports, mac="", addr="10.0.0.5"):
    return Host(addr, "up", mac=mac, ports=[Port("tcp", n, "open", service=s, product=p, version=v)
                                           for n, s, p, v in ports])


def titles(changes):
    return {(c.level, c.title) for c in changes}


def test_port_opened_closed_and_versions():
    old = host([(22, "ssh", "OpenSSH", "8.9p1"), (80, "http", "nginx", "1.24.0"), (21, "ftp", "vsftpd", "3.0.5")])
    new = host([(22, "ssh", "OpenSSH", "9.6p1"), (80, "http", "nginx", "1.22.0"), (23, "telnet", "", "")])
    t = titles(hd.diff_hosts(old, new))
    assert ("alert", "Port opened: 23/tcp") in t
    assert ("good", "Port closed: 21/tcp") in t
    assert ("good", "OpenSSH updated on 22/tcp") in t
    assert ("notice", "nginx version changed on 80/tcp") in t
    assert ("alert", "New finding") in t          # telnet exposure


def test_finding_resolved_and_mac_change():
    old = host([(21, "ftp", "vsftpd", "2.3.4")], mac="AA:AA:AA:AA:AA:AA")
    new = host([(21, "ftp", "vsftpd", "3.0.5")], mac="BB:BB:BB:BB:BB:BB")
    changes = hd.diff_hosts(old, new)
    assert any(c.level == "good" and c.title == "Resolved" and "vsftpd 2.3.4" in c.detail for c in changes)
    assert any(c.title.startswith("Different device") for c in changes)


def test_hosts_appear_and_disappear():
    lab = parse_xml((FX / "nmap_lab.xml").read_text())
    empty = parse_xml("")
    appeared = hd.diff_scans(empty, lab)
    assert appeared[0].level == "alert" or any(c.title.startswith("New host") for c in appeared)
    gone = hd.diff_scans(lab, empty)
    assert [c.title for c in gone] == ["Host no longer responds: 192.168.56.101 (labbox.lan)"]
    assert hd.diff_scans(lab, lab) == []


def obs(bssid, ssid, sec="WPA2", wps=0, ch=6):
    return {"bssid": bssid, "ssid": ssid, "security": sec, "wps": wps, "channel": ch}


def test_wifi_evil_twin_downgrade_and_wps():
    old = {"AA:01": obs("AA:01", "Home"), "AA:02": obs("AA:02", "Cafe", "Open")}
    new = {"AA:01": obs("AA:01", "Home", "Open", wps=1), "AA:09": obs("AA:09", "Home", "Open")}
    t = titles(hd.diff_wifi(old, new, {"Home"}, {"AA:01"}))
    assert ("alert", "New access point using your network name “Home”") in t
    assert ("alert", "Security changed on Home") in t
    assert ("alert", "WPS turned on: Home") in t
    assert ("info", "Network not seen: Cafe") in t
    upgraded = hd.diff_wifi({"AA:01": obs("AA:01", "Home")}, {"AA:01": obs("AA:01", "Home", "WPA3")}, {"Home"},
                            {"AA:01"})
    assert upgraded[0].level == "good"


def test_summary():
    assert hd.summary([]) == "No changes."
    assert hd.summary([hd.Change("alert", "port", "x", "a"), hd.Change("good", "port", "x", "b")]) == "1 alert, 1 good"


def test_schedule_store_due(db):
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import ScheduleStore
    st = ScheduleStore(db, AuditLog(db))
    sid = st.add("10.0.0.0/24", "Quick scan", 1440)
    assert [s["id"] for s in st.due()] == [sid]
    st.mark_run(sid, "ok", "2026-11-01T00:00:00+00:00", "2999-01-01T00:00:00+00:00")
    assert st.due() == []
    st.run_now(sid)
    assert st.due()
    st.set_enabled(sid, False)
    assert st.due() == []


def test_timer_units():
    units = scheduler.timer_units(python="/home/me/.venv/bin/python", home="/tmp/wt home")
    svc = units["watchtower-schedules.service"]
    assert "ExecStart=/home/me/.venv/bin/python -m watchtower --run-scheduled" in svc
    assert "WATCHTOWER_HOME='/tmp/wt home'" in svc
    assert "OnUnitActiveSec=15min" in units["watchtower-schedules.timer"]


def _stores(db):
    from watchtower.storage.audit_log import AuditLog
    from watchtower.storage.scope import ScanStore, ScheduleStore, TargetStore
    audit = AuditLog(db)
    return audit, TargetStore(db, audit), ScanStore(db), ScheduleStore(db, audit)


def test_schedule_skips_unauthorized_and_root(db):
    from watchtower.core.runner import CommandRunner
    audit, targets, scans, schedules = _stores(db)
    sid = schedules.add("10.66.0.1", "Quick scan", 60)
    r = scheduler.run_schedule(schedules.get(sid), CommandRunner(audit), targets, scans, schedules)
    assert r.status.startswith("skipped") and scans.recent() == []
    if shutil.which("nmap") and os.geteuid() != 0:
        targets.add("10.66.0.1")
        sid2 = schedules.add("10.66.0.1", "Intense scan", 60)
        r2 = scheduler.run_schedule(schedules.get(sid2), CommandRunner(audit), targets, scans, schedules)
        assert "need root" in r2.status


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_scheduled_rescan_detects_new_port(db):
    from watchtower.core.runner import CommandRunner
    audit, targets, scans, schedules = _stores(db)
    targets.add("127.0.0.1")
    p1, p2 = _port(), _port()
    sid = schedules.add("127.0.0.1", "Custom (only my options)", 60)
    db.execute("UPDATE schedules SET extra = ? WHERE id = ?", (f"-sT -Pn -p {p1},{p2}", sid))
    s1 = subprocess.Popen([sys.executable, "-m", "http.server", str(p1), "--bind", "127.0.0.1"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    s2 = None
    try:
        time.sleep(0.8)
        first = scheduler.run_schedule(schedules.get(sid), CommandRunner(audit), targets, scans, schedules)
        assert first.status == "ok: first scan (baseline)"
        s2 = subprocess.Popen([sys.executable, "-m", "http.server", str(p2), "--bind", "127.0.0.1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)
        schedules.run_now(sid)
        second = scheduler.run_due(CommandRunner(audit), targets, scans, schedules)[0]
        assert second.status.startswith("ok:")
        assert any(c.title == f"Port opened: {p2}/tcp" for c in second.alerts)
        assert schedules.get(sid)["next_run"] > schedules.get(sid)["last_run"]
        assert scans.recent()[0]["exit_code"] == 0
    finally:
        s1.terminate()
        if s2:
            s2.terminate()


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_headless_run_scheduled_cli(tmp_path):
    env = {**os.environ, "WATCHTOWER_HOME": str(tmp_path), "QT_QPA_PLATFORM": "offscreen"}
    setup = ("from watchtower.storage.db import Database\nfrom watchtower.storage.audit_log import AuditLog\n"
             "from watchtower.storage.scope import TargetStore, ScheduleStore\n"
             "db=Database(); a=AuditLog(db); TargetStore(db,a).add('127.0.0.1')\n"
             "sid=ScheduleStore(db,a).add('127.0.0.1','Custom (only my options)',60)\n"
             "db.execute('UPDATE schedules SET extra=? WHERE id=?', ('-sT -Pn -p 1', sid))\n")
    subprocess.run([sys.executable, "-c", setup], env=env, check=True)
    r = subprocess.run([sys.executable, "-m", "watchtower", "--run-scheduled"], env=env, capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0 and "#1 127.0.0.1: ok: first scan (baseline)" in r.stdout, r.stdout + r.stderr
