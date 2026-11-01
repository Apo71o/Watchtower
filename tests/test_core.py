import shlex
import sqlite3
import sys

import pytest

from watchtower.core import deps
from watchtower.core.platform_utils import (
    OS,
    PlatformUnsupported,
    current_os,
    data_dir,
    platform_info,
    require_linux,
)
from watchtower.core.runner import CommandRunner, CommandUnavailable
from watchtower.storage.audit_log import AuditLog, Event
from watchtower.storage.db import MIGRATIONS, Database
from watchtower.storage.settings import Settings


def test_platform_detection():
    info = platform_info()
    assert info.os is current_os()
    assert info.wifi_radio_supported == (info.os is OS.LINUX)


def test_require_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert current_os() is OS.WINDOWS
    with pytest.raises(PlatformUnsupported, match="only available on Linux"):
        require_linux("Passive Wi-Fi scan")


def test_data_dir_override(home):
    assert data_dir() == home


def test_migrations_idempotent(home):
    Database().close()
    d = Database()
    assert d.schema_version == len(MIGRATIONS)


def test_settings_roundtrip(db):
    s = Settings(db)
    assert s.get("x", 5) == 5
    s.set("x", {"a": [1, 2]})
    assert s.get("x") == {"a": [1, 2]}
    s.delete("x")
    assert s.get("x") is None


def test_audit_log_is_append_only(db):
    log = AuditLog(db)
    i = log.append(Event.CONFIRMATION, detail={"k": "v"})
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_log SET event='x' WHERE id=?", (i,))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit_log")
    assert log.entries()[0].detail == '{"k": "v"}'


def test_audit_export(db):
    log = AuditLog(db)
    log.append(Event.APP_START)
    log.append(Event.COMMAND_START, command="nmap -sV 10.0.0.1", target="10.0.0.1")
    assert "nmap -sV 10.0.0.1" in log.export_csv()
    assert '"target": "10.0.0.1"' in log.export_json()


def test_runner_logs_exact_command(db):
    log = AuditLog(db)
    runner = CommandRunner(log)
    shown = []
    runner.on_command(lambda c, p: shown.append(c))
    res = runner.run([sys.executable, "-c", "print('hi there')"], purpose="test", target="t")
    assert res.ok and "hi there" in res.stdout
    end, start = log.entries()[:2]
    assert start.event == "command_start" and end.event == "command_end"
    assert end.ref_id == start.id and end.exit_code == 0
    assert start.command == shown[0]
    assert shlex.split(start.command)[-1] == "print('hi there')"


def test_runner_missing_binary_is_readable(db):
    runner = CommandRunner(AuditLog(db))
    with pytest.raises(CommandUnavailable, match="not installed"):
        runner.run(["definitely-not-a-real-tool-xyz"], purpose="test")
    assert AuditLog(db).entries()[0].event == "command_error"


def test_install_hints():
    nmap = next(t for t in deps.TOOLS if t.key == "nmap")
    assert deps.install_hint(nmap, OS.LINUX) == "sudo apt install nmap"
    assert deps.install_hint(nmap, OS.WINDOWS) == "winget install Insecure.Nmap"


def test_install_plan_linux(monkeypatch):
    monkeypatch.setattr(deps, "is_linux", lambda: True)
    monkeypatch.setattr(deps, "is_windows", lambda: False)
    missing = [deps.ToolStatus(t, False) for t in deps.TOOLS if OS.LINUX in t.platforms]
    plan = deps.install_plan(missing, python="/venv/bin/python")
    apt = plan.steps[0]
    assert apt.elevated and apt.argv[:2] == ["/bin/sh", "-c"]
    assert "apt-get update" in apt.script and "apt-get install -y \"$p\"" in apt.script
    assert "aircrack-ng" in apt.script and "nmap" in apt.script
    pip = plan.steps[-1]
    assert pip.argv[:4] == ["/venv/bin/python", "-m", "pip", "install"] and "sslyze" in pip.argv
    assert any("Metasploit" in m for m in plan.manual)


def test_install_plan_windows(monkeypatch):
    monkeypatch.setattr(deps, "is_linux", lambda: False)
    monkeypatch.setattr(deps, "is_windows", lambda: True)
    missing = [deps.ToolStatus(t, False) for t in deps.TOOLS if OS.WINDOWS in t.platforms]
    plan = deps.install_plan(missing)
    nmap = next(s for s in plan.steps if "Insecure.Nmap" in s.argv)
    assert "--accept-source-agreements" in nmap.argv and "--accept-package-agreements" in nmap.argv
    npcap = next(s for s in plan.steps if "Insecure.Npcap" in s.argv)
    assert "--interactive" in npcap.argv


def test_apt_script_rejects_weird_package_names():
    assert "evil" not in deps.apt_script(["nmap", "evil;rm -rf /"])


def test_find_binary_searches_sbin(tmp_path, monkeypatch):
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    tool = sbin / "iwfake"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setattr(deps, "_extra_dirs", lambda: [sbin])
    assert deps.find_binary("iwfake") == str(tool)


def test_runner_stream_and_cancel(db):
    import threading
    runner = CommandRunner(AuditLog(db))
    lines = []
    res = runner.stream([sys.executable, "-c", "print('a'); print('b')"], purpose="t", on_line=lines.append)
    assert res.ok and lines == ["a", "b"]
    cancel = threading.Event()
    cancel.set()
    res = runner.stream([sys.executable, "-c", "import time; time.sleep(30)"], purpose="t", cancel=cancel)
    assert res.exit_code != 0
    assert '"cancelled": true' in AuditLog(db).entries()[0].detail


def test_dependency_state_reason():
    nmap = next(t for t in deps.TOOLS if t.key == "nmap")
    st = deps.DependencyState([deps.ToolStatus(nmap, False, install_hint="sudo apt install nmap")])
    assert not st.available("nmap")
    assert "requires Nmap, not installed" in st.reason("nmap")


def test_windows_tool_list_excludes_radio_tools():
    keys = {t.key for t in deps.tools_for_platform(OS.WINDOWS)}
    assert "nmap" in keys and "npcap" in keys
    assert not keys & {"iw", "airodump-ng", "iwlist"}


APT_POLICY = """nmap:
  Installed: (none)
  Candidate: 7.95+dfsg-1
  Version table:
     7.95+dfsg-1 500
        500 http://archive.ubuntu.com/ubuntu resolute/universe amd64 Packages
wireless-tools:
  Installed: (none)
  Candidate: (none)
  Version table:
"""


def test_parse_apt_policy():
    assert deps.parse_apt_policy(APT_POLICY) == {"nmap": True, "wireless-tools": False}


def test_install_plan_skips_unavailable_packages(monkeypatch):
    monkeypatch.setattr(deps, "is_linux", lambda: True)
    monkeypatch.setattr(deps, "is_windows", lambda: False)
    by_key = {t.key: t for t in deps.TOOLS}
    iwlist = deps.ToolStatus(by_key["iwlist"], False, installable=False, install_hint="not available")
    nmap = deps.ToolStatus(by_key["nmap"], False, installable=True)
    plan = deps.install_plan([iwlist, nmap])
    assert "wireless-tools" not in plan.steps[0].script and "nmap" in plan.steps[0].script
    assert any("iwlist" in m and "skipped" in m for m in plan.manual)
    only_unavailable = deps.install_plan([iwlist])
    assert only_unavailable.steps == []


def test_check_all_marks_unavailable(db, monkeypatch):
    monkeypatch.setattr(deps, "is_linux", lambda: True)
    monkeypatch.setattr(deps, "apt_availability", lambda pkgs, runner: {p: p != "wireless-tools" for p in pkgs})
    monkeypatch.setattr(deps, "find_binary", lambda *n: None)
    statuses = {s.tool.key: s for s in deps.check_all(CommandRunner(AuditLog(db)))}
    assert statuses["iwlist"].installable is False and "not available" in statuses["iwlist"].install_hint
    assert statuses["nmap"].installable is True


def test_terminate_all_stops_running_children(db):
    import threading
    import time
    runner = CommandRunner(AuditLog(db))
    result = {}
    t = threading.Thread(target=lambda: result.setdefault(
        "r", runner.run([sys.executable, "-c", "import time; time.sleep(60)"], purpose="t")))
    t.start()
    for _ in range(100):
        if runner._active:
            break
        time.sleep(0.05)
    assert runner.terminate_all() == 1
    t.join(10)
    assert not t.is_alive() and result["r"].exit_code != 0 and not runner._active
