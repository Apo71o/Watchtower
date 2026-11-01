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


def test_apt_plan_dedups_and_sorts():
    missing = [deps.ToolStatus(t, False) for t in deps.TOOLS if t.apt_package]
    argv = deps.apt_install_argv(missing)
    assert argv[:3] == ["apt-get", "install", "-y"]
    assert argv[3:] == sorted(set(argv[3:]))


def test_dependency_state_reason():
    nmap = next(t for t in deps.TOOLS if t.key == "nmap")
    st = deps.DependencyState([deps.ToolStatus(nmap, False, install_hint="sudo apt install nmap")])
    assert not st.available("nmap")
    assert "requires Nmap, not installed" in st.reason("nmap")


def test_windows_tool_list_excludes_radio_tools():
    keys = {t.key for t in deps.tools_for_platform(OS.WINDOWS)}
    assert "nmap" in keys and "npcap" in keys
    assert not keys & {"iw", "airodump-ng", "iwlist"}
