import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from watchtower.core.platform_utils import platform_info

FX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def ctx(db, qapp):
    from watchtower.gui.context import AppContext
    return AppContext.create(db, platform_info())


def wait_for(cond, timeout=60.0):
    end = time.time() + timeout
    while time.time() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_main_window_builds_without_startup_gate(ctx):
    from watchtower.gui.main_window import MainWindow
    win = MainWindow(ctx)
    labels = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    assert labels == ["Interfaces", "Nearby Networks", "Scan a Target", "Findings", "Host Audit",
                      "What Changed", "Audit Log", "Help", "Settings"]
    assert not hasattr(ctx, "authorized")
    ctx.runner.run([sys.executable, "-c", "pass"], purpose="smoke")
    QApplication.processEvents()
    assert "-c pass" in win.console.toPlainText()
    assert win.audit_tab.table.rowCount() >= 2


def test_windows_grays_out_nearby(ctx):
    import dataclasses

    from watchtower.gui.main_window import MainWindow
    ctx.platform = dataclasses.replace(ctx.platform, wifi_radio_supported=False)
    win = MainWindow(ctx)
    idx = [win.tabs.tabText(i) for i in range(win.tabs.count())].index("Nearby Networks")
    assert not win.tabs.isTabEnabled(idx)
    assert "monitor mode" in win.tabs.tabToolTip(idx)
    assert not win.interfaces_tab.refresh_btn.isEnabled()


def test_run_plan_dialog_streams_output(ctx):
    from watchtower.core import deps
    from watchtower.gui.run_dialog import RunPlanDialog
    plan = deps.Plan([deps.Step("say hi", [sys.executable, "-c", "print('hello from step')"])], [])
    dlg = RunPlanDialog(ctx, "Test", "intro", plan)
    results = []
    dlg.finished_ok.connect(results.append)
    dlg.run_btn.click()
    assert wait_for(lambda: results)
    assert results == [True] and "hello from step" in dlg.text.toPlainText()
    assert any(e.event == "user_confirmation" for e in ctx.audit.entries())


def test_nearby_authorized_checkbox_persists(ctx):
    from watchtower.core import wifi_scan
    from watchtower.gui.tabs.nearby_tab import NearbyTab
    ctx.networks.record(wifi_scan.parse_nmcli((FX / "nmcli.txt").read_text()), source="nmcli")
    tab = NearbyTab(ctx)
    assert tab.table.rowCount() == 5
    row = next(r for r in range(5) if tab.table.item(r, 2).text() == "AA:BB:CC:00:00:03")
    tab.table.item(row, 0).setCheckState(Qt.CheckState.Checked)
    assert ctx.networks.is_authorized("AA:BB:CC:00:00:03")
    assert ctx.audit.entries()[0].event == "scope_change"


def test_scan_tab_blocks_out_of_scope(ctx):
    from watchtower.gui.tabs.scan_tab import ScanTab
    tab = ScanTab(ctx)
    tab.target.setText("10.1.2.3")
    assert not tab.run_btn.isEnabled() and "not covered" in tab.preview.text()
    ctx.targets.add("10.1.2.0/24")
    ctx.bus.targets_changed.emit()
    if shutil.which("nmap"):
        assert tab.run_btn.isEnabled() and "10.1.2.3" in tab.preview.text()
    tab.extra.setText("-iL list.txt")
    assert not tab.run_btn.isEnabled() and "-iL is not allowed" in tab.preview.text()


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_scan_tab_end_to_end(ctx):
    from watchtower.core import deps
    from watchtower.gui.tabs.scan_tab import ScanTab
    ctx.deps.update(deps.check_all())
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.8)
        ctx.targets.add("127.0.0.1")
        tab = ScanTab(ctx)
        tab.target.setText("127.0.0.1")
        tab.profile.setCurrentText("Custom (only my options)")
        tab.extra.setText(f"-sT -sV -p {port} -Pn")
        assert tab.run_btn.isEnabled(), tab.preview.text()
        tab.run_scan()
        assert wait_for(lambda: tab.cancel_event is None and tab.tree.topLevelItemCount() > 0, 120)
        host = tab.tree.topLevelItem(0)
        assert host.text(0).startswith("127.0.0.1")
        assert host.child(0).text(0) == f"{port}/tcp" and host.child(0).text(1) == "open"
        assert "http" in host.child(0).text(2)
        assert tab.history.count() == 1
        scan = ctx.scans.recent()[0]
        assert scan["exit_code"] == 0 and "<nmaprun" in ctx.scans.get(scan["id"])["raw_output"]
    finally:
        srv.terminate()
