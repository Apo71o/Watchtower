import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from watchtower.core.platform_utils import platform_info  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def ctx(db, qapp):
    from watchtower.gui.context import AppContext
    return AppContext.create(db, platform_info())


def test_auth_gate_records_ack(ctx):
    from watchtower.gui.auth_gate import AuthGateDialog, revoke_acknowledgment
    dlg = AuthGateDialog(ctx)
    assert not dlg.accept_btn.isEnabled()
    dlg.check.setChecked(True)
    assert dlg.accept_btn.isEnabled()
    dlg.accept_btn.click()
    assert ctx.authorized
    assert ctx.audit.entries()[0].event == "authorization_ack"
    revoke_acknowledgment(ctx)
    assert not ctx.authorized


def test_main_window_builds(ctx):
    from watchtower.gui.main_window import MainWindow
    win = MainWindow(ctx)
    labels = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    assert labels == ["Interfaces", "Nearby Networks", "Scan a Target", "Findings", "Host Audit",
                      "What Changed", "Audit Log", "Help", "Settings"]
    assert "LOCKED" in win.lock_lbl.text()
    ctx.runner.run(["python3", "-c", "pass"], purpose="smoke")
    QApplication.processEvents()
    assert "python3 -c pass" in win.console.toPlainText()
    assert win.audit_tab.table.rowCount() >= 2


def test_windows_grays_out_nearby(ctx, monkeypatch):
    import dataclasses

    from watchtower.gui.main_window import MainWindow
    ctx.platform = dataclasses.replace(ctx.platform, wifi_radio_supported=False)
    win = MainWindow(ctx)
    idx = [win.tabs.tabText(i) for i in range(win.tabs.count())].index("Nearby Networks")
    assert not win.tabs.isTabEnabled(idx)
    assert "monitor mode" in win.tabs.tabToolTip(idx)
