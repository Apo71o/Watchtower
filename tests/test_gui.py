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
    from watchtower.gui.worker import shutdown
    yield AppContext.create(db, platform_info())
    # Like the real app on exit: finish background jobs, then destroy the widgets this test made
    # (left alive, they'd be torn down after QApplication and crash the interpreter on exit).
    shutdown()
    for w in QApplication.topLevelWidgets():
        w.close()
        w.deleteLater()
    QApplication.sendPostedEvents(None, 0)
    QApplication.processEvents()


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
                      "Web Audit", "Domain Audit", "Traffic Audit", "What Changed", "Password Tools", "Audit Log",
                      "Help", "Settings"]
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


def test_findings_tab(ctx):
    from watchtower.gui.tabs.findings_tab import FindingsTab
    sid = ctx.scans.start("nmap", "192.168.56.101", "nmap -sV --script vuln 192.168.56.101")
    ctx.scans.finish(sid, 0, (FX / "nmap_lab.xml").read_text())
    tab = FindingsTab(ctx)
    assert tab.table.rowCount() > 5 and tab.risks.rowCount() == 1
    assert tab.table.item(0, 0).text() == "Critical"
    tab.table.selectRow(0)
    md = tab.detail.toMarkdown()
    assert "How to fix it" in md
    tab.min_sev.setCurrentIndex(4)   # Critical only
    assert all(tab.table.item(r, 0).text() == "Critical" for r in range(tab.table.rowCount()))
    from watchtower.core import wifi_scan
    ctx.networks.record(wifi_scan.parse_iw_scan((FX / "iw_scan.txt").read_text()), source="iw")
    ctx.networks.set_authorized("AA:BB:CC:00:00:03", True)
    ctx.bus.networks_changed.emit()
    assert tab.risks.rowCount() == 2



def test_findings_details_for_devices_and_unauthorized(ctx):
    from watchtower.core import wifi_scan
    from watchtower.gui.tabs.findings_tab import FindingsTab
    ctx.networks.record(wifi_scan.parse_iw_scan((FX / "iw_scan.txt").read_text()), source="iw")
    tab = FindingsTab(ctx)
    assert "Nothing assessed yet" in tab.detail.toPlainText()
    tab.include_unauth.setChecked(True)
    for r in range(tab.table.rowCount()):            # every finding has details incl. its device
        tab.table.selectRow(r)
        text = tab.detail.toPlainText()
        assert "How to fix it" in text and "Network:" in text and "Risk score" in text
    # a WPA3-only network has no findings but is still listed and has details
    row = next(r for r in range(tab.risks.rowCount()) if tab.risks.item(r, 1).text().startswith("Modern"))
    tab.risks.selectRow(row)
    assert "BSSID" in tab.detail.toPlainText()
    # selection survives a refresh
    tab._show_all()
    tab.table.selectRow(0)
    before = tab.detail.toPlainText()
    ctx.bus.networks_changed.emit()
    assert tab.detail.toPlainText() == before and before


def test_findings_details_patch_section(ctx):
    from watchtower.gui.tabs.findings_tab import FindingsTab
    sid = ctx.scans.start("nmap", "192.168.56.101", "nmap -sV 192.168.56.101")
    ctx.scans.finish(sid, 0, (FX / "nmap_lab.xml").read_text())
    tab = FindingsTab(ctx)
    row = next(r for r in range(tab.table.rowCount()) if tab.table.item(r, 4).text() == "CVE-2024-6387")
    tab.table.selectRow(row)
    text = tab.detail.toPlainText()
    for needle in ("Is it fixed on this system?", "3ubuntu0.10", "USN-6859-1", "CVE details", "CWE-364",
                   "apt changelog openssh-server", "Open ports", "Host: 192.168.56.101"):
        assert needle in text, needle


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not (shutil.which("openssl") and shutil.which("testssl")), reason="openssl/testssl.sh missing")
def test_host_audit_tls_end_to_end(ctx, tmp_path):
    from watchtower.core import deps
    from watchtower.gui.tabs.host_audit_tab import HostAuditTab
    ctx.deps.update(deps.check_all())
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k.pem"),
                    "-out", str(tmp_path / "c.pem"), "-days", "5", "-subj", "/CN=test.lan"], check=True,
                   capture_output=True)
    port = _free_port()
    srv = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-cert", str(tmp_path / "c.pem"),
                            "-key", str(tmp_path / "k.pem"), "-www"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    try:
        time.sleep(0.8)
        ctx.targets.add("127.0.0.1")
        tab = HostAuditTab(ctx)
        tab.host_input.setText("127.0.0.1")
        tab._add_host()
        tab.tls_port.setEditText(str(port))
        tab.tls_port.setCurrentIndex(-1)
        tab.tls_port.setEditText(str(port))
        tab.tls_backend.setCurrentText("testssl.sh")
        assert tab.tls_btn.isEnabled()
        tab.run_tls()
        assert wait_for(lambda: tab.cancel_event is None, 400)
        text = tab.results.toPlainText()
        assert f"Port {port}" in text and "Certificate" in text, text
        row = ctx.audits.latest("127.0.0.1")[0]
        assert row["kind"] == "tls" and row["tool"] == "testssl.sh" and row["raw_output"]
    finally:
        srv.terminate()


@pytest.mark.skipif(not (shutil.which("snmpd") and shutil.which("snmpget")), reason="snmpd/snmpget missing")
def test_host_audit_snmp_end_to_end(ctx, tmp_path):
    from watchtower.gui.tabs.host_audit_tab import HostAuditTab
    port = _free_port()
    conf = tmp_path / "snmpd.conf"
    conf.write_text(f"agentaddress udp:127.0.0.1:{port}\nrocommunity public 127.0.0.1\nsysName e2e-box\n")
    srv = subprocess.Popen(["snmpd", "-f", "-Lo", "-C", "-c", str(conf)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.0)
        ctx.targets.add("127.0.0.1")
        tab = HostAuditTab(ctx)
        tab.host_input.setText("127.0.0.1")
        tab._add_host()
        tab.snmp_port.setValue(port)
        tab.v1.setChecked(False)
        tab.run_snmp()
        assert wait_for(lambda: tab.cancel_event is None, 60)
        text = tab.results.toPlainText()
        assert "e2e-box" in text and "private" in text
        assert any("snmpget" in (e.command or "") and "-c public" in (e.command or "") for e in ctx.audit.entries())
        assert not any(" set" in (e.command or "").lower() for e in ctx.audit.entries())
    finally:
        srv.terminate()


def test_host_audit_refuses_out_of_scope(ctx, monkeypatch):
    from watchtower.gui.tabs import host_audit_tab
    shown = []

    class FakeBox:   # don't monkeypatch attributes on PySide types themselves: it crashes at exit
        @staticmethod
        def warning(*a, **k):
            shown.append(a[2])

    monkeypatch.setattr(host_audit_tab, "QMessageBox", FakeBox)
    tab = host_audit_tab.HostAuditTab(ctx)
    tab.host_input.setText("10.9.9.9")
    tab._add_host()
    assert shown and "authorized" in shown[0] and tab.host_list.count() == 0


def test_findings_fix_buttons(ctx):
    from watchtower.gui.tabs.findings_tab import FindingsTab
    xml = (FX / "nmap_lab.xml").read_text().replace("192.168.56.101", "127.0.0.1")
    sid = ctx.scans.start("nmap", "127.0.0.1", "nmap -sV 127.0.0.1")
    ctx.scans.finish(sid, 0, xml)
    tab = FindingsTab(ctx)
    row = next(r for r in range(tab.table.rowCount()) if tab.table.item(r, 4).text() == "CVE-2024-6387")
    tab.table.selectRow(row)
    labels = [a.label for a in tab.fix_actions]
    assert "Install security updates for openssh-server" in labels and "Re-scan to verify" in labels
    assert "this machine" in tab.fix_label.text() and not tab.fix_bar.isHidden()
    got = []
    ctx.bus.request_scan.connect(got.append)
    tab._apply_fix(next(a for a in tab.fix_actions if a.kind == "rescan"),
                   next(f for f in tab.shown if f.cve_id == "CVE-2024-6387"))
    assert got == ["127.0.0.1"] and ctx.audit.entries()[0].event == "remediation"


def test_changes_tab_compares_scans_and_wifi(ctx):
    from watchtower.core import wifi_scan
    from watchtower.gui.tabs.changes_tab import ChangesTab
    lab = (FX / "nmap_lab.xml").read_text()
    for xml in (lab.replace('<port protocol="tcp" portid="23">', '<port protocol="tcp" portid="2323">'), lab):
        sid = ctx.scans.start("nmap", "192.168.56.101", "nmap ...")
        ctx.scans.finish(sid, 0, xml)
    aps = wifi_scan.parse_iw_scan((FX / "iw_scan.txt").read_text())
    ctx.networks.record(aps[:3], source="iw")
    ctx.networks.set_authorized("AA:BB:CC:00:00:01", True)
    ctx.networks.record(aps, source="iw")
    tab = ChangesTab(ctx)
    assert tab.sources.count() == 2
    tab.sources.setCurrentRow(1)
    texts = [tab.table.item(r, 2).text() for r in range(tab.table.rowCount())]
    assert "Port opened: 23/tcp" in texts and "Port closed: 2323/tcp" in texts
    tab.sources.setCurrentRow(0)
    assert tab.table.rowCount() == 3 and "New network nearby" in tab.table.item(0, 2).text()
    ctx.targets.add("192.168.56.0/24")
    ctx.bus.targets_changed.emit()
    tab._add_schedule()
    assert tab.sched_table.rowCount() == 1 and tab.sched_table.item(0, 1).text() == "192.168.56.0/24"
    tab.sched_table.item(0, 0).setCheckState(Qt.CheckState.Unchecked)
    assert ctx.schedules.all()[0]["enabled"] == 0


def test_nvd_lookup_logs_and_caches(ctx, monkeypatch):
    import json as _json

    import requests

    from watchtower.gui.tabs.findings_tab import FindingsTab
    from watchtower.storage.settings import NVD_ENABLED
    sample = _json.loads((FX / "nvd_api2_sample.json").read_text())

    class Resp:
        status_code = 200

        def json(self):
            return sample

    class Sess:
        def get(self, *a, **k):
            return Resp()

    monkeypatch.setattr(requests, "Session", Sess)
    from watchtower.core import nvd as nvd_mod
    monkeypatch.setattr(nvd_mod, "DELAY_NO_KEY", 0)
    sid = ctx.scans.start("nmap", "192.168.56.101", "nmap -sV 192.168.56.101")
    ctx.scans.finish(sid, 0, (FX / "nmap_lab.xml").read_text())
    tab = FindingsTab(ctx)
    assert tab.nvd_btn.isHidden()                                   # off by default: no network calls
    before = tab.table.rowCount()
    ctx.settings.set(NVD_ENABLED, True)
    tab.refresh()
    assert not tab.nvd_btn.isHidden()
    tab.nvd_lookup()
    assert wait_for(lambda: not getattr(tab, "_nvd_running", False), 30)
    assert tab.table.rowCount() == before + 1, tab.nvd_status.text()  # CVE-2099-0001 added; 2011-2523 deduped
    reqs = [e for e in ctx.audit.entries() if e.event == "network_request"]
    assert len(reqs) == 1 and "services.nvd.nist.gov" in reqs[0].command
    assert ctx.nvd.get("cpe:2.3:a:vsftpd:vsftpd:2.3.4")


def test_settings_retention(ctx, tmp_path):
    from watchtower.gui.tabs.settings_tab import SettingsTab
    from watchtower.storage.settings import RETENTION_DAYS
    sid = ctx.scans.start("nmap", "10.0.0.1", "nmap 10.0.0.1")
    ctx.scans.finish(sid, 0, "<x/>")
    tab = SettingsTab(ctx)
    tab.retention.setValue(30)
    assert ctx.settings.get(RETENTION_DAYS) == 30
    assert "Database size" in tab.data_info.text()


def test_password_strength_panel(ctx):
    from watchtower.gui.tabs.password_tab import StrengthPanel
    panel = StrengthPanel(ctx)
    panel.pw_input.setText("password")
    assert panel.bar.value() <= 1 and panel.checklist.rowCount() > 0
    assert panel.crack_table.rowCount() > 0
    panel.pw_input.setText("correct-horse-battery-staple-9471")
    assert panel.bar.value() >= 3
    # context reuse weakens the score
    panel.pw_input.setText("Smithxyz2020")
    before = panel.bar.value()
    panel.context_input.setText("Smith 2020")
    assert panel.bar.value() <= before


def test_breach_panel_online_and_batch(ctx, monkeypatch):
    import requests

    from watchtower.gui.tabs.password_tab import BreachPanel
    sample_suffix = __import__("watchtower.core.pwned_check", fromlist=["x"]).split_hash("password")[1]

    class Resp:
        status_code = 200
        text = f"{sample_suffix}:4242\r\nAAAABBBBCCCCDDDDEEEEFFFF0000111122:3"

    class Sess:
        def get(self, url, headers=None, timeout=None):
            return Resp()

    monkeypatch.setattr(requests, "Session", Sess)
    panel = BreachPanel(ctx)
    panel.single_input.setText("password")
    panel._check_single()
    assert wait_for(lambda: not panel._running, 10)
    assert "4,242" in panel.single_result.text() and "breaches" in panel.single_result.text()
    # the request is logged and only the hash prefix was involved (never the password)
    reqs = [e for e in ctx.audit.entries() if e.event == "network_request"]
    assert reqs and "api.pwnedpasswords.com/range/" in reqs[0].command
    assert "password" not in reqs[0].command.split("/range/")[1]   # only the 5-char prefix, never the password
    # batch
    panel.batch_input.setPlainText("password\npassword\nsomethingelse")
    panel._check_batch()
    assert wait_for(lambda: not panel._running, 10)
    assert panel.batch_table.rowCount() == 3
    assert "breaches" in panel.batch_status.text() or "breach" in panel.batch_status.text()


def test_breach_panel_offline(ctx, tmp_path):
    from watchtower.core import pwned_check
    from watchtower.gui.tabs.password_tab import BreachPanel
    rows = sorted((pwned_check.sha1_hex(w), w) for w in ("password", "secret", "dragon"))
    f = tmp_path / "pwned.txt"
    f.write_text("\n".join(f"{h}:{500 if w == 'password' else 1}" for h, w in rows) + "\n")
    panel = BreachPanel(ctx)
    panel.offline.setChecked(True)
    panel.offline_path.setText(str(f))
    panel.single_input.setText("password")
    panel._check_single()
    assert wait_for(lambda: not panel._running, 10)
    assert "500" in panel.single_result.text()


def _select_tool(panel, key):
    data = [panel.tool_combo.itemData(i) for i in range(panel.tool_combo.count())]
    panel.tool_combo.setCurrentIndex(data.index(key))


def test_hash_recovery_panel_generates_but_never_runs(ctx, tmp_path):
    from watchtower.core import hash_cracker as hc
    from watchtower.gui.tabs.password_tab import HashRecoveryPanel
    if "hashcat" not in hc.available_tools():
        pytest.skip("hashcat not installed")

    hash_file = tmp_path / "hash.txt"
    hash_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")   # md5("password")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("letmein\npassword\n")

    panel = HashRecoveryPanel(ctx)
    # pick hashcat + MD5
    _select_tool(panel, "hashcat")
    panel.type_combo.setCurrentIndex(0)   # MD5
    assert panel.type_combo.currentData().label == "MD5"
    panel.hash_input.setText(str(hash_file))
    panel.word_input.setText(str(wordlist))

    # ownership gate: can't generate until confirmed
    assert not panel.gen_btn.isEnabled()
    panel.own_box.setChecked(True)
    assert panel.gen_btn.isEnabled()

    panel._generate()
    out = panel.output.toPlainText()
    assert "hashcat" in out and "-m 0" in out and "--show" in out   # crack + show commands shown
    assert panel.copy_btn.isEnabled()

    # nothing was executed: no command_start/end was logged, only a confirmation of the generated command
    events = [e.event for e in ctx.audit.entries()]
    assert "command_start" not in events and "command_end" not in events
    conf = [e for e in ctx.audit.entries() if e.event == "user_confirmation"]
    assert conf and conf[0].target == str(hash_file)
    assert str(hash_file) in conf[0].command and "password" not in (conf[0].detail or "")

    # copy puts the crack command on the clipboard
    panel._copy()
    assert "hashcat" in QApplication.clipboard().text()


def test_hash_recovery_panel_document_type_shows_extractor(ctx, tmp_path):
    from watchtower.core import hash_cracker as hc
    from watchtower.gui.tabs.password_tab import HashRecoveryPanel
    if not hc.available_tools():
        pytest.skip("no recovery tool installed")
    hash_file = tmp_path / "zip.hash"
    hash_file.write_text("$zip2$*0*...*$/zip2$\n")
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("secret\n")
    panel = HashRecoveryPanel(ctx)
    # select the ZIP type and John (hashcat has no ZIP mode)
    idx = [panel.type_combo.itemData(i).label for i in range(panel.type_combo.count())].index("ZIP (PKZIP/WinZip)")
    panel.type_combo.setCurrentIndex(idx)
    if "john" in hc.available_tools():
        _select_tool(panel, "john")
    panel.hash_input.setText(str(hash_file))
    panel.word_input.setText(str(wordlist))
    panel.own_box.setChecked(True)
    panel._generate()
    out = panel.output.toPlainText()
    if "john" in hc.available_tools():
        assert "zip2john" in out and "Step 1" in out   # one-off extractor command is shown first


def test_wordlist_panel_build_merge_and_starter(ctx, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    from watchtower.gui.tabs.password_tab import PasswordTab
    tab = PasswordTab(ctx)
    assert [tab.tabs.tabText(i) for i in range(tab.tabs.count())][-1] == "Wordlists"
    wp = tab.wordlists

    # build a targeted list and preview it
    wp.base_input.setPlainText("spot\nsmith")
    wp.cb_leet.setChecked(True)
    wp.cb_years.setChecked(True)
    wp._preview()
    assert "entries" in wp.build_count.text()
    assert 0 < len(wp.preview_box.toPlainText().splitlines()) <= 200

    # save it (stub the file dialog + the "use it now?" prompt)
    out = tmp_path / "wl.txt"
    monkeypatch.setattr("watchtower.gui.tabs.password_tab.QFileDialog.getSaveFileName",
                        lambda *a, **k: (str(out), ""))
    monkeypatch.setattr("watchtower.gui.tabs.password_tab.QMessageBox.question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    wp._save_build()
    assert out.is_file() and out.read_text().strip()
    # "use it" routed the saved list into Hash Recovery and switched tabs
    assert tab.hashrec.word_input.text() == str(out)
    assert tab.tabs.tabText(tab.tabs.currentIndex()) == "Hash Recovery"

    # starter list -> Hash Recovery
    assert wp.starter_table.rowCount() >= 1
    wp.starter_table.selectRow(0)
    wp._use_starter()
    assert tab.hashrec.word_input.text().endswith(".txt")

    # merge two files, dedupe
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("alpha\nbeta\n")
    b.write_text("beta\ngamma\n")
    wp.files_list.addItem(str(a))
    wp.files_list.addItem(str(b))
    merged = tmp_path / "m.txt"
    monkeypatch.setattr("watchtower.gui.tabs.password_tab.QFileDialog.getSaveFileName",
                        lambda *a, **k: (str(merged), ""))
    wp._merge()
    assert merged.read_text().splitlines() == ["alpha", "beta", "gamma"]
    assert "removed 1" in wp.merge_status.text()


def test_wordlist_install_actions_never_run(ctx, monkeypatch):
    """The 'Get more wordlists' buttons build a shown/logged plan in RunPlanDialog;
    they must not execute anything on their own."""
    from watchtower.gui.tabs.password_tab import PasswordTab
    captured = {}

    class FakeDialog:
        def __init__(self, ctx, title, intro, plan, parent=None):
            captured["title"] = title
            captured["cmd"] = plan.describe()

        def exec(self):
            captured["execed"] = True   # only shows the confirm dialog; runs nothing itself

    monkeypatch.setattr("watchtower.gui.run_dialog.RunPlanDialog", FakeDialog)
    wp = PasswordTab(ctx).wordlists
    wp._install_rockyou()
    assert "wordlists" in captured["cmd"] and captured.get("execed")
    wp._install_seclists()
    assert "git clone" in captured["cmd"]
    # nothing was executed as a command by clicking the buttons
    assert not [e for e in ctx.audit.entries() if e.event in ("command_start", "command_end")]


def _http_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=1; Path=/")
            self.end_headers()
            self.wfile.write(b"<html></html>")

        def log_message(self, *a):
            pass
    import threading
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_web_audit_tab_scope_and_header_check(ctx, monkeypatch):
    import requests

    from watchtower.gui.tabs import web_audit_tab
    from watchtower.gui.tabs.findings_tab import FindingsTab
    from watchtower.gui.tabs.host_audit_tab import HostAuditTab
    srv = _http_server()
    port = srv.server_address[1]

    class NoProxySession(requests.Session):
        def __init__(self):
            super().__init__()
            self.trust_env = False
    monkeypatch.setattr(requests, "Session", NoProxySession)
    try:
        tab = web_audit_tab.WebAuditTab(ctx)
        tab.url_input.setText(f"http://127.0.0.1:{port}/")
        assert not tab.add_url(confirm=lambda: False)              # declined: nothing authorized
        assert not ctx.targets.covers("127.0.0.1") and tab.url_list.count() == 0
        assert tab.add_url(confirm=lambda: True)
        assert ctx.targets.covers("127.0.0.1")
        assert any(e.event == "scope_change" and e.target == "127.0.0.1" for e in ctx.audit.entries(limit=20))
        assert tab.current_url() == f"http://127.0.0.1:{port}/" and tab.headers_btn.isEnabled()
        tab.run_headers()
        assert wait_for(lambda: tab.cancel_event is None, 30)
        text = tab.results.toPlainText()
        assert "Site served over plain HTTP" in text and "HttpOnly" in text, text
        net = [e for e in ctx.audit.entries(limit=50) if e.event == "network_request"]
        assert net and net[0].command == f"GET http://127.0.0.1:{port}/"
        # results flow into Findings as a Web device; Host Audit ignores URL rows
        ft = FindingsTab(ctx)
        ft.refresh()
        assert any(r.kind == "web" for r in ft.assessment.risks)
        assert "1 web URL(s)" in ft.summary.text()
        HostAuditTab(ctx)
        # out of scope again -> buttons off
        ctx.targets.remove("127.0.0.1")
        ctx.bus.targets_changed.emit()
        assert not tab.headers_btn.isEnabled()
    finally:
        srv.shutdown()
        srv.server_close()


def test_domain_audit_tab_owned_domains_and_dns(ctx):
    import json

    from watchtower.core import domain_audit
    from watchtower.gui.tabs.domain_audit_tab import DomainAuditTab
    records = json.loads((FX / "dns_records.json").read_text())["records"]
    tab = DomainAuditTab(ctx)
    tab.domain_input.setText("weak.example")
    assert not tab.add_domain(confirm=lambda: False) and ctx.domains.values() == []
    assert tab.add_domain(confirm=lambda: True) and ctx.domains.values() == ["weak.example"]
    assert tab.current_domain() == "weak.example"
    labels = [tab.sub_backend.itemData(i) for i in range(tab.sub_backend.count())]
    assert labels == ["subfinder", "amass", "crt.sh"] and tab.sub_backend.model().item(2).isEnabled()

    def factory(on_query):
        base = domain_audit.dict_resolver(records)

        def resolve(name, rdtype):
            on_query(name, rdtype)
            return base(name, rdtype)
        return resolve
    tab.run_mail(resolver_factory=factory)
    assert wait_for(lambda: tab.cancel_event is None, 30)
    text = tab.results.toPlainText()
    assert "DMARC policy is p=none" in text and "768 bits" in text, text
    dns_log = [e for e in ctx.audit.entries(limit=100) if e.event == "network_request"]
    assert any(e.command == "DNS TXT _dmarc.weak.example" for e in dns_log)
    row = ctx.audits.latest("weak.example")[0]
    assert row["kind"] == "email"


def test_traffic_tab_open_file_schedule_and_changes(ctx, monkeypatch):
    if not shutil.which("tshark"):
        pytest.skip("tshark missing")
    from watchtower.gui.tabs import traffic_tab
    from watchtower.gui.tabs.changes_tab import CAPTURE_PREFIX, ChangesTab
    from watchtower.gui.tabs.findings_tab import FindingsTab
    tab = traffic_tab.TrafficTab(ctx)
    assert "Nothing analyzed yet" in tab.findings_view.toPlainText()
    pcap = str(FX / "traffic_lab.pcapng")
    tab.open_file(pcap)
    assert wait_for(lambda: tab.cancel_event is None, 60)
    text = tab.findings_view.toPlainText()
    for needle in ("password sent unencrypted (FTP)", "How to fix it", "Why it matters", "SMBv1 in use",
                   "broadcasts LLMNR name lookups"):
        assert needle in text, needle
    assert "s3cret" not in text and "YWRtaW46" not in text            # never a password on screen
    assert "Who talked to whom" in tab.overview.toPlainText()
    row = ctx.captures.all()[0]
    assert row["source"] == f"file:{pcap}" and not row["owned"] and row["packets"] == 176
    # the tshark commands were shown and logged
    cmds = [e.command or "" for e in ctx.audit.entries(limit=50) if e.event == "command_start"]
    assert any("tshark" in c and pcap in c for c in cmds)
    # Findings tab picks the capture up (merged per IP address)
    ft = FindingsTab(ctx)
    ft.refresh()
    assert any(f.kind == "traffic" for f in ft.assessment.findings) and "1 traffic capture(s)" in ft.summary.text()
    # deleting an imported capture never deletes the user's file
    monkeypatch.setattr(traffic_tab.QMessageBox, "question",
                        lambda *a, **k: traffic_tab.QMessageBox.StandardButton.Yes)
    # open it a second time, compare the two in What Changed (identical -> no changes)
    tab.open_file(pcap)
    assert wait_for(lambda: tab.cancel_event is None, 60)
    ch = ChangesTab(ctx)
    items = [ch.sources.item(i) for i in range(ch.sources.count())]
    cap_item = next(i for i in items if str(i.data(Qt.ItemDataRole.UserRole)).startswith(CAPTURE_PREFIX))
    assert "2 captures" in cap_item.text()
    ch.sources.setCurrentItem(cap_item)
    assert ch.older.count() == 2 and "No changes" in ch.summary.text()
    tab.select_capture(row["id"])
    tab.delete_capture()
    assert Path(pcap).exists() and ctx.captures.get(row["id"]) is None
    # repeating capture from the current settings
    idx = tab.iface.findData("lo")
    if idx >= 0:
        tab.iface.setCurrentIndex(idx)
        tab.filter.setText("port 53")
        tab.add_schedule()
        s = ctx.capture_schedules.all()[0]
        assert (s["interface"], s["user_filter"], s["seconds"]) == ("lo", "port 53", 60)
        assert tab.sched_table.rowCount() == 1


def test_traffic_tab_live_capture_on_loopback(ctx):
    from watchtower.core import traffic_audit as ta
    if not (shutil.which("dumpcap") and shutil.which("tshark")) or ta.capture_permission()[0] is False:
        pytest.skip("can't capture here")
    from watchtower.gui.tabs.traffic_tab import TrafficTab
    tab = TrafficTab(ctx)
    idx = tab.iface.findData("lo")
    if idx < 0:
        pytest.skip("no loopback interface")
    tab.iface.setCurrentIndex(idx)
    tab.duration.setCurrentText("30 seconds")
    assert tab.start_btn.isEnabled()
    tab.start_capture()
    assert not tab.progress.isHidden() and tab.cancel_btn.isEnabled()
    time.sleep(1.5)
    tab.cancel_btn.click()                               # Stop early: what was recorded is still analyzed
    assert wait_for(lambda: tab.cancel_event is None, 60)
    row = ctx.captures.all()[0]
    assert row["source"] == "interface:lo" and row["owned"] and not row["error"], row["error"]
    assert Path(row["pcap_path"]).exists() and oct(Path(row["pcap_path"]).stat().st_mode)[-3:] == "600"
    assert "not ether proto 0x888e" in row["command"]
    assert "Live capture on lo" in tab.findings_view.toPlainText()


def _untipped_controls(root):
    """Interactive controls under `root` without a tooltip (internal editors of combo/spin boxes skipped)."""
    from PySide6.QtWidgets import (
        QAbstractSpinBox,
        QCheckBox,
        QComboBox,
        QLineEdit,
        QPushButton,
        QRadioButton,
        QSpinBox,
    )
    out = []
    for cls in (QPushButton, QCheckBox, QRadioButton, QComboBox, QLineEdit, QSpinBox):
        for w in root.findChildren(cls):
            if w.objectName().startswith("qt_") or isinstance(w.parent(), (QComboBox, QAbstractSpinBox)):
                continue
            if not w.toolTip().strip():
                label = w.text() if hasattr(w, "text") and not isinstance(w, QLineEdit) else ""
                ph = w.placeholderText() if isinstance(w, QLineEdit) else ""
                out.append(f"{cls.__name__} {label or ph or w.objectName()!r}")
    return out


def test_every_control_explains_itself(ctx):
    """GUI clarity rule: every button, checkbox, choice and input on every tab has a tooltip saying what
    it does (and, when disabled, why). New controls must follow this: use gui.ui.tip()."""
    from watchtower.gui.main_window import MainWindow
    from watchtower.help.content import TAB_HELP
    win = MainWindow(ctx)
    problems = {}
    for key, page in win.pages.items():
        assert TAB_HELP.get(page.help_key if hasattr(page, "help_key") else key, "").strip() or key == "help", key
        missing = _untipped_controls(page)
        if missing:
            problems[key] = missing
    assert not problems, problems
    # enabled controls keep their explanation (gates restore it instead of blanking it)
    win.scan_tab.target.setText("192.168.99.1")
    QApplication.processEvents()
    assert win.scan_tab.cancel_btn.toolTip()


def test_dialogs_explain_their_controls(ctx):
    from watchtower.core import deps
    from watchtower.gui.dependency_check import DependencyDialog
    from watchtower.gui.report_export import ExportDialog
    from watchtower.gui.run_dialog import RunPlanDialog
    for dlg in (ExportDialog(ctx, False, None), DependencyDialog(ctx),
                RunPlanDialog(ctx, "t", "intro", deps.Plan([deps.Step("x", ["true"])], []))):
        assert not _untipped_controls(dlg), (type(dlg).__name__, _untipped_controls(dlg))


def test_traffic_devices_view(ctx):
    if not shutil.which("tshark"):
        pytest.skip("tshark missing")
    from watchtower.gui.tabs.traffic_tab import SHOW_CHOICES, TrafficTab
    tab = TrafficTab(ctx)
    tab.open_file(str(FX / "traffic_lan.pcapng"))
    assert wait_for(lambda: tab.cancel_event is None, 60)
    dv = tab.devices
    assert dv.count.text() == "3 device(s) on your network, 1 outside address(es)"
    ips = [dv.table.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in range(dv.table.rowCount())]
    assert sorted(ips) == ["10.9.0.1", "10.9.0.23", "10.9.0.42"]
    r = ips.index("10.9.0.23")
    assert dv.table.item(r, 1).text() == "Raspberry Pi Foundation" and "High" in dv.table.item(r, 5).text()
    dv.table.selectRow(r)
    text = dv.detail.toPlainText()
    for needle in ("10.9.0.23 (homeassistant)", "Who it is", "cloud.camvendor.example", "Services it offered"):
        assert needle in text, needle
    assert "SECRET" not in text
    # not an authorized target yet -> can't jump to a scan; once authorized, it opens Scan a Target
    assert not dv.scan_btn.isEnabled() and "authorized targets" in dv.scan_btn.toolTip()
    asked = []
    ctx.bus.request_scan.connect(asked.append)
    ctx.targets.add("10.9.0.0/24")
    ctx.bus.targets_changed.emit()
    assert dv.scan_btn.isEnabled()
    dv.scan_btn.click()
    assert asked == ["10.9.0.23"]
    dv.show.setCurrentText(next(k for k, v in SHOW_CHOICES.items() if v == "outside"))
    assert dv.table.rowCount() == 1 and dv.table.item(0, 0).data(Qt.ItemDataRole.UserRole) == "203.0.113.10"


def test_traffic_quiet_device_scan_needs_authorization(ctx):
    from watchtower.gui.tabs.traffic_tab import TrafficTab
    if not shutil.which("nmap"):
        pytest.skip("nmap missing")
    tab = TrafficTab(ctx)
    tab.iface.addItem("lab0", "lab0")
    tab.iface.setCurrentIndex(tab.iface.count() - 1)
    tab._nets["lab0"] = ["10.9.0.0/24"]
    tab._gate()
    assert not tab.discover.isEnabled() and "isn't in your authorized targets" in tab.discover.toolTip()
    ctx.targets.add("10.9.0.0/24")
    tab._gate()
    assert tab.discover.isEnabled() and "ping scan" in tab.discover.toolTip()
    tab._nets["lab0"] = ["10.0.0.0/16"]
    ctx.targets.add("10.0.0.0/16")
    tab._gate()
    assert not tab.discover.isEnabled() and "too large" in tab.discover.toolTip()


def test_devices_view_asks_to_reanalyze_old_captures(ctx):
    from watchtower.core import traffic_audit as ta
    from watchtower.gui.tabs.traffic_tab import DevicesView
    old = ta.CaptureStats(packets=176, seconds=8.0)          # pre-rundown analysis: no endpoints/flows
    cid = ctx.captures.start("file:/tmp/x.pcapng", "/tmp/x.pcapng", False, "open")
    ctx.captures.finish(cid, 0, 176, 8.0, ta.stats_to_json(old), "[]")
    dv = DevicesView(ctx)
    dv.show_capture(ctx.captures.get(cid))
    assert "Analyze again" in dv.detail.toPlainText() and dv.table.rowCount() == 0


def test_command_console_can_be_hidden_and_remembers(ctx):
    from watchtower.gui.main_window import MainWindow
    from watchtower.storage.settings import CONSOLE_VISIBLE
    win = MainWindow(ctx)
    win.show()
    QApplication.processEvents()
    assert win.console_dock.isVisible() and win.console_action.isChecked()
    assert win.console_action.shortcut().toString() == "Ctrl+`" and win.console_action.toolTip()
    win.console_action.trigger()                       # View -> Command Console (or Ctrl+`)
    QApplication.processEvents()
    assert not win.console_dock.isVisible() and ctx.settings.get(CONSOLE_VISIBLE) is False
    ctx.runner.run([sys.executable, "-c", "pass"], purpose="still logged while hidden")
    QApplication.processEvents()
    assert any(e.event == "command_start" and "-c pass" in (e.command or "") for e in ctx.audit.entries(limit=5))
    win2 = MainWindow(ctx)                             # next start: stays hidden
    win2.show()
    QApplication.processEvents()
    assert not win2.console_dock.isVisible() and not win2.console_action.isChecked()
    win2.console_action.trigger()
    QApplication.processEvents()
    assert win2.console_dock.isVisible() and ctx.settings.get(CONSOLE_VISIBLE) is True


def test_settings_options_apply_live_and_reset(ctx):
    from PySide6.QtWidgets import QCheckBox, QComboBox, QLineEdit, QSpinBox

    from watchtower.gui.main_window import MainWindow
    from watchtower.gui.report_export import ExportDialog
    from watchtower.storage import preferences as prefs
    from watchtower.storage.settings import CONSOLE_VISIBLE
    win = MainWindow(ctx)
    win.show()
    QApplication.processEvents()
    st = win.settings_tab
    assert set(st.pref_widgets) == {p.key for p in prefs.PREFS}      # every option has a control
    w = st.pref_widgets
    base = QApplication.font().pointSizeF()
    w[prefs.FONT_SIZE].setCurrentText("Extra large")
    assert QApplication.font().pointSizeF() == pytest.approx(base + 4)
    w[prefs.HELP_PANELS].setChecked(False)
    assert not any(p.help.toggle.isChecked() for p in win.pages.values())
    w[prefs.HELP_PANELS].setChecked(True)
    assert win.pages["scan"].help.toggle.isChecked() and not win.pages["findings"].help.toggle.isChecked()
    w[prefs.NIKTO_MINUTES].setValue(45)
    assert win.web_audit_tab.nikto_minutes.value() == 45
    w[prefs.SCAN_PROFILE].setCurrentText("Quick scan")
    assert win.scan_tab.profile.currentText() == "Quick scan"
    w[prefs.FINDINGS_MIN_SEVERITY].setCurrentText("High and above")
    assert win.findings_tab.min_sev.currentText() == "High and above"
    w[prefs.SCHEDULE_INTERVAL].setCurrentText("Weekly")
    assert win.changes_tab.s_interval.currentText() == "Weekly" and win.traffic_tab.every.currentText() == "Weekly"
    w[prefs.TRAFFIC_DURATION].setCurrentText("5 minutes")
    assert win.traffic_tab.duration.currentText() == "5 minutes"
    w[prefs.DKIM_SELECTORS].setText("selector1, google")
    w[prefs.DKIM_SELECTORS].editingFinished.emit()
    assert win.domain_audit_tab.selectors.text() == "selector1, google"
    w[prefs.REPORT_TITLE].setText("Lab Q4")
    w[prefs.REPORT_TITLE].editingFinished.emit()
    w[prefs.REPORT_INCLUDE_INFO].setChecked(True)
    dlg = ExportDialog(ctx, False, None)
    assert dlg.title.text() == "Lab Q4" and dlg.include_info.isChecked()
    # console: Settings checkbox and View menu stay in sync both ways
    w[CONSOLE_VISIBLE].setChecked(False)
    QApplication.processEvents()
    assert not win.console_dock.isVisible() and not win.console_action.isChecked()
    win.console_action.trigger()
    QApplication.processEvents()
    assert win.console_dock.isVisible() and w[CONSOLE_VISIBLE].isChecked()
    # start tab
    w[prefs.START_TAB].setCurrentText("Findings")
    win2 = MainWindow(ctx)
    assert win2.tabs.currentWidget() is win2.pages["findings"]
    # reset puts everything back, live
    st.reset_defaults(confirm=lambda: True)
    QApplication.processEvents()
    assert QApplication.font().pointSizeF() == pytest.approx(base)
    assert win.web_audit_tab.nikto_minutes.value() == 30 and w[prefs.NIKTO_MINUTES].value() == 30
    assert win.scan_tab.profile.currentText() == "Intense scan" and w[prefs.REPORT_TITLE].text() == \
        "Home lab security assessment"
    for key, wid in w.items():
        assert isinstance(wid, (QCheckBox, QComboBox, QLineEdit, QSpinBox)) and wid.toolTip(), key


def test_start_tab_last_used(ctx):
    from watchtower.gui.main_window import MainWindow
    win = MainWindow(ctx)
    win.tabs.setCurrentWidget(win.pages["traffic"])
    win2 = MainWindow(ctx)
    assert win2.tabs.currentWidget() is win2.pages["traffic"]


def test_closed_help_panel_leaves_no_gap(ctx):
    """Regression: closing "What is this?" used to leave an empty column the width of its button."""
    from watchtower.gui.main_window import MainWindow
    win = MainWindow(ctx)
    win.resize(1400, 900)
    win.show()
    QApplication.processEvents()
    for key in ("scan", "traffic", "settings"):
        win.tabs.setCurrentWidget(win.pages[key])
        page = win.pages[key]
        assert win.help_button.defaultAction() is page.help.toggle       # corner button drives this tab
        page.help.toggle.setChecked(True)
        QApplication.processEvents()
        open_width = page.content.width()
        assert page.help.isVisible() and open_width < page.width() - 250
        win.help_button.click()                                           # close via the corner button
        QApplication.processEvents()
        assert not page.help.toggle.isChecked() and not page.help.isVisible()
        assert page.content.width() >= page.width() - 20, (key, page.content.width(), page.width())
        win.help_button.click()
        QApplication.processEvents()
        assert page.help.isVisible() and page.content.width() == open_width   # reopens at the same size
