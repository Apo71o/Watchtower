import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from watchtower.core import history_diff, report
from watchtower.core.assessment import assess
from watchtower.core.nmap_runner import parse_xml

FX = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def build(include_info=False, nets=None):
    lab = (FX / "nmap_lab.xml").read_text()
    nets = nets if nets is not None else [{"bssid": "AA:BB:CC:00:00:01", "ssid": "Home", "security": "WPA2",
                                          "auth": "PSK", "wps": 1, "authorized": 1}]
    a = assess([{"id": 1, "raw_output": lab}], nets)
    changes = {"192.168.56.101": history_diff.diff_scans(parse_xml(""), parse_xml(lab))}
    cmds = [{"ts": "2026-11-01T10:00:00+00:00", "command": "nmap -sV --script vuln 192.168.56.101",
             "purpose": "nmap scan"}]
    return report.ReportInput(a, "Lab report", "me", ["192.168.56.0/24"], nets, changes, cmds, include_info)


def test_report_sections_and_content():
    html = report.render_html(build(), NOW)
    for needle in ("<h2>Executive summary</h2>", "<h2>Scope</h2>", "<h2>Top risks</h2>", "<h2>Findings</h2>",
                   "<h2>Recent changes</h2>", "<h2>Methodology</h2>", "vsftpd 2.3.4 backdoor",
                   "exploit/unix/ftp/vsftpd_234_backdoor", "How to fix it", "How the attack works",
                   "https://nvd.nist.gov/vuln/detail/CVE-2011-2523", "https://attack.mitre.org/techniques/T1190/",
                   "192.168.56.0/24", "nmap -sV --script vuln 192.168.56.101", "2026-11-01 12:00 UTC",
                   "WPS (Wi-Fi Protected Setup) enabled", "<strong>PIN brute force:</strong>", "Fix first"):
        assert needle in html, needle
    assert html.startswith("<!doctype html>") and html.rstrip().endswith("</html>")


def test_report_escapes_hostile_input():
    evil = "<script>alert(1)</script>"
    html = report.render_html(build(nets=[{"bssid": "AA:BB:CC:00:00:09", "ssid": evil, "security": "Open",
                                           "auth": "OPN", "authorized": 1}]), NOW)
    assert evil not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_info_findings_optional():
    lab = (FX / "nmap_lab.xml").read_text().replace("3ubuntu0.1", "3ubuntu0.13")
    a = assess([{"id": 1, "raw_output": lab}], [])
    without = report.render_html(report.ReportInput(a), NOW)
    with_info = report.render_html(report.ReportInput(a, include_info=True), NOW)
    assert "fixed by Ubuntu update" not in without and "fixed by Ubuntu update" in with_info


@pytest.mark.skipif(report.pdf_argv("a", "b") is None, reason="WeasyPrint not installed")
def test_pdf_render(tmp_path):
    src = tmp_path / "r.html"
    src.write_text(report.render_html(build(), NOW))
    r = subprocess.run(report.pdf_argv(str(src), str(tmp_path / "r.pdf")), capture_output=True, text=True,
                       timeout=180)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "r.pdf").read_bytes()[:5] == b"%PDF-"


def test_gui_export(tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from watchtower.core.platform_utils import platform_info
    from watchtower.gui import report_export
    from watchtower.gui.context import AppContext
    from watchtower.gui.worker import shutdown
    from watchtower.storage.db import Database
    monkeypatch.setenv("WATCHTOWER_HOME", str(tmp_path / "home"))
    ctx = AppContext.create(Database(), platform_info())
    sid = ctx.scans.start("nmap", "192.168.56.101", "nmap -sV 192.168.56.101")
    ctx.scans.finish(sid, 0, (FX / "nmap_lab.xml").read_text())
    ctx.runner.run(["true"] if shutil.which("true") else ["python3", "-c", "1"], purpose="nmap scan")
    dlg = report_export.ExportDialog(ctx)
    monkeypatch.setattr(dlg, "_finish", lambda p: None)
    dlg.path.setText(str(tmp_path / "out.html"))
    dlg.pdf.setChecked(False)
    assert dlg.export() == tmp_path / "out.html"
    html = (tmp_path / "out.html").read_text()
    assert "vsftpd 2.3.4 backdoor" in html and "<h2>Methodology</h2>" in html
    assert ctx.audit.entries()[0].detail and "export report" in ctx.audit.entries()[0].detail
    shutdown()
    dlg.deleteLater()
    app.processEvents()
