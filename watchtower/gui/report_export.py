"""Export Report dialog: gathers everything and writes HTML (and optionally PDF)."""

from __future__ import annotations

import getpass
import json
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from watchtower.core import history_diff, nmap_runner, report
from watchtower.core.assessment import assess
from watchtower.gui.context import AppContext
from watchtower.gui.worker import run_in_background
from watchtower.storage.audit_log import Event


def gather(ctx: AppContext, include_unauthorized_wifi: bool, include_info: bool, title: str,
           author: str, msf_index: dict | None = None) -> report.ReportInput:
    a = assess(ctx.scans.with_output(), ctx.networks.all(), include_unauthorized_wifi, ctx.audits.latest(), msf_index,
               ctx.nvd.all() if ctx.nvd_enabled() else None, captures=ctx.captures.latest_per_source())
    changes = {}
    for t in ctx.scans.targets():
        scans = ctx.scans.for_target(t["target"], limit=2)
        if len(scans) == 2:
            changes[t["target"]] = history_diff.diff_scans(nmap_runner.parse_xml(scans[1]["raw_output"]),
                                                           nmap_runner.parse_xml(scans[0]["raw_output"]))
    commands = []
    for e in reversed(ctx.audit.entries(limit=2000)):
        if e.event not in ("command_start", "network_request") or not e.command:
            continue
        try:
            purpose = json.loads(e.detail or "{}").get("purpose", "")
        except ValueError:
            purpose = ""
        if purpose.startswith(("dependency check", "list ", "read ", "find default")):
            continue   # housekeeping, not part of the assessment
        commands.append({"ts": e.ts, "command": e.command, "purpose": purpose})
    nets = [n for n in ctx.networks.all() if n.get("authorized")]
    return report.ReportInput(a, title, author, ctx.targets.values(), nets, changes, commands[-200:], include_info,
                              ctx.domains.values())


class ExportDialog(QDialog):
    def __init__(self, ctx: AppContext, include_unauthorized_wifi: bool = False, msf_index: dict | None = None,
                 parent=None):
        super().__init__(parent)
        self.ctx, self.include_unauth, self.msf_index = ctx, include_unauthorized_wifi, msf_index
        self.setWindowTitle("Export report")
        self.setMinimumWidth(560)
        self.title = QLineEdit("Home lab security assessment")
        self.author = QLineEdit(getpass.getuser())
        self.include_info = QCheckBox("Include Info-level findings (e.g. CVEs already fixed by distro updates)")
        self.pdf = QCheckBox("Also create a PDF")
        has_pdf = report.pdf_argv("a.html", "a.pdf") is not None
        self.pdf.setEnabled(has_pdf)
        self.pdf.setToolTip("" if has_pdf else "requires WeasyPrint (sudo apt install weasyprint, or "
                                               "pip install weasyprint in Watchtower's environment)")
        self.path = QLineEdit(str(Path.home() / "watchtower-report.html"))
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        prow = QHBoxLayout()
        prow.addWidget(self.path)
        prow.addWidget(browse)
        self.status = QLabel()
        self.status.setWordWrap(True)
        form = QFormLayout()
        form.addRow("Title:", self.title)
        form.addRow("Author:", self.author)
        form.addRow("Save to:", prow)
        form.addRow(self.include_info)
        form.addRow(self.pdf)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.export)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.status)
        lay.addWidget(self.buttons)

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save report", self.path.text(), "HTML (*.html)")
        if path:
            self.path.setText(path if path.endswith(".html") else path + ".html")

    def export(self) -> Path | None:
        path = Path(self.path.text()).expanduser()
        try:
            data = gather(self.ctx, self.include_unauth, self.include_info.isChecked(), self.title.text(),
                          self.author.text(), self.msf_index)
            path.write_text(report.render_html(data), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export", f"Couldn't write {path}: {exc}")
            return None
        self.ctx.audit.append(Event.CONFIRMATION, detail={"action": "export report", "path": str(path),
                                                          "findings": len(data.assessment.findings)})
        self.exported = path
        if self.pdf.isChecked():
            pdf = path.with_suffix(".pdf")
            argv = report.pdf_argv(str(path), str(pdf))
            self.status.setText("Creating PDF…")
            self.buttons.setEnabled(False)

            def done(res):
                self.buttons.setEnabled(True)
                if res.ok and pdf.exists():
                    self._finish(pdf)
                else:
                    self.status.setText(f"PDF failed (exit {res.exit_code}); the HTML report was saved.")
            run_in_background(self.ctx.runner.run, argv, purpose="render PDF report", timeout=300, on_done=done,
                              on_error=lambda m: self.status.setText("PDF failed: " + m.split("\n")[0]))
            return path
        self._finish(path)
        return path

    def _finish(self, path: Path):
        if QMessageBox.question(self, "Report saved", f"Saved {path}. Open it now?") \
                == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        self.accept()
