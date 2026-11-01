from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import attck_mapping
from watchtower.core.assessment import Assessment, assess
from watchtower.core.findings_engine import SEV_RANK, SEVERITIES, Finding
from watchtower.gui.context import AppContext

SEV_COLORS = {"Critical": "#b71c1c", "High": "#e53935", "Medium": "#ef6c00", "Low": "#f9a825", "Info": "#757575"}
FCOLS = ["Severity", "Device", "Finding", "Port / service", "CVE", "CVSS", "ATT&CK"]
RCOLS = ["Risk", "Device", "Type", "#", "Worst"]


def _item(text, color=None, bold=False):
    it = QTableWidgetItem(str(text))
    if color:
        it.setForeground(QBrush(QColor(color)))
    if bold:
        f = it.font()
        f.setBold(True)
        it.setFont(f)
    return it


class _SortItem(QTableWidgetItem):
    def __lt__(self, other):
        a, b = self.data(Qt.ItemDataRole.UserRole + 1), other.data(Qt.ItemDataRole.UserRole + 1)
        if a is not None and b is not None:
            return a < b
        return super().__lt__(other)


def _sitem(text, sort, color=None, bold=False):
    it = _SortItem(str(text))
    it.setData(Qt.ItemDataRole.UserRole + 1, sort)
    if color:
        it.setForeground(QBrush(QColor(color)))
    if bold:
        f = it.font()
        f.setBold(True)
        it.setFont(f)
    return it


class FindingsTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.assessment: Assessment | None = None
        self.shown: list[Finding] = []
        self.device_filter: str | None = None

        self.summary = QLabel()
        self.min_sev = QComboBox()
        self.min_sev.addItems(["All severities", "Low and above", "Medium and above", "High and above",
                               "Critical only"])
        self.include_unauth = QCheckBox("Include unauthorized Wi-Fi networks")
        self.include_unauth.setToolTip("Assess every network seen nearby, not just ones marked Authorized "
                                       "(uses only what they broadcast).")
        self.refresh_btn = QPushButton("Refresh")
        top = QHBoxLayout()
        top.addWidget(self.summary, 1)
        top.addWidget(self.include_unauth)
        top.addWidget(self.min_sev)
        top.addWidget(self.refresh_btn)

        self.risks = QTableWidget(0, len(RCOLS))
        self.risks.setHorizontalHeaderLabels(RCOLS)
        self.risks.verticalHeader().setVisible(False)
        self.risks.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.risks.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.risks.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.risks.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.risks.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.risks.setSortingEnabled(True)
        self.risks.horizontalHeader().setSortIndicator(0, Qt.SortOrder.DescendingOrder)  # highest risk first
        self.show_all_btn = QPushButton("Show all devices")
        rbox = QWidget()
        rl = QVBoxLayout(rbox)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(QLabel("<b>Top risks</b> (0-100, highest first)"))
        rl.addWidget(self.risks)
        rl.addWidget(self.show_all_btn)

        self.table = QTableWidget(0, len(FCOLS))
        self.table.setHorizontalHeaderLabels(FCOLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicator(0, Qt.SortOrder.AscendingOrder)   # Critical first
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        for col, width in ((1, 170), (3, 110), (4, 115), (6, 110)):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            hh.resizeSection(col, width)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.detail = QTextBrowser(openExternalLinks=True)
        self.detail.setPlaceholderText(
            "Select a finding to see the details, the technique explained, and how to fix it.")

        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self.table)
        right.addWidget(self.detail)
        right.setStretchFactor(0, 1)
        right.setStretchFactor(1, 1)
        split = QSplitter()
        split.addWidget(rbox)
        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([330, 820])
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split)

        self.refresh_btn.clicked.connect(self.refresh)
        self.include_unauth.toggled.connect(self.refresh)
        self.min_sev.currentIndexChanged.connect(self._fill_findings)
        self.risks.itemSelectionChanged.connect(self._risk_selected)
        self.show_all_btn.clicked.connect(lambda: (self.risks.clearSelection(), self._set_device(None)))
        self.table.itemSelectionChanged.connect(self._finding_selected)
        ctx.bus.scan_finished.connect(self.refresh)
        ctx.bus.networks_changed.connect(self.refresh)
        self.refresh()

    def refresh(self):
        self.assessment = assess(self.ctx.scans.with_output(), self.ctx.networks.all(),
                                 self.include_unauth.isChecked())
        a = self.assessment
        c = a.counts()
        parts = [f"<span style='color:{SEV_COLORS[s]}'><b>{c[s]}</b> {s}</span>" for s in SEVERITIES if c[s]]
        self.summary.setText(
            f"{len(a.findings)} finding(s) across {a.hosts_assessed} host(s) and {a.networks_assessed} "
            f"Wi-Fi network(s)" + (": " + " · ".join(parts) if parts else
                                   ". Run a scan or mark networks Authorized to see findings."))
        self.risks.setSortingEnabled(False)
        self.risks.setRowCount(len(a.risks))
        for r, d in enumerate(a.risks):
            color = SEV_COLORS[d.worst] if d.findings else None
            vals = [_sitem(d.score, d.score, color, bold=True), _item(d.label),
                    _item("Wi-Fi" if d.kind == "wifi" else "Host"), _sitem(len(d.findings), len(d.findings)),
                    _sitem(d.worst if d.findings else "-", SEV_RANK[d.worst], color)]
            vals[1].setData(Qt.ItemDataRole.UserRole, d.device)
            vals[1].setToolTip(f"{d.open_ports} open port(s)" if d.kind == "host" else d.device)
            for c_, it in enumerate(vals):
                self.risks.setItem(r, c_, it)
        self.risks.setSortingEnabled(True)
        if self.device_filter and not any(d.device == self.device_filter for d in a.risks):
            self.device_filter = None
        self._fill_findings()

    def _set_device(self, dev):
        self.device_filter = dev
        self._fill_findings()

    def _risk_selected(self):
        rows = self.risks.selectionModel().selectedRows()
        if rows:
            self._set_device(self.risks.item(rows[0].row(), 1).data(Qt.ItemDataRole.UserRole))

    def _fill_findings(self):
        if not self.assessment:
            return
        max_rank = {0: 4, 1: 3, 2: 2, 3: 1, 4: 0}[self.min_sev.currentIndex()]
        dev = self.device_filter
        self.shown = [f for f in self.assessment.findings
                      if SEV_RANK[f.severity] <= max_rank and (not dev or f.device == dev)]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.shown))
        for r, f in enumerate(self.shown):
            color = SEV_COLORS[f.severity]
            sev = _sitem(f.severity, SEV_RANK[f.severity], color, bold=True)
            sev.setData(Qt.ItemDataRole.UserRole, r)
            vals = [sev, _item(f.device_label), _item(f.title), _item(f.port or f.service),
                    _item(f.cve_id), _sitem("" if f.cvss is None else f"{f.cvss:.1f}", f.cvss or 0),
                    _item(", ".join(f.attck))]
            vals[2].setToolTip(f.title)
            vals[6].setToolTip("\n".join(attck_mapping.label(t) for t in f.attck))
            for c, it in enumerate(vals):
                self.table.setItem(r, c, it)
        self.table.setSortingEnabled(True)
        self.detail.clear()

    def _finding_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        idx = self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        self.detail.setMarkdown(finding_markdown(self.shown[idx]))


def finding_markdown(f: Finding) -> str:
    lines = [f"## {f.title}", "",
             f"**{f.severity}** · {f.device_label}" + (f" · {f.service}" if f.service else ""), ""]
    meta = []
    if f.cve_id:
        links = ", ".join(f"[{c.strip()}](https://nvd.nist.gov/vuln/detail/{c.strip()})" for c in f.cve_id.split(","))
        meta.append(f"**CVE:** {links}")
    if f.cvss is not None:
        meta.append(f"**CVSS:** {f.cvss:.1f}")
    meta.append(f"**Confidence:** {f.confidence}")
    meta.append(f"**Source:** {f.source}")
    lines += [" · ".join(meta), ""]
    lines += ["### What was found", "", f.description, ""]
    if f.technique:
        lines += ["### How the attack works", "", f.technique, ""]
    lines += ["### How to fix it", "", f.remediation, ""]
    if f.attck:
        lines += ["### MITRE ATT&CK", ""]
        lines += [f"- [{t}]({attck_mapping.url(t)}) {attck_mapping.name(t)}" for t in f.attck]
    return "\n".join(lines)
