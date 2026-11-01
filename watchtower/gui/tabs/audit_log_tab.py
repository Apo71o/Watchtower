from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.gui.context import AppContext
from watchtower.storage.audit_log import Entry

COLS = ["#", "Time (UTC)", "Event", "Command", "Target", "Exit", "Detail"]


class AuditLogTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self.table.horizontalHeader()
        for i in range(len(COLS)):
            hh.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        csv_btn = QPushButton("Export CSV…")
        json_btn = QPushButton("Export JSON…")
        csv_btn.clicked.connect(lambda: self._export("csv"))
        json_btn.clicked.connect(lambda: self._export("json"))
        self.count_lbl = QLabel()
        row = QHBoxLayout()
        row.addWidget(QLabel("Read-only, append-only. Newest first."))
        row.addStretch()
        row.addWidget(self.count_lbl)
        row.addWidget(csv_btn)
        row.addWidget(json_btn)
        lay = QVBoxLayout(self)
        lay.addLayout(row)
        lay.addWidget(self.table)
        ctx.bus.audit_appended.connect(self._prepend)
        self.reload()

    def reload(self):
        entries = self.ctx.audit.entries(limit=5000)
        self.table.setRowCount(0)
        for e in reversed(entries):
            self._prepend(e)

    def _prepend(self, e: Entry):
        self.table.insertRow(0)
        vals = [str(e.id), e.ts, e.event, e.command or "", e.target or "",
                "" if e.exit_code is None else str(e.exit_code), e.detail or ""]
        for col, v in enumerate(vals):
            item = QTableWidgetItem(v)
            item.setToolTip(v)
            self.table.setItem(0, col, item)
        self.count_lbl.setText(f"{self.table.rowCount()} entries")

    def _export(self, fmt: str):
        path, _ = QFileDialog.getSaveFileName(self, "Export audit log", f"watchtower-audit.{fmt}",
                                              f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        data = self.ctx.audit.export_csv() if fmt == "csv" else self.ctx.audit.export_json()
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(data)
