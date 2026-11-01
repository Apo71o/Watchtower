"""Dependency Check screen: what's installed, what's missing, and the exact
commands to fix it. Nothing runs without an explicit confirmation."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import deps
from watchtower.core.platform_utils import is_linux
from watchtower.gui.context import AppContext
from watchtower.gui.help_panel import TabPage
from watchtower.gui.run_dialog import RunPlanDialog
from watchtower.gui.worker import run_in_background

COLS = ["Tool", "Status", "Version", "Used for", "Install"]


class DependencyWidget(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.statuses: list[deps.ToolStatus] = []
        self.platform_lbl = QLabel(f"Platform: {ctx.platform.summary()}")
        self.platform_lbl.setWordWrap(True)
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(True)
        hh = self.table.horizontalHeader()
        for i in (0, 1, 2):
            hh.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.refresh_btn = QPushButton("Re-check")
        self.install_btn = QPushButton("Run these install commands for me…")
        self.setcap_btn = QPushButton("Grant raw-socket capabilities (setcap)…")
        self.setcap_btn.setVisible(is_linux())
        self.status_lbl = QLabel()
        self.refresh_btn.clicked.connect(self.refresh)
        self.install_btn.clicked.connect(self._install)
        self.setcap_btn.clicked.connect(self._setcap)

        btns = QHBoxLayout()
        btns.addWidget(self.refresh_btn)
        btns.addWidget(self.install_btn)
        btns.addWidget(self.setcap_btn)
        btns.addStretch()
        lay = QVBoxLayout(self)
        lay.addWidget(self.platform_lbl)
        lay.addWidget(self.table)
        lay.addLayout(btns)
        lay.addWidget(self.status_lbl)

    # ---- checking ----
    def refresh(self):
        self.status_lbl.setText("Checking installed tools…")
        self.refresh_btn.setEnabled(False)
        run_in_background(deps.check_all, self.ctx.runner, on_done=self._populate,
                          on_error=self._error)

    def _error(self, msg: str):
        self.refresh_btn.setEnabled(True)
        self.status_lbl.setText(f"Dependency check failed: {msg.splitlines()[0]}")

    def _populate(self, statuses: list[deps.ToolStatus]):
        self.refresh_btn.setEnabled(True)
        self.statuses = statuses
        self.ctx.deps.update(statuses)
        self.ctx.bus.dependencies_changed.emit()
        self.table.setRowCount(len(statuses))
        ok_color, missing_color, opt_color = QColor("#2e7d32"), QColor("#c62828"), QColor("#9e6a00")
        for row, s in enumerate(statuses):
            name = s.tool.name + ("" if not s.tool.optional else "  (optional)")
            if s.present:
                state, color = "installed", ok_color
            elif s.installable is False:
                state, color = "not packaged", QColor("#757575")
            elif s.tool.optional:
                state, color = "not installed", opt_color
            else:
                state, color = "MISSING", missing_color
            purpose = s.tool.purpose + (f"\n{s.tool.note}" if s.tool.note else "")
            values = [name, state, s.version or "", purpose, "" if s.present else s.install_hint]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if col == 1:
                    item.setForeground(QBrush(color))
                item.setToolTip(s.path if (col == 0 and s.path) else val)
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()
        missing = [s for s in statuses if not s.present]
        required_missing = [s for s in missing if not s.tool.optional]
        plan = self._install_plan()
        self.install_btn.setEnabled(bool(plan.steps))
        self.install_btn.setToolTip("" if plan.steps else "Nothing installable automatically is missing.")
        self.setcap_btn.setEnabled(bool(deps.setcap_plan(statuses).steps))
        self.status_lbl.setText(
            f"{len(statuses) - len(missing)}/{len(statuses)} tools present. "
            + (f"Missing required: {', '.join(s.tool.name for s in required_missing)}. "
               "Features that need them are grayed out." if required_missing else
               "All required tools present.")
        )

    # ---- installing (always confirmed) ----
    def _install_plan(self):
        return deps.install_plan([s for s in self.statuses if not s.present])

    def _install(self):
        plan = self._install_plan()
        intro = ("These commands install the missing tools. Steps marked sudo ask for your password "
                 "(a password window, or a terminal if no password window is available). "
                 "Output is shown live below once you click Run.")
        self._run_plan("Install missing tools", intro, plan)

    def _setcap(self):
        intro = ("Grants raw-socket capabilities to these specific binaries so they work at full "
                 "capability without running Watchtower as root. Watchtower then passes --privileged "
                 "to nmap automatically. Any local user can use these binaries with raw sockets afterward.")
        self._run_plan("Grant capabilities", intro, deps.setcap_plan(self.statuses))

    def _run_plan(self, title, intro, plan):
        dlg = RunPlanDialog(self.ctx, title, intro, plan, self)
        dlg.finished_ok.connect(lambda _ok: self.refresh())
        dlg.exec()
        self.refresh()


class DependencyDialog(QDialog):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Watchtower: dependency check")
        self.resize(1050, 560)
        self.widget = DependencyWidget(ctx)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.accept)
        close.button(QDialogButtonBox.StandardButton.Close).clicked.connect(self.accept)
        lay = QVBoxLayout(self)
        lay.addWidget(TabPage(self.widget, "deps"))
        lay.addWidget(close)
        self.widget.refresh()

