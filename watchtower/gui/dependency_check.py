"""Dependency Check screen: what's installed, what's missing, and the exact
commands to fix it. Nothing runs without an explicit confirmation."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import deps
from watchtower.core.platform_utils import is_linux, is_windows
from watchtower.gui.context import AppContext
from watchtower.gui.help_panel import TabPage
from watchtower.gui.worker import run_in_background
from watchtower.storage.audit_log import Event

COLS = ["Tool", "Status", "Version", "Used for", "Install"]


class ConfirmCommandsDialog(QDialog):
    """Shows the full command list and requires an explicit OK."""

    def __init__(self, title: str, intro: str, commands: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(620)
        text = QPlainTextEdit(commands, readOnly=True)
        text.setMinimumHeight(140)
        intro_lbl = QLabel(intro)
        intro_lbl.setWordWrap(True)
        copy = QPushButton("Copy commands")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(commands))
        buttons = QDialogButtonBox()
        self.run_btn = buttons.addButton("Run these commands", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(intro_lbl)
        lay.addWidget(text)
        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch()
        row.addWidget(buttons)
        lay.addLayout(row)


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
        self.install_btn.setEnabled(bool(self._install_argvs(missing)))
        self.setcap_btn.setEnabled(bool(deps.setcap_argvs(statuses)))
        self.status_lbl.setText(
            f"{len(statuses) - len(missing)}/{len(statuses)} tools present. "
            + (f"Missing required: {', '.join(s.tool.name for s in required_missing)}. "
               "Features that need them are grayed out." if required_missing else
               "All required tools present.")
        )

    # ---- installing (always confirmed) ----
    def _install_argvs(self, missing):
        if is_linux():
            argv = deps.apt_install_argv(missing)
            return [argv] if argv else []
        if is_windows():
            return deps.winget_install_argvs(missing)
        return []

    def _install(self):
        missing = [s for s in self.statuses if not s.present]
        argvs = self._install_argvs(missing)
        if not argvs:
            return
        needs_sudo = is_linux()
        plan = deps.describe_plan(argvs, elevated=needs_sudo)
        manual = [s for s in missing if (is_linux() and not s.tool.apt_package)
                  or (is_windows() and not s.tool.winget_id)]
        intro = ("These commands will install the missing tools"
                 + (" with administrator rights (you will be asked for your password)." if needs_sudo else ".")
                 + " Review them before running.")
        if manual:
            intro += ("\n\nNot covered by a package manager (install by hand): "
                      + "; ".join(f"{s.tool.name}: {s.install_hint}" for s in manual))
        self._confirm_and_run("Install missing tools", intro, plan, argvs, needs_sudo)

    def _setcap(self):
        argvs = deps.setcap_argvs(self.statuses)
        intro = ("Grants raw-socket capabilities to these specific binaries so they can run "
                 "without running Watchtower as root. Any local user will be able to use "
                 "these binaries with raw sockets afterward. Note: nmap must then be run with "
                 "--privileged, which Watchtower does automatically.")
        self._confirm_and_run("Grant capabilities", intro, deps.describe_plan(argvs, True), argvs, True)

    def _confirm_and_run(self, title, intro, plan, argvs, needs_elevation):
        dlg = ConfirmCommandsDialog(title, intro, plan, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self.ctx.audit.append(Event.DECLINED, command=plan, detail={"action": title})
            return
        self.ctx.audit.append(Event.CONFIRMATION, command=plan, detail={"action": title})
        if needs_elevation:
            wrapped = [deps.elevate(a) for a in argvs]
            if any(w is None for w in wrapped):
                QMessageBox.information(
                    self, title,
                    "No graphical password prompt (pkexec) is available, so Watchtower will not "
                    "escalate privileges itself. Run these in a terminal:\n\n" + plan)
                return
            argvs = wrapped
        self.status_lbl.setText("Running… (see the Command Console below)")

        def _run_all():
            return [self.ctx.runner.run(a, purpose=title, timeout=1800) for a in argvs]

        def _done(results):
            failed = [r for r in results if not r.ok]
            if failed:
                QMessageBox.warning(self, title, "Some commands failed:\n\n" + "\n\n".join(
                    f"$ {r.command}\nexit {r.exit_code}\n{r.output[-1500:]}" for r in failed))
            self.refresh()

        run_in_background(_run_all, on_done=_done,
                          on_error=lambda m: QMessageBox.warning(self, title, m))


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

