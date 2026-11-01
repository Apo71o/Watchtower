from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QDockWidget, QLabel, QMainWindow, QPlainTextEdit, QTabWidget

from watchtower import APP_NAME, __version__
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.gui.auth_gate import AuthGateDialog
from watchtower.gui.context import AppContext
from watchtower.gui.dependency_check import DependencyDialog
from watchtower.gui.help_panel import TabPage
from watchtower.gui.tabs.audit_log_tab import AuditLogTab
from watchtower.gui.tabs.help_tab import HelpTab
from watchtower.gui.tabs.placeholder import PlaceholderTab
from watchtower.gui.tabs.settings_tab import SettingsTab
from watchtower.storage.settings import DEPS_REVIEWED


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext):
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self.resize(1280, 820)

        wifi_reason = None if ctx.platform.wifi_radio_supported else WIFI_UNSUPPORTED_REASON
        self.tabs = QTabWidget()
        self.pages: dict[str, TabPage] = {}

        def add(key, label, widget, help_key=None, tooltip=None, enabled=True):
            page = TabPage(widget, help_key or key)
            idx = self.tabs.addTab(page, label)
            self.pages[key] = page
            if tooltip:
                self.tabs.setTabToolTip(idx, tooltip)
            if not enabled:
                self.tabs.setTabEnabled(idx, False)

        add("interfaces", "Interfaces",
            PlaceholderTab(ctx, "Interfaces", "step 2", ["iw"], "List wireless interfaces",
                           disabled_reason=wifi_reason))
        add("nearby", "Nearby Networks",
            PlaceholderTab(ctx, "Nearby Networks", "step 2", ["iw", "airodump-ng"], "Passive scan",
                           disabled_reason=wifi_reason),
            tooltip=wifi_reason, enabled=wifi_reason is None)
        add("scan", "Scan a Target",
            PlaceholderTab(ctx, "Scan a Target", "step 3", ["nmap"], "Run nmap"))
        add("findings", "Findings",
            PlaceholderTab(ctx, "Findings", "steps 4, 5, 7", [], "Show findings"))
        add("host_audit", "Host Audit",
            PlaceholderTab(ctx, "Host Audit", "step 6", ["sslyze", "snmp"], "Audit host"))
        add("changes", "What Changed",
            PlaceholderTab(ctx, "What Changed", "step 8", ["nmap"], "Compare scans"))
        self.audit_tab = AuditLogTab(ctx)
        add("audit_log", "Audit Log", self.audit_tab)
        self.help_tab = HelpTab(ctx)
        add("help", "Help", self.help_tab, help_key="help")
        self.pages["help"].help.toggle.setChecked(False)
        self.settings_tab = SettingsTab(ctx)
        add("settings", "Settings", self.settings_tab)
        self.setCentralWidget(self.tabs)

        # Command console: every command is displayed here as it starts.
        self.console = QPlainTextEdit(readOnly=True)
        self.console.setMaximumBlockCount(2000)
        self.console.setPlaceholderText("Every external command Watchtower runs appears here "
                                        "before it starts, exactly as executed.")
        dock = QDockWidget("Command Console", self)
        dock.setObjectName("command_console")
        dock.setWidget(self.console)
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable
                         | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)
        self.resizeDocks([dock], [150], Qt.Orientation.Vertical)
        ctx.bus.command_started.connect(self._show_command)

        # Menus
        tools = self.menuBar().addMenu("&Tools")
        dep_action = QAction("Dependency Check…", self)
        dep_action.triggered.connect(self.show_dependency_check)
        tools.addAction(dep_action)

        self.lock_lbl = QLabel()
        self.statusBar().addPermanentWidget(self.lock_lbl)
        self.statusBar().showMessage(ctx.platform.summary())
        ctx.bus.authorization_changed.connect(lambda _: self._refresh_lock())
        self._refresh_lock()

    def _show_command(self, command: str, purpose: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{ts}] {purpose}\n  $ {command}")
        self.statusBar().showMessage(f"Running: {command}", 8000)

    def _refresh_lock(self):
        if self.ctx.authorized:
            self.lock_lbl.setText("Scanning: unlocked")
            self.lock_lbl.setStyleSheet("color: #2e7d32; padding: 0 8px;")
        else:
            self.lock_lbl.setText("Scanning: LOCKED (accept authorization in Settings)")
            self.lock_lbl.setStyleSheet("color: #c62828; font-weight: bold; padding: 0 8px;")

    def show_dependency_check(self):
        dlg = DependencyDialog(self.ctx, self)
        dlg.exec()
        self.ctx.settings.set(DEPS_REVIEWED, True)

    def first_run(self):
        """Authorization gate, then dependency check, each only until handled once."""
        if not self.ctx.authorized:
            AuthGateDialog(self.ctx, self).exec()
        if not self.ctx.settings.get(DEPS_REVIEWED):
            self.show_dependency_check()
