from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QDockWidget, QMainWindow, QPlainTextEdit, QTabWidget

from watchtower import APP_NAME, __version__
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.gui.context import AppContext
from watchtower.gui.dependency_check import DependencyDialog
from watchtower.gui.help_panel import TabPage
from watchtower.gui.tabs.audit_log_tab import AuditLogTab
from watchtower.gui.tabs.help_tab import HelpTab
from watchtower.gui.tabs.interfaces_tab import InterfacesTab
from watchtower.gui.tabs.nearby_tab import NearbyTab
from watchtower.gui.tabs.placeholder import PlaceholderTab
from watchtower.gui.tabs.scan_tab import ScanTab
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

        self.interfaces_tab = InterfacesTab(ctx)
        add("interfaces", "Interfaces", self.interfaces_tab)
        self.nearby_tab = NearbyTab(ctx)
        add("nearby", "Nearby Networks", self.nearby_tab, tooltip=wifi_reason, enabled=wifi_reason is None)
        self.scan_tab = ScanTab(ctx)
        add("scan", "Scan a Target", self.scan_tab)
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
        ctx.bus.request_scan.connect(lambda _t: self.tabs.setCurrentWidget(self.pages["scan"]))

        # Menus
        tools = self.menuBar().addMenu("&Tools")
        dep_action = QAction("Dependency Check…", self)
        dep_action.triggered.connect(self.show_dependency_check)
        tools.addAction(dep_action)

        self.statusBar().showMessage(ctx.platform.summary())

    def _show_command(self, command: str, purpose: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{ts}] {purpose}\n  $ {command}")
        self.statusBar().showMessage(f"Running: {command}", 8000)

    def show_dependency_check(self):
        dlg = DependencyDialog(self.ctx, self)
        dlg.exec()
        self.ctx.settings.set(DEPS_REVIEWED, True)

    def first_run(self):
        """Show the dependency check once, on the very first launch."""
        if not self.ctx.settings.get(DEPS_REVIEWED):
            self.show_dependency_check()
