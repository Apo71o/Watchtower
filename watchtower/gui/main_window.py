from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QDockWidget, QMainWindow, QPlainTextEdit, QStyle, QSystemTrayIcon, QTabWidget

from watchtower import APP_NAME, __version__
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.gui.context import AppContext
from watchtower.gui.dependency_check import DependencyDialog
from watchtower.gui.help_panel import TabPage
from watchtower.gui.tabs.audit_log_tab import AuditLogTab
from watchtower.gui.tabs.changes_tab import ChangesTab
from watchtower.gui.tabs.domain_audit_tab import DomainAuditTab
from watchtower.gui.tabs.findings_tab import FindingsTab
from watchtower.gui.tabs.help_tab import HelpTab
from watchtower.gui.tabs.host_audit_tab import HostAuditTab
from watchtower.gui.tabs.interfaces_tab import InterfacesTab
from watchtower.gui.tabs.nearby_tab import NearbyTab
from watchtower.gui.tabs.password_tab import PasswordTab
from watchtower.gui.tabs.scan_tab import ScanTab
from watchtower.gui.tabs.settings_tab import SettingsTab
from watchtower.gui.tabs.traffic_tab import TrafficTab
from watchtower.gui.tabs.web_audit_tab import WebAuditTab
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
        self.findings_tab = FindingsTab(ctx)
        add("findings", "Findings", self.findings_tab)
        self.pages["findings"].help.toggle.setChecked(False)   # the detail pane explains each finding
        self.host_audit_tab = HostAuditTab(ctx)
        add("host_audit", "Host Audit", self.host_audit_tab)
        self.web_audit_tab = WebAuditTab(ctx)
        add("web_audit", "Web Audit", self.web_audit_tab)
        self.domain_audit_tab = DomainAuditTab(ctx)
        add("domain_audit", "Domain Audit", self.domain_audit_tab)
        self.traffic_tab = TrafficTab(ctx)
        add("traffic", "Traffic Audit", self.traffic_tab)
        self.changes_tab = ChangesTab(ctx)
        add("changes", "What Changed", self.changes_tab)
        self.password_tab = PasswordTab(ctx)
        add("passwords", "Password Tools", self.password_tab)
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
        report_action = QAction("Export report…", self)
        report_action.triggered.connect(lambda: self.findings_tab.export_report())
        tools.addAction(report_action)

        self.statusBar().showMessage(ctx.platform.summary())

    def notify(self, title: str, message: str):
        """Desktop notification (tray balloon where available) plus the status bar."""
        self.statusBar().showMessage(f"{title}: {message}", 30000)
        if QSystemTrayIcon.isSystemTrayAvailable():
            if not hasattr(self, "_tray"):
                self._tray = QSystemTrayIcon(self.windowIcon() or self.style().standardIcon(
                    QStyle.StandardPixmap.SP_MessageBoxWarning), self)
                self._tray.show()
            self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Warning, 10000)

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
