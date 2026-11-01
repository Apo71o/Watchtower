from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import interfaces
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.gui.context import AppContext
from watchtower.gui.run_dialog import RunPlanDialog
from watchtower.gui.worker import run_in_background

COLS = ["Interface", "Mode", "Monitor mode", "Driver", "MAC", "Connected to", "Channel", "IP addresses"]


class InterfacesTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.ifaces: list[interfaces.WirelessInterface] = []
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.refresh_btn = QPushButton("Refresh")
        self.monitor_btn = QPushButton("Enable monitor mode…")
        self.managed_btn = QPushButton("Return to managed mode…")
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.refresh_btn.clicked.connect(self.refresh)
        self.monitor_btn.clicked.connect(lambda: self._set_mode("monitor"))
        self.managed_btn.clicked.connect(lambda: self._set_mode("managed"))
        self.table.itemSelectionChanged.connect(self._update_buttons)
        row = QHBoxLayout()
        for b in (self.refresh_btn, self.monitor_btn, self.managed_btn):
            row.addWidget(b)
        row.addStretch()
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<h3>Wireless interfaces</h3>"))
        lay.addWidget(self.table)
        lay.addLayout(row)
        lay.addWidget(self.status)
        ctx.bus.dependencies_changed.connect(self._gate)
        self._gate()

    def _gate(self):
        if not self.ctx.platform.wifi_radio_supported:
            for w in (self.refresh_btn, self.monitor_btn, self.managed_btn):
                w.setEnabled(False)
                w.setToolTip(WIFI_UNSUPPORTED_REASON)
            self.status.setText(WIFI_UNSUPPORTED_REASON)
            return
        ok = self.ctx.deps.available("iw")
        self.refresh_btn.setEnabled(ok)
        self.refresh_btn.setToolTip("" if ok else self.ctx.deps.reason("iw"))
        if ok and not self.ifaces:
            self.refresh()
        elif not ok:
            self.status.setText(self.ctx.deps.reason("iw"))
        self._update_buttons()

    def refresh(self):
        self.status.setText("Reading interfaces…")
        self.refresh_btn.setEnabled(False)
        run_in_background(interfaces.list_wireless, self.ctx.runner, on_done=self._populate, on_error=self._error)

    def _error(self, msg):
        self.refresh_btn.setEnabled(True)
        self.status.setText(msg.split("\n\n")[0])

    def _populate(self, ifaces):
        self.refresh_btn.setEnabled(True)
        self.ifaces = ifaces
        self.table.setRowCount(len(ifaces))
        for r, i in enumerate(ifaces):
            vals = [i.name, i.mode, "yes" if i.monitor_capable else "no", i.driver, i.mac, i.ssid,
                    f"{i.channel} ({i.freq} MHz)" if i.channel else "", ", ".join(i.addresses)]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        if ifaces and not self.table.selectedItems():
            self.table.selectRow(0)
        capable = [i.name for i in ifaces if i.monitor_capable]
        self.status.setText(
            "No wireless interfaces found." if not ifaces else
            f"{len(ifaces)} wireless interface(s). Monitor-capable: {', '.join(capable) or 'none'}."
            + ("" if capable else " Monitor-mode listening needs a USB adapter whose driver supports it."))
        self._update_buttons()
        self.ctx.bus.interfaces_changed.emit(ifaces)

    def selected(self) -> interfaces.WirelessInterface | None:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        return self.ifaces[rows[0].row()] if rows and rows[0].row() < len(self.ifaces) else None

    def _update_buttons(self):
        i = self.selected()
        linux = self.ctx.platform.wifi_radio_supported
        self.monitor_btn.setEnabled(bool(linux and i and i.monitor_capable and not i.in_monitor_mode))
        self.managed_btn.setEnabled(bool(linux and i and i.in_monitor_mode))
        if i and not i.monitor_capable:
            self.monitor_btn.setToolTip(f"{i.name}'s driver ({i.driver or 'unknown'}) does not support monitor mode.")
        else:
            self.monitor_btn.setToolTip("")

    def _set_mode(self, mode: str):
        i = self.selected()
        if not i:
            return
        plan = interfaces.set_mode_plan(i.name, mode)
        if mode == "monitor":
            intro = (f"Switch {i.name} to monitor mode. While in monitor mode it is disconnected from Wi-Fi"
                     + (f" (currently connected to “{i.ssid}”)" if i.ssid else "")
                     + ", and NetworkManager is told to leave it alone. Use “Return to managed mode” afterwards.")
        else:
            intro = f"Switch {i.name} back to managed mode and hand it back to NetworkManager so it can reconnect."
        dlg = RunPlanDialog(self.ctx, f"{mode.capitalize()} mode: {i.name}", intro, plan, self)
        dlg.exec()
        self.refresh()


def ask_switch_to_monitor(ctx: AppContext, parent, iface: interfaces.WirelessInterface) -> bool:
    """Used by Nearby Networks: offer to switch an interface into monitor mode."""
    if QMessageBox.question(parent, "Monitor mode needed",
                            f"{iface.name} is in {iface.mode or 'unknown'} mode. Listening with airodump-ng needs "
                            f"monitor mode, which disconnects it from Wi-Fi. Switch it now?") \
            != QMessageBox.StandardButton.Yes:
        return False
    dlg = RunPlanDialog(ctx, f"Monitor mode: {iface.name}",
                        "Switch the interface to monitor mode (asks for your password).",
                        interfaces.set_mode_plan(iface.name, "monitor"), parent)
    dlg.exec()
    return True
