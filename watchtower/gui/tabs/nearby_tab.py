from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import deps, interfaces, wifi_scan
from watchtower.core.platform_utils import WIFI_UNSUPPORTED_REASON
from watchtower.core.runner import format_command
from watchtower.gui.context import AppContext
from watchtower.gui.tabs.interfaces_tab import ask_switch_to_monitor
from watchtower.gui.worker import run_in_background

COLS = ["Authorized", "SSID", "BSSID", "Ch", "Signal", "Security", "Auth", "Cipher", "WPS", "Clients",
        "Connected", "Last seen", "Source"]
MANAGED, MONITOR = "Managed scan (nmcli / iw)", "Monitor-mode listen (airodump-ng)"
BANDS = {"2.4 GHz": "bg", "5 GHz": "a", "2.4 + 5 GHz": "abg"}
WEAK = {"Open": "#c62828", "WEP": "#c62828", "WPA": "#e65100", "WPA/WPA2": "#e65100"}


class NearbyTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.ifaces: list[interfaces.WirelessInterface] = []
        self.connected: set[str] = set()   # BSSIDs we're associated with (from the last managed scan)
        self.rows: list[dict] = []
        self._loading = False

        self.method = QComboBox()
        self.method.addItems([MANAGED, MONITOR])
        self.iface = QComboBox()
        self.tool = QComboBox()
        self.tool_lbl = QLabel("Tool:")
        self.duration = QSpinBox(minimum=5, maximum=3600, value=30, suffix=" s")
        self.band = QComboBox()
        self.band.addItems(list(BANDS))
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setDefault(True)
        self.status = QLabel()
        self.status.setWordWrap(True)
        top = QHBoxLayout()
        top.addWidget(QLabel("Method:"))
        top.addWidget(self.method)
        top.addWidget(self.tool_lbl)
        top.addWidget(self.tool)
        top.addWidget(QLabel("Interface:"))
        top.addWidget(self.iface)
        self.dur_lbl = QLabel("Listen for:")
        top.addWidget(self.dur_lbl)
        top.addWidget(self.duration)
        self.band_lbl = QLabel("Band:")
        top.addWidget(self.band_lbl)
        top.addWidget(self.band)
        top.addWidget(self.scan_btn)
        top.addStretch()

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hh.setStretchLastSection(True)

        self.detail = QLabel("Select a network.")
        self.detail.setWordWrap(True)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.stations = QTableWidget(0, 4)
        self.stations.setHorizontalHeaderLabels(["Client MAC", "Signal (dBm)", "Packets", "Probed SSIDs"])
        self.stations.verticalHeader().setVisible(False)
        self.stations.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.stations.horizontalHeader().setStretchLastSection(True)
        self.investigate_btn = QPushButton("Investigate (scan hosts on this network)…")
        self.forget_btn = QPushButton("Forget unauthorized networks")
        btns = QHBoxLayout()
        btns.addWidget(self.investigate_btn)
        btns.addStretch()
        btns.addWidget(self.forget_btn)
        bottom = QWidget()
        bl = QVBoxLayout(bottom)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(self.detail)
        bl.addWidget(self.stations)
        bl.addLayout(btns)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(bottom)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.status)
        lay.addWidget(split)

        self.method.currentTextChanged.connect(self._method_changed)
        self.tool.currentIndexChanged.connect(lambda _i: self._set_interfaces(self.ifaces))
        self.scan_btn.clicked.connect(self.scan)
        self.table.itemChanged.connect(self._item_changed)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.investigate_btn.clicked.connect(self._investigate)
        self.forget_btn.clicked.connect(self._forget)
        ctx.bus.interfaces_changed.connect(self._set_interfaces)
        ctx.bus.dependencies_changed.connect(self._gate)
        self._method_changed(MANAGED)
        self.reload()
        self._gate()

    # ---- state ----
    def _set_interfaces(self, ifaces):
        self.ifaces = ifaces
        cur = self.iface.currentData()
        self.iface.clear()
        if self.method.currentText() == MANAGED and self._managed_tool() in ("nmcli", None) \
                and deps.find_binary("nmcli"):
            self.iface.addItem("(all)", None)
        for i in ifaces:
            label = f"{i.name} [{i.mode}{', monitor-capable' if i.monitor_capable else ''}]"
            self.iface.addItem(label, i.name)
        idx = self.iface.findData(cur)
        if idx >= 0:
            self.iface.setCurrentIndex(idx)
        elif self.method.currentText() == MONITOR:
            mon = next((n for n, i in enumerate(ifaces) if i.in_monitor_mode), None)
            if mon is not None:
                self.iface.setCurrentIndex(mon)

    def _managed_tool(self) -> str | None:
        return self.tool.currentData()

    def _fill_tools(self):
        cur = self.tool.currentData()
        self.tool.blockSignals(True)
        self.tool.clear()
        avail = wifi_scan.available_managed_tools()
        self.tool.addItem("Auto", None)
        for t in avail:
            self.tool.addItem(t, t)
            self.tool.setItemData(self.tool.count() - 1, wifi_scan.MANAGED_TOOLS[t], Qt.ItemDataRole.ToolTipRole)
        idx = self.tool.findData(cur)
        self.tool.setCurrentIndex(max(idx, 0))
        self.tool.blockSignals(False)

    def _method_changed(self, text):
        mon = text == MONITOR
        for w in (self.duration, self.dur_lbl, self.band, self.band_lbl):
            w.setVisible(mon)
        for w in (self.tool, self.tool_lbl):
            w.setVisible(not mon)
        self._fill_tools()
        self._set_interfaces(self.ifaces)
        self._gate()

    def _gate(self):
        if not self.ctx.platform.wifi_radio_supported:
            self.scan_btn.setEnabled(False)
            self.scan_btn.setToolTip(WIFI_UNSUPPORTED_REASON)
            return
        if self.method.currentText() == MONITOR:
            ok, why = self.ctx.deps.available("airodump-ng"), self.ctx.deps.reason("airodump-ng")
        else:
            ok = bool(wifi_scan.available_managed_tools())
            why = "requires nmcli (network-manager) or iw"
        self.scan_btn.setEnabled(ok)
        self.scan_btn.setToolTip("" if ok else why)

    # ---- scanning ----
    def _selected_iface(self) -> interfaces.WirelessInterface | None:
        name = self.iface.currentData()
        return next((i for i in self.ifaces if i.name == name), None)

    def scan(self):
        if self.method.currentText() == MANAGED:
            iface = self.iface.currentData()
            try:
                argv, tool, needs_root = wifi_scan.managed_scan_argv(iface, self._managed_tool())
            except (ValueError, RuntimeError) as exc:
                QMessageBox.information(self, "Scan", str(exc))
                return
            if needs_root:
                wrapped = deps.elevate(argv)
                if wrapped is None:
                    QMessageBox.warning(self, "Needs root", f"{tool} scan needs root. Pick nmcli, or start "
                                        "Watchtower with sudo.")
                    return
                if QMessageBox.question(self, "Password needed",
                                        f"This scan needs root and will ask for your password:\n\n"
                                        f"{format_command(wrapped)}") != QMessageBox.StandardButton.Yes:
                    return
                argv = wrapped
            self._busy(f"Scanning with {tool}…")
            run_in_background(wifi_scan.managed_scan, self.ctx.runner, iface, tool, argv,
                              on_done=lambda aps: self._scanned(aps, [], "managed"), on_error=self._failed)
            return
        iface = self._selected_iface()
        if iface is None:
            QMessageBox.information(self, "Choose an interface", "Pick a monitor-capable interface first "
                                    "(the Interfaces tab lists them).")
            return
        if not iface.in_monitor_mode:
            if not iface.monitor_capable:
                QMessageBox.warning(self, "Not supported", f"{iface.name} does not support monitor mode.")
                return
            if ask_switch_to_monitor(self.ctx, self, iface):
                self.status.setText("Refresh the Interfaces tab if the mode didn't update, then click Scan again.")
                self.ctx.bus.dependencies_changed.emit()
            return
        try:
            run = wifi_scan.airodump_argv(iface.name, self.duration.value(), BANDS[self.band.currentText()])
        except ValueError as exc:
            QMessageBox.warning(self, "Scan", str(exc))
            return
        argv = run.argv
        if run.needs_password:
            wrapped = deps.elevate(argv)
            if wrapped is None:
                QMessageBox.warning(self, "Needs root",
                                    "airodump-ng needs root or raw-socket capabilities. Use Tools → Dependency "
                                    "Check → Grant raw-socket capabilities, or start Watchtower with sudo.")
                return
            argv = wrapped
        self._busy(f"Listening on {iface.name} for {self.duration.value()} s (passive)…")

        def _work():
            res = self.ctx.runner.run(argv, purpose="passive Wi-Fi listen (airodump-ng)", target=iface.name,
                                      timeout=self.duration.value() + 60)
            aps, stations = wifi_scan.read_airodump_output(run)
            if not aps and not wifi_scan.airodump_ok(res):
                raise RuntimeError(f"airodump-ng failed (exit {res.exit_code}): {res.output.strip()[-400:]}")
            return aps, stations

        run_in_background(_work, on_done=lambda r: self._scanned(r[0], r[1], "airodump-ng"), on_error=self._failed)

    def _busy(self, msg):
        self.scan_btn.setEnabled(False)
        self.status.setText(msg)

    def _failed(self, msg):
        self._gate()
        self.status.setText("Scan failed: " + msg.split("\n\n")[0])

    def _scanned(self, aps, stations, kind):
        self._gate()
        if kind == "managed":
            self.connected = {a.bssid for a in aps if a.in_use}
        self.ctx.networks.record(aps, stations, source="" if kind == "managed" else "airodump-ng")
        self.status.setText(f"Found {len(aps)} network(s)" + (f" and {len(stations)} client(s)" if stations else "")
                            + ". Tick Authorized for networks that are yours.")
        self.reload()
        self.ctx.bus.networks_changed.emit()

    # ---- table ----
    def reload(self):
        self._loading = True
        self.table.setSortingEnabled(False)
        self.rows = self.ctx.networks.all()
        self.table.setRowCount(len(self.rows))
        for r, n in enumerate(self.rows):
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            chk.setCheckState(Qt.CheckState.Checked if n["authorized"] else Qt.CheckState.Unchecked)
            chk.setData(Qt.ItemDataRole.UserRole, n["bssid"])
            self.table.setItem(r, 0, chk)
            sig = f"{n['signal_dbm']} dBm" if n["signal_dbm"] is not None else \
                (f"{n['signal_pct']}%" if n["signal_pct"] is not None else "")
            wps = {1: "yes", 0: "no"}.get(n["wps"], "?")
            vals = [n["ssid"] or "(hidden)", n["bssid"], n["channel"] or "", sig, n["security"], n["auth"] or "",
                    n["cipher"] or "", wps, n["clients"] or "", "●" if n["bssid"] in self.connected else "",
                    (n["last_seen"] or "").replace("T", " ")[:19], n["source"]]
            for c, v in enumerate(vals, start=1):
                item = QTableWidgetItem()
                item.setData(Qt.ItemDataRole.DisplayRole, v)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if c == 5 and n["security"] in WEAK:
                    item.setForeground(QBrush(QColor(WEAK[n["security"]])))
                if c == 8 and n["wps"] == 1:
                    item.setForeground(QBrush(QColor("#e65100")))
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        self._loading = False
        self._selection_changed()

    def _item_changed(self, item):
        if self._loading or item.column() != 0:
            return
        bssid = item.data(Qt.ItemDataRole.UserRole)
        self.ctx.networks.set_authorized(bssid, item.checkState() == Qt.CheckState.Checked)
        self.ctx.bus.networks_changed.emit()
        self._selection_changed()

    def _selected(self) -> dict | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        bssid = self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        return next((n for n in self.ctx.networks.all() if n["bssid"] == bssid), None)

    def _selection_changed(self):
        n = self._selected()
        self.investigate_btn.setEnabled(bool(n and n["authorized"]))
        self.investigate_btn.setToolTip("" if n and n["authorized"] else "Tick Authorized for this network first.")
        if not n:
            self.detail.setText("Select a network.")
            self.stations.setRowCount(0)
            return
        freq = f" ({n['freq']} MHz)" if n["freq"] else ""
        self.detail.setText(
            f"<b>{n['ssid'] or '(hidden)'}</b>  {n['bssid']}  ch {n['channel'] or '?'}"
            f"{freq} · {n['security']} {n['auth'] or ''} "
            f"{n['cipher'] or ''} · first seen {n['first_seen'][:19].replace('T', ' ')}"
            + ("" if n["authorized"] else " · <i>not authorized: visible only</i>"))
        sts = self.ctx.networks.stations_for(n["bssid"])
        self.stations.setRowCount(len(sts))
        for r, s in enumerate(sts):
            for c, v in enumerate([s["mac"], s["power"], s["packets"], s["probes"]]):
                self.stations.setItem(r, c, QTableWidgetItem("" if v is None else str(v)))

    def _investigate(self):
        n = self._selected()
        if not n or not n["authorized"]:
            return
        iface = next((i for i in self.ifaces if i.ssid and i.ssid == n["ssid"] and i.addresses), None)
        if iface is None and n["bssid"] not in self.connected:
            QMessageBox.information(
                self, "Not connected",
                f"Watchtower investigates hosts over your normal connection. Connect to “{n['ssid']}” first "
                "(then refresh the Interfaces tab), or add specific host IPs under Scan a Target.")
            return
        if iface is None:
            iface = next((i for i in self.ifaces if i.addresses and i.mode == "managed"), None)
        subnets = sorted({interfaces.network_of(a) for a in (iface.addresses if iface else []) if ":" not in a})
        if not subnets:
            QMessageBox.information(self, "No address", "Couldn't determine your IP address on this network. "
                                    "Refresh the Interfaces tab, or enter targets manually under Scan a Target.")
            return
        subnet = subnets[0]
        if QMessageBox.question(
                self, "Authorize subnet",
                f"Add {subnet} (your subnet on “{n['ssid']}”) to your authorized targets and open Scan a Target? "
                "Nothing is scanned until you click Run there.") != QMessageBox.StandardButton.Yes:
            return
        self.ctx.targets.add(subnet, note=f"subnet of {n['ssid']}", bssid=n["bssid"])
        self.ctx.bus.targets_changed.emit()
        self.ctx.bus.request_scan.emit(subnet)

    def _forget(self):
        if QMessageBox.question(self, "Forget", "Remove all networks not marked Authorized from the list?") \
                == QMessageBox.StandardButton.Yes:
            self.ctx.networks.forget_unauthorized()
            self.reload()
            self.ctx.bus.networks_changed.emit()
