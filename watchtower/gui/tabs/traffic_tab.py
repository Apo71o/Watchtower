"""Traffic Audit tab: capture live traffic or open a capture file, then explain what it shows.

Laid out as three numbered steps so it reads top to bottom:
  1. Choose what to analyze (live capture, or a file)
  2. (Optional) repeat the capture automatically
  3. Results: findings in plain language, a traffic overview, and the raw tool output
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import deps, scheduler
from watchtower.core import traffic_audit as ta
from watchtower.core import traffic_hosts as th
from watchtower.core.findings_engine import SEV_RANK, latest_hosts
from watchtower.core.runner import format_command
from watchtower.gui.context import AppContext
from watchtower.gui.ui import follow, restore_tip, set_combo, tip
from watchtower.gui.worker import run_in_background
from watchtower.storage import preferences as prefs

SEV_ICON = {"Critical": "🔴", "High": "🔴", "Medium": "🟠", "Low": "🟡", "Info": "🔵"}


OPEN_TIP = ("Analyze a capture made earlier with Wireshark, tcpdump, your router's packet capture page, or "
            "Watchtower. The file isn't changed or copied.")


class _Signals(QObject):
    done = Signal()

    def emit(self):
        self.done.emit()


class _Lines(QObject):
    line = Signal(str)


DISCOVER_TIP = ("After the capture, run a quick nmap ping scan (nmap -sn) of the interface's network, so devices "
                "that stayed quiet while Watchtower listened also appear under Devices. This sends packets, so it "
                "only works when that network is in your authorized targets.")


def _label(text: str, tip: str = "") -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    if tip:
        lbl.setToolTip(tip)
    return lbl


class TrafficTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.cancel_event: threading.Event | None = None
        self._lines = _Lines()
        self._ping_done = _Signals()          # ping scan stored -> refresh Findings, Scan history
        self._deadline = 0.0
        self._monitor: set[str] = set()
        self._nets: dict[str, list[str]] = {}       # interface -> its networks (for the device view / ping scan)

        intro = _label("Listen to the traffic on your network (or open a saved capture) and find passwords sent "
                       "without encryption, risky Windows name lookups, old protocols and more. Listening sends "
                       "nothing. Wi-Fi handshake frames are always filtered out.")

        # ---- step 1a: live capture ----
        live = QGroupBox("1. Capture live traffic")
        self.iface = QComboBox()
        self.iface.setToolTip("The network connection to listen on. Pick the one connected to the network you want "
                              "to check (usually your Ethernet or Wi-Fi adapter). 'lo' only sees this computer's "
                              "own internal traffic.")
        self.refresh_ifaces_btn = QPushButton("↻")
        self.refresh_ifaces_btn.setToolTip("Refresh the list of network interfaces")
        self.refresh_ifaces_btn.setFixedWidth(32)
        self.duration = QComboBox()
        self.duration.addItems(list(ta.DURATIONS))
        follow(ctx, prefs.TRAFFIC_DURATION, lambda v: set_combo(self.duration, v))
        self.duration.setToolTip("How long to listen. Longer captures catch more (devices that only log in now and "
                                 "then); 1-5 minutes is a good start.")
        self.max_packets = QSpinBox(minimum=0, maximum=10_000_000, value=0, singleStep=1000)
        self.max_packets.setSpecialValueText("No limit")
        self.max_packets.setToolTip("Stop early after this many packets (keeps the file small on a busy network).")
        self.filter = QLineEdit(placeholderText="optional, e.g.  host 192.168.1.20   or   port 21")
        self.filter.setToolTip("A capture filter (BPF syntax, same as tcpdump/Wireshark capture filters) to record "
                               "only some traffic. Leave empty to record everything. Watchtower always adds "
                               "'not ether proto 0x888e' so Wi-Fi handshakes are never recorded.")
        self.discover = QCheckBox("Also find quiet devices (quick ping scan of my network afterwards)")
        tip(self.discover, DISCOVER_TIP)
        self.start_btn = QPushButton("Start capture")
        self.start_btn.setToolTip("Start listening on the chosen interface for the chosen time, then analyze it.")
        self.perm = _label("")
        self.perm_btn = QPushButton("Allow capturing…")
        self.perm_btn.setToolTip("One-time setup: lets dumpcap capture packets without running Watchtower as root "
                                 "(runs setcap on dumpcap after showing you the command and asking for your password).")
        irow = QHBoxLayout()
        irow.addWidget(self.iface, 1)
        irow.addWidget(self.refresh_ifaces_btn)
        lf = QFormLayout(live)
        lf.addRow("Interface:", irow)
        lf.addRow("Listen for:", self.duration)
        lf.addRow("Stop after:", self.max_packets)
        lf.addRow("Only record:", self.filter)
        lf.addRow(self.discover)
        prow = QHBoxLayout()
        prow.addWidget(self.perm, 1)
        prow.addWidget(self.perm_btn)
        lf.addRow(prow)
        lf.addRow(self.start_btn)

        # ---- step 1b: open a file ----
        filebox = QGroupBox("…or open a capture file")
        self.open_btn = QPushButton("Open .pcap / .pcapng file…")
        self.open_btn.setToolTip(OPEN_TIP)
        ff = QVBoxLayout(filebox)
        ff.addWidget(_label("Already have a capture from Wireshark, tcpdump or your router? Watchtower analyzes it "
                            "the same way. Nothing is sent anywhere."))
        ff.addWidget(self.open_btn)
        ff.addStretch()

        # ---- step 2: repeat ----
        rep = QGroupBox("2. Repeat automatically (optional)")
        self.every = QComboBox()
        self.every.addItems(list(scheduler.INTERVALS))
        follow(ctx, prefs.SCHEDULE_INTERVAL, lambda v: set_combo(self.every, v))
        self.every.setToolTip("How often to repeat the capture.")
        self.add_sched_btn = QPushButton("Repeat this capture")
        self.add_sched_btn.setToolTip("Save the interface, length and filter from step 1 as a repeating capture. "
                                      "Each run is compared with the previous one in What Changed.")
        self.sched_table = QTableWidget(0, 6)
        self.sched_table.setHorizontalHeaderLabels(["On", "Interface", "Length", "Every", "Next run", "Last result"])
        self.sched_table.verticalHeader().setVisible(False)
        self.sched_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sched_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.sched_table.setToolTip("Repeating captures. Untick 'On' to pause one.")
        sh = self.sched_table.horizontalHeader()
        sh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        sh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.sched_table.setMaximumHeight(110)
        self.sched_run_btn = QPushButton("Run now")
        self.sched_run_btn.setToolTip("Run the selected repeating capture right away.")
        self.sched_rm_btn = QPushButton("Remove")
        self.sched_rm_btn.setToolTip("Delete the selected repeating capture (past results are kept).")
        rl = QVBoxLayout(rep)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Every:"))
        r1.addWidget(self.every)
        r1.addWidget(self.add_sched_btn)
        r1.addStretch()
        r1.addWidget(self.sched_run_btn)
        r1.addWidget(self.sched_rm_btn)
        rl.addLayout(r1)
        self.no_sched = _label("<i>No repeating captures yet. Set up step 1, pick how often, then click "
                               "'Repeat this capture'.</i>")
        rl.addWidget(self.no_sched)
        rl.addWidget(self.sched_table)
        rl.addWidget(_label("<small>Repeats run while Watchtower is open (or in the background if you turned that "
                            "on in What Changed). They need capture permission, because they never ask for a "
                            "password.</small>"))

        top = QHBoxLayout()
        top.addWidget(live, 3)
        top.addWidget(filebox, 2)

        # ---- progress ----
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFormat("%v s left")
        self.cancel_btn = QPushButton("Stop")
        self.cancel_btn.setToolTip("Stop the capture now and analyze what was recorded so far.")
        self.cancel_btn.setEnabled(False)
        self.status = _label("")
        srow = QHBoxLayout()
        srow.addWidget(self.cancel_btn)
        srow.addWidget(self.progress)
        srow.addWidget(self.status, 1)

        # ---- step 3: results ----
        self.cap_list = QListWidget()
        self.cap_list.setToolTip("Every capture you've made or opened, newest first. Select one to see its results.")
        self.wireshark_btn = QPushButton("Open in Wireshark")
        self.wireshark_btn.setToolTip("Open the selected capture in Wireshark to inspect it packet by packet.")
        self.folder_btn = QPushButton("Show file")
        self.folder_btn.setToolTip("Open the folder containing the capture file.")
        self.reanalyze_btn = QPushButton("Analyze again")
        self.reanalyze_btn.setToolTip("Run the analysis on the selected capture file again (for example after it "
                                      "failed, or after updating Watchtower). Doesn't capture anything new.")
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setToolTip("Remove the selected capture from Watchtower. Files Watchtower recorded are "
                                   "deleted from disk; files you opened are left untouched.")
        ll = QVBoxLayout()
        ll.addWidget(QLabel("<b>3. Results</b> (captures)"))
        ll.addWidget(self.cap_list)
        b1 = QHBoxLayout()
        b1.addWidget(self.wireshark_btn)
        b1.addWidget(self.folder_btn)
        b1.addWidget(self.reanalyze_btn)
        b1.addWidget(self.delete_btn)
        ll.addLayout(b1)
        left = QWidget()
        left.setLayout(ll)

        self.findings_view = QTextBrowser(openExternalLinks=True)
        self.overview = QTextBrowser()
        self.output = QPlainTextEdit(readOnly=True)
        self.output.setFont(QFont("monospace"))
        self.output.setMaximumBlockCount(5000)
        self.tabs = QTabWidget()
        self.devices = DevicesView(ctx)
        self.tabs.addTab(self.findings_view, "What was found")
        self.tabs.addTab(self.devices, "Devices")
        self.tabs.addTab(self.overview, "Traffic overview")
        self.tabs.addTab(self.output, "Live output")
        self.tabs.setTabToolTip(0, "Problems found in the capture, in plain language, with how to fix each one.")
        self.tabs.setTabToolTip(1, "Every address in the capture: who it is, what it talked to, which names and "
                                   "sites it asked for, and its problems.")
        self.tabs.setTabToolTip(2, "Who talked to whom and which protocols were used.")
        self.tabs.setTabToolTip(3, "The exact commands Watchtower ran and their messages.")

        split = QSplitter()
        split.addWidget(left)
        split.addWidget(self.tabs)
        split.setStretchFactor(1, 3)
        split.setSizes([300, 900])

        upper = QWidget()
        ul = QVBoxLayout(upper)
        ul.setContentsMargins(0, 0, 0, 0)
        ul.addWidget(intro)
        ul.addLayout(top)
        ul.addWidget(rep)
        ul.addLayout(srow)
        vsplit = QSplitter(Qt.Orientation.Vertical)
        vsplit.addWidget(upper)
        vsplit.addWidget(split)
        vsplit.setStretchFactor(0, 0)
        vsplit.setStretchFactor(1, 1)
        vsplit.setChildrenCollapsible(False)
        upper.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self._vsplit, self._upper, self._fitted = vsplit, upper, False
        lay = QVBoxLayout(self)
        lay.addWidget(vsplit)

        self.refresh_ifaces_btn.clicked.connect(self.load_interfaces)
        self.start_btn.clicked.connect(self.start_capture)
        self.open_btn.clicked.connect(lambda: self.open_file())
        self.perm_btn.clicked.connect(self.grant_permission)
        self.cancel_btn.clicked.connect(lambda: self.cancel_event and self.cancel_event.set())
        self.cap_list.currentItemChanged.connect(lambda *_: self.render())
        self.wireshark_btn.clicked.connect(self.open_in_wireshark)
        self.folder_btn.clicked.connect(self.show_file)
        self.delete_btn.clicked.connect(self.delete_capture)
        self.reanalyze_btn.clicked.connect(self.reanalyze)
        self.add_sched_btn.clicked.connect(self.add_schedule)
        self.sched_rm_btn.clicked.connect(self.remove_schedule)
        self.sched_run_btn.clicked.connect(self.run_schedule_now)
        self.sched_table.itemChanged.connect(self._sched_item_changed)
        self.sched_table.itemSelectionChanged.connect(self._gate)
        self._lines.line.connect(self.output.appendPlainText)
        self._ping_done.done.connect(ctx.bus.scan_finished.emit)
        ctx.bus.captures_changed.connect(self.reload)
        ctx.bus.scan_finished.connect(self.render)          # host names for addresses
        ctx.bus.dependencies_changed.connect(self._gate)
        ctx.bus.interfaces_changed.connect(self._interfaces_changed)
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._tick)

        self.load_interfaces()
        follow(ctx, prefs.TRAFFIC_INTERFACE, self._prefer_interface)
        follow(ctx, prefs.TRAFFIC_DISCOVER, lambda v: self.discover.setChecked(v and self.discover.isEnabled()))
        self.reload()

    def showEvent(self, event):
        super().showEvent(event)
        if not self._fitted:      # give the results everything the steps above don't need
            self._fitted = True
            self._vsplit.setSizes([self._upper.sizeHint().height(), 10_000])

    # ---- interfaces / permission ----
    def load_interfaces(self):
        cur = self.iface.currentData()
        names = ta.local_interfaces()
        if not names and ta.capture_binary():
            res = self.ctx.runner.run(ta.list_interfaces_argv(), purpose="list capture interfaces", timeout=20)
            names = [n for n, _d in ta.useful_interfaces(ta.parse_interfaces(res.stdout))]
        names = [n for n, _d in ta.useful_interfaces([(n, "") for n in names])]
        self.iface.clear()
        for n in sorted(names, key=lambda n: (n == "lo", n == "any", n)):
            desc = {"lo": "this computer only", "any": "all interfaces at once"}.get(n, "")
            if n in self._monitor:
                desc = "monitor mode: not allowed"
            self.iface.addItem(f"{n}  ({desc})" if desc else n, n)
        idx = self.iface.findData(cur) if cur else -1
        self.iface.setCurrentIndex(max(idx, 0))
        self._nets = {}
        try:
            from watchtower.core import interfaces
            addrs = interfaces.local_addresses(self.ctx.runner)
            self._nets = {n: [interfaces.network_of(c) for c in cs] for n, cs in addrs.items()}
        except Exception:  # noqa: BLE001 - not Linux / no `ip`: no network info, discovery stays off
            pass
        self._gate()

    def _prefer_interface(self, name: str):
        idx = self.iface.findData(name) if name else -1
        if idx >= 0:
            self.iface.setCurrentIndex(idx)

    def iface_nets(self, iface: str | None) -> list[str]:
        return [n for n in self._nets.get(iface or "", []) if not n.startswith(("127.", "fe80:", "::1"))]

    def _interfaces_changed(self, wireless):
        self._monitor = {w.name for w in wireless if getattr(w, "in_monitor_mode", False)}
        self.load_interfaces()

    def _gate(self):
        busy = self.cancel_event is not None
        have_dumpcap = bool(ta.capture_binary())
        have_tshark = bool(ta.tshark_binary())
        ok, why = ta.capture_permission()
        if not have_dumpcap or not have_tshark:
            self.perm.setText("<span style='color:#c62828'>Needs Wireshark's command-line tools: "
                              "<code>sudo apt install tshark</code> (or Settings → Dependency Check).</span>")
        elif ok is False:
            self.perm.setText(f"<span style='color:#e65100'>⚠ {why}</span>")
        else:
            self.perm.setText(f"<span style='color:#2e7d32'>✓ {why}</span>" if why else "")
        self.perm_btn.setVisible(have_dumpcap and ok is False)
        iface = self.iface.currentData()
        self.start_btn.setEnabled(have_dumpcap and have_tshark and bool(iface) and not busy
                                  and iface not in self._monitor)
        self.open_btn.setEnabled(have_tshark and not busy)
        self.open_btn.setToolTip(OPEN_TIP if have_tshark else "Requires tshark (sudo apt install tshark)")
        row = self.current_capture()
        has_file = bool(row and row.get("pcap_path") and Path(row["pcap_path"]).exists())
        self.wireshark_btn.setEnabled(has_file and bool(deps.find_binary("wireshark")))
        if not deps.find_binary("wireshark"):
            self.wireshark_btn.setToolTip("Wireshark isn't installed (sudo apt install wireshark).")
        self.folder_btn.setEnabled(has_file)
        self.reanalyze_btn.setEnabled(has_file and have_tshark and not busy)
        self.delete_btn.setEnabled(bool(row) and not busy)
        self.add_sched_btn.setEnabled(bool(iface) and have_dumpcap)
        nets, why = th.ping_scan_networks(self.iface_nets(iface), self.ctx.targets.values())
        if not deps.find_binary("nmap"):
            nets, why = [], "nmap isn't installed (sudo apt install nmap)."
        self.discover.setEnabled(bool(nets) and not busy)
        if not nets:
            self.discover.setChecked(False)
        restore_tip(self.discover, "" if nets else why)
        sel = self._selected_schedule() is not None
        self.sched_rm_btn.setEnabled(sel)
        self.sched_run_btn.setEnabled(sel and not busy)

    def grant_permission(self):
        from watchtower.gui.run_dialog import RunPlanDialog
        tool = next(t for t in deps.TOOLS if t.key == "dumpcap")
        plan = deps.setcap_plan([deps.check_tool(tool)])
        if not plan.steps:
            QMessageBox.information(self, "Allow capturing", "Nothing to do: dumpcap wasn't found.")
            return
        intro = ("This gives dumpcap (Wireshark's capture program) permission to capture packets, so neither it "
                 "nor Watchtower has to run as root. You'll be asked for your password.")
        RunPlanDialog(self.ctx, "Allow capturing", intro, plan, self).exec()
        self._gate()

    # ---- capturing ----
    def _begin(self, msg: str, seconds: int = 0):
        self.cancel_event = threading.Event()
        self.output.clear()
        self.tabs.setCurrentWidget(self.output)
        self.cancel_btn.setEnabled(seconds > 0)
        self.status.setText(msg)
        if seconds:
            import time
            self._deadline = time.time() + seconds
            self.progress.setRange(0, seconds)
            self.progress.setValue(seconds)
            self.progress.setVisible(True)
            self._timer.start()
        self._gate()

    def _tick(self):
        import time
        left = max(0, int(round(self._deadline - time.time())))
        self.progress.setValue(left)
        if left == 0:
            self._timer.stop()
            self.progress.setVisible(False)
            self.status.setText("Analyzing the capture…")

    def _end(self, msg: str, select: int | None = None):
        self._timer.stop()
        self.progress.setVisible(False)
        self.cancel_event = None
        self.cancel_btn.setEnabled(False)
        self.status.setText(msg)
        self.ctx.bus.captures_changed.emit()
        if select is not None:
            self.select_capture(select)
        self.tabs.setCurrentWidget(self.findings_view)
        self._gate()

    def start_capture(self):
        iface = self.iface.currentData()
        if not iface:
            return
        seconds = ta.DURATIONS[self.duration.currentText()]
        out = ta.new_capture_path(iface)
        user_filter = self.filter.text().strip()
        try:
            argv = ta.capture_argv(iface, out, seconds, self.max_packets.value(), user_filter, self._monitor)
        except (ValueError, RuntimeError) as exc:
            QMessageBox.warning(self, "Can't capture", str(exc))
            return
        cid = self.ctx.captures.start(f"interface:{iface}", out, True, format_command(argv))
        nets = self.iface_nets(iface)
        ping_nets = (th.ping_scan_networks(nets, self.ctx.targets.values())[0]
                     if self.discover.isChecked() and self.discover.isEnabled() else [])
        self._begin(f"Listening on {iface} for {self.duration.currentText()}… (Stop ends it early)", seconds)
        cancel = self.cancel_event

        def work():
            mon = ta.monitor_interfaces(self.ctx.runner)
            if iface in mon:     # re-check right before capturing
                self.ctx.captures.finish(cid, -1, 0, 0, "{}", "[]", "interface is in monitor mode")
                raise RuntimeError(f"{iface} is in monitor mode; Traffic Audit won't capture there.")
            res = self.ctx.runner.stream(argv, purpose="Traffic audit: live capture (listen-only)", target=iface,
                                         on_line=self._lines.line.emit, cancel=cancel)
            if not Path(out).exists() or (res.exit_code != 0 and not (cancel and cancel.is_set())):
                err = ta.capture_error(res.output, res.exit_code)
                self.ctx.captures.finish(cid, res.exit_code, 0, 0, "{}", "[]", err)
                raise RuntimeError(err)
            try:
                os.chmod(out, 0o600)
            except OSError:
                pass
            n = self._analyze(cid, out, iface, nets)
            for net in ping_nets:       # opt-in: find devices that stayed silent while we listened
                self._lines.line.emit(f"Ping scan of {net} to find quiet devices…")
                _sid, msg = th.ping_scan(self.ctx.runner, self.ctx.scans, self.ctx.targets.values(), net)
                self._lines.line.emit(msg)
            if ping_nets:
                self._ping_done.emit()
            return n

        run_in_background(work, on_done=lambda n: self._end(self._done_text(n), cid),
                          on_error=lambda m: self._end("Capture failed: " + m.split("\n\n")[0], cid))

    def open_file(self, path: str | None = None):
        if path is None:
            path, _ = QFileDialog.getOpenFileName(self, "Open a capture file", str(Path.home()),
                                                  "Packet captures (*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz);;"
                                                  "All files (*)")
        if not path:
            return
        path = os.path.abspath(path)
        cid = self.ctx.captures.start(f"file:{path}", path, False, f"open {path}")
        self._begin(f"Analyzing {Path(path).name}…")

        def work():
            return self._analyze(cid, path, None)

        run_in_background(work, on_done=lambda n: self._end(self._done_text(n), cid),
                          on_error=lambda m: self._end("Analysis failed: " + m.split("\n\n")[0], cid))

    def reanalyze(self):
        row = self.current_capture()
        if not row or not row.get("pcap_path"):
            return
        cid, pcap = row["id"], row["pcap_path"]
        target = row["source"].split(":", 1)[1] if row["source"].startswith("interface:") else None
        nets = ta.stats_from_json(row.get("stats_json")).local_nets or (self.iface_nets(target) if target else [])
        self._begin(f"Analyzing {Path(pcap).name} again…")
        run_in_background(lambda: self._analyze(cid, pcap, target, nets),
                          on_done=lambda n: self._end(self._done_text(n), cid),
                          on_error=lambda m: self._end("Analysis failed: " + m.split("\n\n")[0], cid))

    def _analyze(self, cid: int, pcap: str, target: str | None, local_nets: list[str] | None = None) -> int:
        self._lines.line.emit("Analyzing with tshark…")
        a = ta.analyze_pcap(self.ctx.runner, pcap, target, local_nets)
        self.ctx.captures.finish(cid, 0 if not a.error else 1, a.stats.packets, a.stats.seconds,
                                 ta.stats_to_json(a.stats), ta.events_to_json(a.events), a.error)
        if a.error:
            raise RuntimeError(a.error)
        self._lines.line.emit(f"{a.stats.packets} packets analyzed.")
        return len(ta.findings(a.events))

    @staticmethod
    def _done_text(n: int) -> str:
        return (f"Done: {n} finding(s). They also appear in the Findings tab." if n else
                "Done: nothing risky was seen in this capture.")

    # ---- capture list ----
    def reload(self):
        cur = self.current_capture()
        self.cap_list.blockSignals(True)
        self.cap_list.clear()
        for r in self.ctx.captures.all():
            kind, _, src = r["source"].partition(":")
            name = Path(src).name if kind == "file" else src
            when = (r["started"] or "")[:16].replace("T", " ")
            state = ("failed" if r["error"] else f"{r['packets'] or 0} packets")
            it = QListWidgetItem(f"{'📄 file ' if kind == 'file' else '📡 live on '}{name}\n     {when}  ·  {state}")
            it.setData(Qt.ItemDataRole.UserRole, r["id"])
            it.setToolTip(r["error"] or r["pcap_path"] or "")
            if r["error"]:
                it.setForeground(Qt.GlobalColor.darkRed)
            self.cap_list.addItem(it)
        self.cap_list.blockSignals(False)
        if cur:
            self.select_capture(cur["id"])
        elif self.cap_list.count():
            self.cap_list.setCurrentRow(0)
        self.render()
        self.reload_schedules()

    def select_capture(self, cid: int):
        for i in range(self.cap_list.count()):
            if self.cap_list.item(i).data(Qt.ItemDataRole.UserRole) == cid:
                self.cap_list.setCurrentRow(i)
                return

    def current_capture(self) -> dict | None:
        it = self.cap_list.currentItem()
        return self.ctx.captures.get(it.data(Qt.ItemDataRole.UserRole)) if it else None

    def render(self):
        row = self.current_capture()
        if not row:
            self.findings_view.setMarkdown(EMPTY_HELP)
            self.overview.setMarkdown("")
            self.devices.show_capture(None)
            self._gate()
            return
        labels = {a: h.label for a, (h, _s) in latest_hosts(self.ctx.scans.with_output()).items()}
        self.devices.show_capture(row)
        self.findings_view.setMarkdown(findings_markdown(row, labels))
        self.overview.setMarkdown(overview_markdown(row, labels))
        self._gate()

    def open_in_wireshark(self):
        row = self.current_capture()
        ws = deps.find_binary("wireshark")
        if row and ws:
            self.ctx.runner.spawn([ws, row["pcap_path"]], purpose="open capture in Wireshark")

    def show_file(self):
        row = self.current_capture()
        if row and row.get("pcap_path"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(row["pcap_path"]).parent)))

    def delete_capture(self):
        row = self.current_capture()
        if not row:
            return
        what = ("The capture file will be deleted from disk." if row["owned"] else
                "Your file stays where it is; only Watchtower's results are removed.")
        if QMessageBox.question(self, "Delete capture", f"Remove this capture from Watchtower?\n\n{what}") == \
                QMessageBox.StandardButton.Yes:
            self.ctx.captures.delete(row["id"])
            self.ctx.bus.captures_changed.emit()

    # ---- schedules ----
    def reload_schedules(self):
        self.sched_table.blockSignals(True)
        rows = self.ctx.capture_schedules.all()
        self.sched_table.setRowCount(len(rows))
        names = {v: k for k, v in scheduler.INTERVALS.items()}
        lengths = {v: k for k, v in ta.DURATIONS.items()}
        for r, s in enumerate(rows):
            on = QTableWidgetItem()
            on.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            on.setCheckState(Qt.CheckState.Checked if s["enabled"] else Qt.CheckState.Unchecked)
            on.setData(Qt.ItemDataRole.UserRole, s["id"])
            self.sched_table.setItem(r, 0, on)
            vals = [s["interface"] + (f"  [{s['user_filter']}]" if s["user_filter"] else ""),
                    lengths.get(s["seconds"], f"{s['seconds']} s"),
                    names.get(s["interval_minutes"], f"{s['interval_minutes']} min"),
                    (s["next_run"] or "")[:16].replace("T", " ") + " UTC", s["last_status"] or "not run yet"]
            for c, v in enumerate(vals, start=1):
                it = QTableWidgetItem(v)
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                it.setToolTip(v)
                self.sched_table.setItem(r, c, it)
        self.sched_table.blockSignals(False)
        self.sched_table.setVisible(bool(rows))
        self.no_sched.setVisible(not rows)
        self._gate()

    def _selected_schedule(self) -> int | None:
        sm = self.sched_table.selectionModel()
        rows = sm.selectedRows() if sm else []
        return self.sched_table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole) if rows else None

    def add_schedule(self):
        iface = self.iface.currentData()
        if not iface:
            return
        user_filter = self.filter.text().strip()
        try:
            ta.capture_argv(iface, "/dev/null", ta.DURATIONS[self.duration.currentText()], 0, user_filter,
                            self._monitor) if ta.capture_binary() else None
        except ValueError as exc:
            QMessageBox.warning(self, "Can't repeat this capture", str(exc))
            return
        self.ctx.capture_schedules.add(iface, ta.DURATIONS[self.duration.currentText()],
                                       scheduler.INTERVALS[self.every.currentText()], user_filter)
        self.reload_schedules()
        ok, why = ta.capture_permission()
        self.status.setText("Repeating capture added. The first run happens within a minute." +
                            ("" if ok is not False else f" Note: {why}"))

    def remove_schedule(self):
        sid = self._selected_schedule()
        if sid is not None:
            self.ctx.capture_schedules.remove(sid)
            self.reload_schedules()

    def run_schedule_now(self):
        sid = self._selected_schedule()
        if sid is None:
            return
        self.ctx.capture_schedules.run_now(sid)
        win = self.window()
        changes = getattr(win, "changes_tab", None)
        if changes is not None:
            changes.tick(force=True)
            self.status.setText("Running the repeating capture now; results appear here when it finishes.")

    def _sched_item_changed(self, item):
        if item.column() == 0:
            self.ctx.capture_schedules.set_enabled(item.data(Qt.ItemDataRole.UserRole),
                                                   item.checkState() == Qt.CheckState.Checked)


EMPTY_HELP = """### Nothing analyzed yet

**To check your network's traffic:**

1. Under **1. Capture live traffic**, pick the interface connected to your network (your Ethernet or Wi-Fi
   adapter) and how long to listen.
2. Click **Start capture**, then use your devices normally for a while: log in to your router or NAS, check mail,
   open a file share. The more normal activity, the more Watchtower can check.
3. When the time is up, Watchtower analyzes the capture and explains what it found here.

You can also **open a capture file** you made with Wireshark or tcpdump.

*Note: on a switched network or Wi-Fi you mainly see your own computer's traffic plus broadcasts from other
devices (which is where name-lookup and UPnP problems show up). To see other devices' traffic, capture on the
router or a mirror port.*
"""


def _cell(v) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


def _source_text(row: dict) -> str:
    kind, _, src = row["source"].partition(":")
    return f"file **{Path(src).name}**" if kind == "file" else f"live capture on **{src}**"


def findings_markdown(row: dict, labels: dict | None = None) -> str:
    labels = labels or {}
    when = (row.get("started") or "")[:19].replace("T", " ")
    head = [f"### {_source_text(row).capitalize()}", "",
            f"{when} UTC · {row.get('packets') or 0} packets · {round(row.get('seconds') or 0)} seconds", ""]
    if row.get("error"):
        return "\n".join(head + [f"**This capture failed:** {row['error']}"])
    events = ta.events_from_json(row.get("events_json"))
    fs = sorted(ta.findings(events, labels), key=lambda f: (SEV_RANK[f.severity], f.device))
    if not fs:
        return "\n".join(head + [
            "**Nothing risky was seen.** No unencrypted passwords, risky name lookups, SMBv1, old TLS or UPnP "
            "announcements were in this capture.", "",
            "That only covers what crossed this interface while it was listening. Try a longer capture while you "
            "use your devices (log in to the router, check mail, open file shares)."])
    counts = {s: sum(1 for f in fs if f.severity == s) for s in SEV_RANK}
    head += [" · ".join(f"{SEV_ICON[s]} **{n}** {s}" for s, n in counts.items() if n), "",
             "Each item below says what was seen, why it matters and how to fix it. They're also in the "
             "**Findings** tab (with risk scores) and in exported reports. Passwords are never shown or saved by "
             "Watchtower.", ""]
    for f in fs:
        title = f.title.removeprefix("Traffic: ")
        head += [f"#### {SEV_ICON[f.severity]} {f.severity}: {title}",
                 f"**Device:** {f.device_label}" + (f" · **Port:** {f.port}" if f.port else ""), "",
                 f.description, "", f"**Why it matters:** {f.technique}", "", f"**How to fix it:** {f.remediation}",
                 "", "---", ""]
    return "\n".join(head)


def overview_markdown(row: dict, labels: dict | None = None) -> str:
    labels = labels or {}
    st = ta.stats_from_json(row.get("stats_json"))
    lines = [f"### Traffic overview: {_source_text(row)}", "",
             f"{st.packets} packets over {round(st.seconds or 0)} seconds.", ""]
    if st.conversations:
        lines += ["**Who talked to whom** (biggest first)", "", "| Between | And | Packets | Data |",
                  "|---|---|---|---|"]
        for c in st.conversations[:25]:
            lines.append(f"| {_cell(labels.get(c.a, c.a))} | {_cell(labels.get(c.b, c.b))} | {c.frames} | "
                         f"{_size(c.bytes)} |")
        lines.append("")
    if st.protocols:
        lines += ["**Protocols seen**", "", "| Protocol | Packets |", "|---|---|"]
        for name, depth, frames in st.protocols:
            if depth >= 1:
                lines.append(f"| {'  ' * (depth - 1)}{'↳ ' if depth > 2 else ''}{_cell(PROTO_NAMES.get(name, name))} "
                             f"| {frames} |")
        lines.append("")
    return "\n".join(lines)


def _size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


PROTO_NAMES = {"ip": "IPv4", "ipv6": "IPv6", "tcp": "TCP", "udp": "UDP", "tls": "TLS (encrypted)",
               "http": "HTTP (unencrypted web)",
               "dns": "DNS (name lookups)", "ftp": "FTP (unencrypted file transfer)", "telnet": "Telnet (unencrypted)",
               "smb": "SMBv1 (old file sharing)", "smb2": "SMB2/3 (file sharing)", "nbss": "NetBIOS session",
               "nbns": "NetBIOS name lookups", "llmnr": "LLMNR (Windows name lookups)", "mdns": "mDNS / Bonjour",
               "ssdp": "SSDP (UPnP discovery)", "snmp": "SNMP (device management)", "pop": "POP3 (mail)",
               "imap": "IMAP (mail)", "smtp": "SMTP (mail)", "icmp": "ICMP (ping, errors)", "arp": "ARP",
               "quic": "QUIC (encrypted web)", "ssh": "SSH (encrypted remote login)", "dhcp": "DHCP"}


class _SortItem(QTableWidgetItem):
    """Table cell that shows text but sorts by a number."""

    def __init__(self, text: str, key):
        super().__init__(text)
        self._key = key

    def __lt__(self, other):
        return self._key < getattr(other, "_key", 0)


SHOW_CHOICES = {"Devices on my network": "local", "Outside addresses (internet)": "outside", "Everything": "all"}


class DevicesView(QWidget):
    """Every address in a capture: a sortable table and, for the selected one, a full rundown."""

    COLS = ["Device", "Maker", "Sent", "Received", "Talked to", "Problems"]

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.row: dict | None = None
        self.stats: ta.CaptureStats | None = None
        self.hosts: list[th.HostRundown] = []
        self.labels: dict = {}
        self.show = QComboBox()
        self.show.addItems(list(SHOW_CHOICES))
        self.show.setToolTip("Which addresses to list: devices on your own network, the internet addresses they "
                             "talked to, or both.")
        self.count = QLabel()
        self.scan_btn = QPushButton("Scan this device…")
        tip(self.scan_btn, "Open Scan a Target with this address filled in, to see its open ports and software "
                           "(it must be in your authorized targets).")
        top = QHBoxLayout()
        top.addWidget(QLabel("Show:"))
        top.addWidget(self.show)
        top.addWidget(self.count, 1)
        top.addWidget(self.scan_btn)
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.setToolTip("Click a device to see everything it did. Click a column header to sort.")
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hh.setStretchLastSection(True)
        self.detail = QTextBrowser()
        split = QSplitter()
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(top)
        lay.addWidget(split, 1)
        self.show.currentIndexChanged.connect(lambda _i: self._fill())
        self.table.itemSelectionChanged.connect(self._selected)
        self.scan_btn.clicked.connect(self._scan)
        ctx.bus.scan_finished.connect(lambda: self.show_capture(self.row))
        ctx.bus.targets_changed.connect(self._selected)
        self.show_capture(None)

    def show_capture(self, row: dict | None):
        self.row = row
        if not row or row.get("error"):
            self.hosts, self.stats = [], None
            self._fill()
            return
        self.stats = ta.stats_from_json(row.get("stats_json"))
        scans = self.ctx.scans.with_output()
        nmap_hosts = th.devices_from_scans(scans, self.stats.local_nets)
        self.labels = {a: h.label for a, (h, _s) in nmap_hosts.items()}
        live = row["source"].startswith("interface:")
        extra = list(nmap_hosts) if live else []      # devices found by ping/nmap scans of this network
        self.hosts = th.rundown(self.stats, ta.events_from_json(row.get("events_json")), self.labels, nmap_hosts,
                                extra)
        self._fill()

    def visible(self) -> list[th.HostRundown]:
        mode = SHOW_CHOICES[self.show.currentText()]
        return [h for h in self.hosts if mode == "all" or (mode == "local") == h.local]

    def _fill(self):
        hosts = self.visible()
        cur = self.current()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(hosts))
        for r, h in enumerate(hosts):
            worst = h.findings[0].severity if h.findings else ""
            problems = (f"{len(h.findings)} ({worst})" if h.findings else
                        ("not seen in traffic" if not h.seen_in_traffic else "none"))
            cells = [
                _SortItem(h.title, tuple(int(x) if x.isdigit() else 0 for x in h.ip.split("."))),
                _SortItem(h.vendor or "", h.vendor or ""),
                _SortItem(th.size(h.bytes_sent), h.bytes_sent),
                _SortItem(th.size(h.bytes_received), h.bytes_received),
                _SortItem(str(len(h.unicast_peers)), len(h.unicast_peers)),
                _SortItem(problems, -(10 - SEV_RANK.get(worst, 9)) if h.findings else 0),
            ]
            cells[0].setData(Qt.ItemDataRole.UserRole, h.ip)
            cells[0].setToolTip(th.summary_line(h))
            if worst in ("Critical", "High"):
                cells[5].setForeground(Qt.GlobalColor.darkRed)
            if not h.seen_in_traffic:
                for c in cells:
                    c.setForeground(Qt.GlobalColor.gray)
            for c, it in enumerate(cells):
                self.table.setItem(r, c, it)
        self.table.setSortingEnabled(True)
        total = len(self.hosts)
        if not self.row:
            self.count.setText("")
            self.detail.setMarkdown("Capture or open a file first; every address it contains will be listed here.")
        elif self.row.get("error"):
            self.count.setText("")
            self.detail.setMarkdown("This capture failed, so there are no devices to show. Try **Analyze again**.")
        elif self.stats is not None and self.stats.packets and not self.stats.endpoints:
            self.count.setText("")
            self.detail.setMarkdown("This capture was analyzed by an older Watchtower version that didn't collect "
                                    "per-device details. Click **Analyze again** (under the capture list) to get "
                                    "the device rundown.")
        else:
            local = sum(1 for h in self.hosts if h.local)
            self.count.setText(f"{local} device(s) on your network, {total - local} outside address(es)")
            if not hosts:
                self.detail.setMarkdown("Nothing to show with this filter. Try **Show: Everything**.")
        target = next((i for i in range(self.table.rowCount())
                       if self.table.item(i, 0).data(Qt.ItemDataRole.UserRole) == cur), 0 if hosts else None)
        if target is not None:
            self.table.selectRow(target)
        self._selected()

    def current(self) -> str | None:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        return self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole) if rows else None

    def _selected(self):
        ip = self.current()
        h = next((x for x in self.hosts if x.ip == ip), None)
        if h and self.stats is not None:
            text = th.host_markdown(h, self.stats, self.labels)
            if not h.seen_in_traffic:
                text += ("\n\n*This device answered the ping scan but sent nothing while Watchtower was listening. "
                         "Try a longer capture while it's in use.*")
            self.detail.setMarkdown(text)
        covered = bool(ip and self.ctx.targets.covers(ip))
        self.scan_btn.setEnabled(covered)
        restore_tip(self.scan_btn, "" if covered else
                    ("Select a device first." if not ip else
                     f"{ip} isn't in your authorized targets. Add it in Scan a Target first."))

    def _scan(self):
        ip = self.current()
        if ip and self.ctx.targets.covers(ip):
            self.ctx.bus.request_scan.emit(ip)
