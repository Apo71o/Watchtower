from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import deps, interfaces
from watchtower.core import nmap_runner as nr
from watchtower.core.platform_utils import is_linux, is_windows, relaunch_as_admin
from watchtower.core.runner import format_command
from watchtower.gui.context import AppContext
from watchtower.gui.worker import run_in_background

STATE_COLORS = {"open": "#2e7d32", "filtered": "#9e6a00", "closed": "#757575"}


class _Lines(QObject):
    line = Signal(str)


class ScanTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.cancel_event: threading.Event | None = None
        self._lines = _Lines()

        # --- authorized targets ---
        tgt_box = QGroupBox("Authorized targets")
        self.tgt_list = QListWidget()
        self.tgt_input = QLineEdit(placeholderText="IP, CIDR, range or hostname")
        add_btn = QPushButton("Add")
        rm_btn = QPushButton("Remove")
        self.subnet_btn = QPushButton("Add one of my subnets…")
        self.subnet_btn.setVisible(is_linux())
        tl = QVBoxLayout(tgt_box)
        tl.addWidget(QLabel("Only targets inside these entries can be scanned."))
        tl.addWidget(self.tgt_list)
        r = QHBoxLayout()
        r.addWidget(self.tgt_input)
        r.addWidget(add_btn)
        tl.addLayout(r)
        r2 = QHBoxLayout()
        r2.addWidget(rm_btn)
        r2.addWidget(self.subnet_btn)
        tl.addLayout(r2)
        add_btn.clicked.connect(self._add_target)
        self.tgt_input.returnPressed.connect(self._add_target)
        rm_btn.clicked.connect(self._remove_target)
        self.subnet_btn.clicked.connect(self._add_subnet)
        self.tgt_list.itemDoubleClicked.connect(lambda it: self.target.setText(it.text()))

        hist_box = QGroupBox("Scan history")
        self.history = QListWidget()
        QVBoxLayout(hist_box).addWidget(self.history)
        self.history.itemClicked.connect(self._load_history)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(tgt_box, 3)
        ll.addWidget(hist_box, 2)

        # --- scan form ---
        self.target = QLineEdit(placeholderText="e.g. 192.168.1.10  or  192.168.1.0/24")
        self.profile = QComboBox()
        for name, (args, desc) in nr.PROFILES.items():
            self.profile.addItem(name)
            tip = (f"nmap {' '.join(args)}\n\n" if args else "") + desc
            self.profile.setItemData(self.profile.count() - 1, tip, Qt.ItemDataRole.ToolTipRole)
        self.scan_type = QComboBox()
        for name, (_flag, desc) in nr.SCAN_TYPES.items():
            self.scan_type.addItem(name)
            self.scan_type.setItemData(self.scan_type.count() - 1, desc, Qt.ItemDataRole.ToolTipRole)
        self.explain = QLabel()
        self.explain.setWordWrap(True)
        self.explain.setStyleSheet("color: palette(placeholder-text);")
        self.explain.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.explain.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self.os_detect = QCheckBox("OS detection (-O)")
        self.all_ports = QCheckBox("All TCP ports (-p-)")
        self.vuln = QCheckBox("Vulnerability scripts (--script vuln)")
        self.vuln.setToolTip("Runs nmap's vuln NSE scripts. Some send real exploit-style probes and can crash "
                             "fragile devices. Only use on hosts you're OK stressing.")
        self.extra = QLineEdit(placeholderText="any nmap options, e.g.  -p 1-1024 -Pn --script http-title,ssl-cert")
        self.preview = QLabel()
        self.preview.setWordWrap(True)
        self.preview.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.preview.setFont(QFont("monospace"))
        self.run_btn = QPushButton("Run scan")
        self.run_btn.setDefault(True)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.status = QLabel()
        self.status.setWordWrap(True)
        form = QFormLayout()
        form.addRow("Target(s):", self.target)
        prof_row = QHBoxLayout()
        prof_row.addWidget(self.profile, 1)
        prof_row.addWidget(QLabel("Scan type:"))
        prof_row.addWidget(self.scan_type, 1)
        form.addRow("Profile:", prof_row)
        opts = QHBoxLayout()
        for w in (self.os_detect, self.all_ports, self.vuln):
            opts.addWidget(w)
        opts.addStretch()
        form.addRow("Options:", opts)
        form.addRow("Extra arguments:", self.extra)
        form.addRow("Command:", self.preview)
        btns = QHBoxLayout()
        btns.addWidget(self.run_btn)
        btns.addWidget(self.cancel_btn)
        btns.addWidget(self.status, 1)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Host / port", "State", "Service", "Version / detail"])
        self.tree.setColumnWidth(0, 230)
        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 110)
        self.output = QPlainTextEdit(readOnly=True)
        self.output.setFont(QFont("monospace"))
        self.output.setMaximumBlockCount(20000)
        self.results_tabs = QTabWidget()
        self.results_tabs.addTab(self.tree, "Results")
        self.results_tabs.addTab(self.output, "Live output")

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addLayout(form)
        rl.addWidget(self.explain)
        rl.addLayout(btns)
        rl.addWidget(self.results_tabs, 1)

        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(1, 3)
        lay = QVBoxLayout(self)
        lay.addWidget(split)

        for w in (self.target, self.extra):
            w.textChanged.connect(self._update_preview)
        for w in (self.os_detect, self.all_ports, self.vuln):
            w.toggled.connect(self._update_preview)
        self.profile.currentTextChanged.connect(self._update_preview)
        self.scan_type.currentTextChanged.connect(self._update_preview)
        self.vuln.toggled.connect(self._vuln_warning)
        self.run_btn.clicked.connect(self.run_scan)
        self.cancel_btn.clicked.connect(self._cancel)
        self._lines.line.connect(self.output.appendPlainText)
        ctx.bus.targets_changed.connect(self._load_targets)
        ctx.bus.dependencies_changed.connect(self._update_preview)
        ctx.bus.request_scan.connect(self.target.setText)
        self._load_targets()
        self._load_history_list()
        self._update_preview()

    # ---- targets ----
    def _load_targets(self):
        self.tgt_list.clear()
        for t in self.ctx.targets.all():
            self.tgt_list.addItem(t["value"])
            self.tgt_list.item(self.tgt_list.count() - 1).setToolTip(t["note"] or "")
        self._update_preview()

    def _add_target(self):
        text = self.tgt_input.text().strip()
        if not text:
            return
        try:
            self.ctx.targets.add(text, note="added manually")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        self.tgt_input.clear()
        self.ctx.bus.targets_changed.emit()

    def _remove_target(self):
        for it in self.tgt_list.selectedItems():
            self.ctx.targets.remove(it.text())
        self.ctx.bus.targets_changed.emit()

    def _add_subnet(self):
        addrs = interfaces.local_addresses(self.ctx.runner)
        choices = [f"{interfaces.network_of(a)}  ({name})" for name, lst in addrs.items() if name != "lo"
                   for a in lst if ":" not in a]
        if not choices:
            QMessageBox.information(self, "No subnets", "No IPv4 addresses found on this machine's interfaces.")
            return
        choice, ok = QInputDialog.getItem(self, "Add subnet", "Authorize which subnet?", choices, 0, False)
        if ok:
            subnet, iface = choice.split("  (")
            self.ctx.targets.add(subnet, note=f"local subnet on {iface.rstrip(')')}")
            self.ctx.bus.targets_changed.emit()

    # ---- command ----
    def _build(self, xml_path="-") -> nr.NmapCommand:
        nmap = self.ctx.deps.path("nmap") or deps.find_binary("nmap")
        if not nmap:
            raise nr.ScopeError(self.ctx.deps.reason("nmap"))
        scan_type = self.scan_type.currentText() if self.scan_type.isEnabled() else None
        return nr.build(nmap, self.target.text(), self.profile.currentText(), scan_type=scan_type,
                        vuln=self.vuln.isChecked(),
                        os_detect=self.os_detect.isChecked(), all_ports=self.all_ports.isChecked(),
                        extra=self.extra.text(), xml_path=xml_path, authorized=self.ctx.targets.values())

    def _explain(self):
        ping_only = nr.profile_is_ping_only(self.profile.currentText())
        self.scan_type.setEnabled(not ping_only)
        self.all_ports.setEnabled(not ping_only)
        self.scan_type.setToolTip("Ping-only profiles don't scan ports." if ping_only else "")
        prof_args, prof_desc = nr.PROFILES[self.profile.currentText()]
        text = f"<b>{_esc(self.profile.currentText())}</b>"
        if prof_args:
            text += f" <code>{_esc(' '.join(prof_args))}</code>"
        text += f": {_esc(prof_desc)}"
        if not ping_only and self.scan_type.currentIndex() > 0:
            st = self.scan_type.currentText()
            text += f"<br><b>{_esc(st)}</b>: {_esc(nr.SCAN_TYPES[st][1])}"
        self.explain.setText(text)

    def _update_preview(self, *_):
        self._explain()
        if self.cancel_event is not None:
            return
        try:
            cmd = self._build()
        except ValueError as exc:
            self.preview.setText(f"<span style='color:#c62828'>{_esc(str(exc))}</span>"
                                 if self.target.text().strip() else "<i>enter a target</i>")
            self.run_btn.setEnabled(False)
            return
        note = " <i>(needs root: you'll be asked)</i>" if cmd.needs_root else ""
        self.preview.setText(_esc(format_command(cmd.argv)) + note)
        self.run_btn.setEnabled(True)

    def _vuln_warning(self, on):
        if on:
            self.status.setText("Note: some vuln scripts send intrusive probes that can crash fragile devices.")

    # ---- running ----
    def run_scan(self):
        out_dir = Path(tempfile.mkdtemp(prefix="watchtower-nmap-"))
        os.chmod(out_dir, 0o755)
        xml_path = out_dir / "scan.xml"
        try:
            cmd = self._build(str(xml_path))
        except ValueError as exc:
            QMessageBox.warning(self, "Can't run", str(exc))
            return
        argv = cmd.argv
        elevated_run = False
        if cmd.needs_root:
            if is_windows():
                ans = QMessageBox.question(
                    self, "Administrator needed",
                    "Some of these options need Administrator rights on Windows. Relaunch Watchtower as "
                    "Administrator? (No = try anyway)",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel)
                if ans == QMessageBox.StandardButton.Cancel:
                    return
                if ans == QMessageBox.StandardButton.Yes:
                    if relaunch_as_admin():
                        QApplication.quit()
                    return
            else:
                wrapped = deps.elevate(argv)
                if wrapped is None:
                    QMessageBox.warning(self, "Needs root",
                                        "These options need root. Grant nmap raw-socket capabilities (Tools → "
                                        "Dependency Check), or run Watchtower with sudo.")
                    return
                if QMessageBox.question(
                        self, "Run as root",
                        "These options (e.g. -O, -sU, -A) need root. Run nmap via the password prompt?\n\n"
                        "Tip: Tools → Dependency Check → Grant raw-socket capabilities avoids this prompt.") \
                        != QMessageBox.StandardButton.Yes:
                    return
                argv = wrapped
                elevated_run = argv[0] != cmd.argv[0]

        target = " ".join(cmd.targets)
        scan_id = self.ctx.scans.start("nmap", target, format_command(argv))
        self.cancel_event = threading.Event()
        self.output.clear()
        self.tree.clear()
        self.results_tabs.setCurrentWidget(self.output)
        self.run_btn.setEnabled(False)
        self.cancel_btn.setEnabled(not elevated_run)
        self.cancel_btn.setToolTip("Can't cancel a scan running as root from here." if elevated_run else "")
        self.status.setText(f"Scanning {target}…")

        def _work():
            res = self.ctx.runner.stream(argv, purpose="nmap scan", target=target, on_line=self._lines.line.emit,
                                         cancel=self.cancel_event)
            xml = xml_path.read_text(encoding="utf-8", errors="replace") if xml_path.exists() else ""
            for f in out_dir.iterdir():
                f.unlink(missing_ok=True)
            out_dir.rmdir()
            self.ctx.scans.finish(scan_id, res.exit_code, xml)
            return res.exit_code, xml

        run_in_background(_work, on_done=self._finished, on_error=self._failed)

    def _cancel(self):
        if self.cancel_event:
            self.cancel_event.set()
            self.status.setText("Cancelling…")

    def _done_common(self):
        self.cancel_event = None
        self.cancel_btn.setEnabled(False)
        self._update_preview()
        self._load_history_list()

    def _failed(self, msg):
        self._done_common()
        self.status.setText("Scan failed: " + msg.split("\n\n")[0])

    def _finished(self, result):
        code, xml = result
        self._done_common()
        parsed = nr.parse_xml(xml)
        self.show_result(parsed)
        hosts_up = sum(1 for h in parsed.hosts if h.status == "up")
        open_ports = sum(1 for h in parsed.hosts for p in h.ports if p.state == "open")
        self.status.setText(f"Done (exit {code}). {hosts_up} host(s) up, {open_ports} open port(s). "
                            + (parsed.summary or ""))
        if parsed.hosts:
            self.results_tabs.setCurrentWidget(self.tree)

    def show_result(self, res: nr.ScanResult):
        self.tree.clear()
        for h in res.hosts:
            os_txt = f"OS: {h.os_matches[0][0]} ({h.os_matches[0][1]}%)" if h.os_matches else ""
            mac = f"MAC {h.mac} {h.vendor}".strip() if h.mac else ""
            hi = QTreeWidgetItem([h.label, h.status, "", "  ".join(x for x in (os_txt, mac, h.closed_summary) if x)])
            f = hi.font(0)
            f.setBold(True)
            hi.setFont(0, f)
            for p in h.ports:
                pi = QTreeWidgetItem([f"{p.portid}/{p.protocol}", p.state,
                                      p.service + (f" ({p.tunnel})" if p.tunnel else ""), p.version_string])
                pi.setForeground(1, QBrush(QColor(STATE_COLORS.get(p.state.split("|")[0], "#000"))))
                for s in p.scripts:
                    si = QTreeWidgetItem([f"script: {s.id}", "", "", s.output.splitlines()[0] if s.output else ""])
                    si.setToolTip(3, s.output)
                    for line in s.output.splitlines()[1:]:
                        si.addChild(QTreeWidgetItem(["", "", "", line]))
                    pi.addChild(si)
                hi.addChild(pi)
            for s in h.scripts:
                si = QTreeWidgetItem([f"host script: {s.id}", "", "", s.output.splitlines()[0] if s.output else ""])
                for line in s.output.splitlines()[1:]:
                    si.addChild(QTreeWidgetItem(["", "", "", line]))
                hi.addChild(si)
            self.tree.addTopLevelItem(hi)
            hi.setExpanded(True)

    def _load_history_list(self):
        self.history.clear()
        for s in self.ctx.scans.recent():
            it = f"#{s['id']}  {s['started'][:16].replace('T', ' ')}  {s['target']}"
            if s["exit_code"] not in (0, None):
                it += f"  (exit {s['exit_code']})"
            self.history.addItem(it)
            self.history.item(self.history.count() - 1).setData(Qt.ItemDataRole.UserRole, s["id"])
            self.history.item(self.history.count() - 1).setToolTip(s["command"])

    def _load_history(self, item):
        scan = self.ctx.scans.get(item.data(Qt.ItemDataRole.UserRole))
        if scan:
            self.show_result(nr.parse_xml(scan["raw_output"] or ""))
            self.results_tabs.setCurrentWidget(self.tree)
            self.status.setText(f"Showing scan #{scan['id']}: {scan['command']}")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


