from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import history_diff, nmap_runner, scheduler, traffic_audit
from watchtower.core.platform_utils import data_dir
from watchtower.gui.context import AppContext
from watchtower.gui.ui import follow, set_combo, tip
from watchtower.gui.worker import run_in_background
from watchtower.storage import preferences as prefs
from watchtower.storage.audit_log import Event
from watchtower.storage.settings import SCHED_BACKGROUND

LEVEL_COLORS = {"alert": "#c62828", "notice": "#ef6c00", "good": "#2e7d32", "info": "#757575"}
WIFI = "__wifi__"
CAPTURE_PREFIX = "__capture__:"


def _ts(s: str | None) -> str:
    return (s or "")[:16].replace("T", " ")


class ChangesTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._running = False

        # ---- history ----
        self.sources = QListWidget()
        self.older = QComboBox()
        tip(self.older, 'The earlier scan/capture to compare.')
        self.newer = QComboBox()
        tip(self.newer, 'The later scan/capture to compare.')
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Level", "Device", "Change", "Detail"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(True)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        cmp_row = QHBoxLayout()
        cmp_row.addWidget(QLabel("Compare"))
        cmp_row.addWidget(self.older, 1)
        cmp_row.addWidget(QLabel("→"))
        cmp_row.addWidget(self.newer, 1)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addLayout(cmp_row)
        rl.addWidget(self.summary)
        rl.addWidget(self.table)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(QLabel("<b>History</b>"))
        ll.addWidget(self.sources)
        hist = QSplitter()
        hist.addWidget(left)
        hist.addWidget(right)
        hist.setStretchFactor(1, 3)
        hist.setSizes([240, 900])

        # ---- schedules ----
        sched_box = QGroupBox("Scheduled scans")
        self.sched_table = QTableWidget(0, 7)
        self.sched_table.setHorizontalHeaderLabels(["On", "Target", "Profile", "Every", "Next run (UTC)",
                                                    "Last run (UTC)", "Last result"])
        self.sched_table.verticalHeader().setVisible(False)
        self.sched_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sched_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        sh = self.sched_table.horizontalHeader()
        sh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        sh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.s_target = QComboBox()
        tip(self.s_target, 'Which authorized target the scheduled scan covers.')
        self.s_profile = QComboBox()
        tip(self.s_profile, 'Which nmap profile the scheduled scan uses (Quick scan is a good default).')
        self.s_profile.addItems([p for p in nmap_runner.PROFILES if not p.startswith("Custom")])
        self.s_profile.setCurrentText("Quick scan")
        self.s_interval = QComboBox()
        tip(self.s_interval, 'How often to repeat the scan.')
        self.s_interval.addItems(list(scheduler.INTERVALS))
        follow(ctx, prefs.SCHEDULE_INTERVAL, lambda v: set_combo(self.s_interval, v))
        add_btn = QPushButton("Add schedule")
        tip(add_btn, ("Repeat this scan automatically; each run is compared with the previous one and alerts are "
                      "shown here."))
        self.rm_btn = QPushButton("Remove")
        tip(self.rm_btn, 'Delete the selected schedule (past scans are kept).')
        self.now_btn = QPushButton("Run now")
        tip(self.now_btn, 'Run the selected schedule right away.')
        self.bg_box = QCheckBox("Keep running scheduled scans when Watchtower is closed")
        self.bg_box.setToolTip("Installs a systemd user timer (no root) that runs due scans every 15 minutes.")
        self.sched_status = QLabel()
        self.sched_status.setWordWrap(True)
        row = QHBoxLayout()
        for w in (QLabel("Target:"), self.s_target, QLabel("Profile:"), self.s_profile, QLabel("Every:"),
                  self.s_interval, add_btn):
            row.addWidget(w)
        row.addStretch()
        row.addWidget(self.now_btn)
        row.addWidget(self.rm_btn)
        sl = QVBoxLayout(sched_box)
        sl.addWidget(self.sched_table)
        sl.addLayout(row)
        sl.addWidget(self.bg_box)
        sl.addWidget(self.sched_status)

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(hist)
        split.addWidget(sched_box)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay = QVBoxLayout(self)
        lay.addWidget(split)

        self.sources.currentItemChanged.connect(lambda *_: self._source_selected())
        self.older.currentIndexChanged.connect(self._compare)
        self.newer.currentIndexChanged.connect(self._compare)
        add_btn.clicked.connect(self._add_schedule)
        self.rm_btn.clicked.connect(self._remove_schedule)
        self.now_btn.clicked.connect(self._run_now)
        self.sched_table.itemChanged.connect(self._sched_item_changed)
        self.bg_box.setChecked(bool(ctx.settings.get(SCHED_BACKGROUND, False)))
        self.bg_box.toggled.connect(self._toggle_background)
        self.bg_box.setEnabled(scheduler.background_supported())
        for sig in (ctx.bus.scan_finished, ctx.bus.networks_changed, ctx.bus.captures_changed):
            sig.connect(self.reload_sources)
        ctx.bus.targets_changed.connect(self._load_targets)

        self.timer = QTimer(self)
        self.timer.setInterval(60_000)
        self.timer.timeout.connect(self.tick)
        self.timer.start()

        self.reload_sources()
        self._load_targets()
        self.reload_schedules()

    # ---- history ----
    def reload_sources(self):
        cur = self.sources.currentItem().data(Qt.ItemDataRole.UserRole) if self.sources.currentItem() else None
        self.sources.blockSignals(True)
        self.sources.clear()
        snaps = self.ctx.networks.snapshots()
        it = QListWidgetItem(f"Wi-Fi nearby ({len(snaps)} scans)")
        it.setData(Qt.ItemDataRole.UserRole, WIFI)
        self.sources.addItem(it)
        for t in self.ctx.scans.targets():
            it = QListWidgetItem(f"{t['target']} ({t['n']} scans)")
            it.setData(Qt.ItemDataRole.UserRole, t["target"])
            self.sources.addItem(it)
        for c in self.ctx.captures.sources():
            kind, _, name = c["source"].partition(":")
            label = f"Traffic on {name}" if kind == "interface" else f"Traffic file {name.rsplit('/', 1)[-1]}"
            it = QListWidgetItem(f"{label} ({c['n']} captures)")
            it.setData(Qt.ItemDataRole.UserRole, CAPTURE_PREFIX + c["source"])
            it.setToolTip("Compare two traffic captures: new cleartext logins, SMBv1, risky name lookups, ...")
            self.sources.addItem(it)
        self.sources.blockSignals(False)
        row = next((i for i in range(self.sources.count())
                    if self.sources.item(i).data(Qt.ItemDataRole.UserRole) == cur), None)
        if row is None:
            row = 1 if self.sources.count() > 1 else 0
        self.sources.setCurrentRow(row)
        self._source_selected()

    def _source_selected(self):
        item = self.sources.currentItem()
        src = item.data(Qt.ItemDataRole.UserRole) if item else None
        for combo in (self.older, self.newer):
            combo.blockSignals(True)
            combo.clear()
        if src == WIFI:
            entries = [(s["id"], f"#{s['id']}  {_ts(s['ts'])}  {s['source']} ({s['count']} networks)")
                       for s in self.ctx.networks.snapshots()]
        elif src and src.startswith(CAPTURE_PREFIX):
            entries = [(c["id"], f"#{c['id']}  {_ts(c['started'])}  {c['packets'] or 0} packets"
                        + ("  (scheduled)" if c.get("schedule_id") else ""))
                       for c in self.ctx.captures.for_source(src[len(CAPTURE_PREFIX):])]
        elif src:
            entries = [(s["id"], f"#{s['id']}  {_ts(s['started'])}" + ("  (scheduled)" if s.get("schedule_id") else ""))
                       for s in self.ctx.scans.for_target(src)]
        else:
            entries = []
        for sid, label in entries:
            self.older.addItem(label, sid)
            self.newer.addItem(label, sid)
        if len(entries) >= 2:
            self.newer.setCurrentIndex(0)
            self.older.setCurrentIndex(1)
        for combo in (self.older, self.newer):
            combo.blockSignals(False)
        self._compare()

    def _compare(self):
        item = self.sources.currentItem()
        src = item.data(Qt.ItemDataRole.UserRole) if item else None
        if self.older.count() < 2:
            self.table.setRowCount(0)
            self.summary.setText("Pick a source on the left. You need at least two scans of the same target (or two "
                                 "Wi-Fi scans, or two traffic captures of the same interface) to see what changed. "
                                 "Schedules below, and repeating captures in Traffic Audit, do this automatically.")
            return
        a, b = self.older.currentData(), self.newer.currentData()
        if a == b:
            changes = []
        elif src and src.startswith(CAPTURE_PREFIX):
            ev = traffic_audit.events_from_json
            changes = traffic_audit.diff_captures(ev(self.ctx.captures.get(a)["events_json"]),
                                                  ev(self.ctx.captures.get(b)["events_json"]))
        elif src == WIFI:
            nets = self.ctx.networks
            changes = history_diff.diff_wifi(nets.snapshot(a), nets.snapshot(b), nets.authorized_ssids(),
                                             nets.authorized_bssids())
        else:
            changes = history_diff.diff_scans(nmap_runner.parse_xml(self.ctx.scans.get(a)["raw_output"] or ""),
                                              nmap_runner.parse_xml(self.ctx.scans.get(b)["raw_output"] or ""))
        self.show_changes(changes)

    def show_changes(self, changes):
        self.summary.setText(history_diff.summary(changes))
        self.table.setRowCount(len(changes))
        for r, c in enumerate(changes):
            vals = [c.level, c.device, c.title, c.detail]
            for col, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setToolTip(v)
                if col == 0:
                    it.setForeground(QBrush(QColor(LEVEL_COLORS[c.level])))
                    f = it.font()
                    f.setBold(True)
                    it.setFont(f)
                self.table.setItem(r, col, it)
        self.table.resizeRowsToContents()

    # ---- schedules ----
    def _load_targets(self):
        cur = self.s_target.currentText()
        self.s_target.clear()
        self.s_target.addItems(self.ctx.targets.values())
        if cur:
            self.s_target.setCurrentText(cur)

    def reload_schedules(self):
        self.sched_table.blockSignals(True)
        rows = self.ctx.schedules.all()
        self.sched_table.setRowCount(len(rows))
        names = {v: k for k, v in scheduler.INTERVALS.items()}
        for r, s in enumerate(rows):
            on = QTableWidgetItem()
            on.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            on.setCheckState(Qt.CheckState.Checked if s["enabled"] else Qt.CheckState.Unchecked)
            on.setData(Qt.ItemDataRole.UserRole, s["id"])
            self.sched_table.setItem(r, 0, on)
            vals = [s["target"], s["profile"], names.get(s["interval_minutes"], f"{s['interval_minutes']} min"),
                    _ts(s["next_run"]), _ts(s["last_run"]), s["last_status"] or ""]
            for c, v in enumerate(vals, start=1):
                it = QTableWidgetItem(v)
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                it.setToolTip(v)
                self.sched_table.setItem(r, c, it)
        self.sched_table.blockSignals(False)
        bg = self.ctx.settings.get(SCHED_BACKGROUND, False)
        self.sched_status.setText(
            ("Background timer is on: due scans run every 15 minutes even when Watchtower is closed."
             if bg else "Scheduled scans run while Watchtower is open (checked every minute).")
            + " Schedules skip targets that are no longer authorized, and scans that need root.")

    def _selected_schedule(self) -> int | None:
        rows = self.sched_table.selectionModel().selectedRows()
        return self.sched_table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole) if rows else None

    def _add_schedule(self):
        target = self.s_target.currentText()
        if not target:
            QMessageBox.information(self, "Schedule", "Add an authorized target under Scan a Target first.")
            return
        self.ctx.schedules.add(target, self.s_profile.currentText(), scheduler.INTERVALS[self.s_interval.currentText()])
        self.reload_schedules()

    def _remove_schedule(self):
        sid = self._selected_schedule()
        if sid is not None:
            self.ctx.schedules.remove(sid)
            self.reload_schedules()

    def _run_now(self):
        sid = self._selected_schedule()
        if sid is not None:
            self.ctx.schedules.run_now(sid)
            self.tick(force=True)

    def _sched_item_changed(self, item):
        if item.column() == 0:
            self.ctx.schedules.set_enabled(item.data(Qt.ItemDataRole.UserRole),
                                           item.checkState() == Qt.CheckState.Checked)

    def tick(self, force: bool = False):
        """Run due schedules in the background (unless the systemd timer owns them)."""
        if self._running or (self.ctx.settings.get(SCHED_BACKGROUND, False) and not force):
            return
        due = self.ctx.schedules.due() + self.ctx.capture_schedules.due()
        if not due:
            return
        self._running = True
        self.sched_status.setText(f"Running {len(due)} scheduled scan(s)/capture(s)…")

        def done(results):
            self._running = False
            self.reload_schedules()
            self.ctx.bus.scan_finished.emit()
            self.ctx.bus.captures_changed.emit()
            alerts = [(r, c) for r in results for c in r.alerts]
            if alerts:
                self.sched_status.setText("⚠ " + "; ".join(f"{r.target}: {c.title}" for r, c in alerts[:4]))
                win = self.window()
                if hasattr(win, "notify"):
                    win.notify(f"Watchtower: {len(alerts)} alert(s)", alerts[0][1].title)

        def failed(msg):
            self._running = False
            self.sched_status.setText("Scheduled run failed: " + msg.split("\n\n")[0])

        run_in_background(scheduler.run_due, self.ctx.runner, self.ctx.targets, self.ctx.scans, self.ctx.schedules,
                          self.ctx.captures, self.ctx.capture_schedules, on_done=done, on_error=failed)

    def _toggle_background(self, on: bool):
        argvs = scheduler.timer_install_argvs() if on else scheduler.timer_remove_argvs()
        unit_dir = scheduler.user_unit_dir()
        files = scheduler.timer_units(home=str(data_dir()) if _custom_home() else None)
        detail = "\n".join(" ".join(a) for a in argvs)
        msg = (f"This writes {', '.join(files)} to {unit_dir} and runs:\n\n{detail}\n\nNo root needed. Note: "
               "scans that need root are skipped in the background.") if on else f"This runs:\n\n{detail}"
        if QMessageBox.question(self, "Background scans", msg) != QMessageBox.StandardButton.Yes:
            self.bg_box.blockSignals(True)
            self.bg_box.setChecked(not on)
            self.bg_box.blockSignals(False)
            return
        if on:
            unit_dir.mkdir(parents=True, exist_ok=True)
            for name, text in files.items():
                (unit_dir / name).write_text(text)
            self.ctx.audit.append(Event.CONFIRMATION, detail={"action": "install background timer",
                                                              "files": [str(unit_dir / n) for n in files]})
        errors = []
        for a in argvs:
            r = self.ctx.runner.run(a, purpose="background schedule timer", timeout=30)
            if not r.ok:
                errors.append(r.output.strip()[-300:])
        if errors:
            QMessageBox.warning(self, "Background scans", "systemctl reported:\n\n" + "\n".join(errors))
        self.ctx.settings.set(SCHED_BACKGROUND, on and not errors)
        self.bg_box.blockSignals(True)
        self.bg_box.setChecked(on and not errors)
        self.bg_box.blockSignals(False)
        self.reload_schedules()


def _custom_home() -> bool:
    import os
    return bool(os.environ.get("WATCHTOWER_HOME"))


