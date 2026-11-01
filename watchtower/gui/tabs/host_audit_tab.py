from __future__ import annotations

import os
import shutil
import tempfile
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import default_creds, deps, snmp_audit, tls_audit
from watchtower.core.findings_engine import latest_hosts
from watchtower.core.runner import format_command
from watchtower.core.targets import parse_target
from watchtower.gui.context import AppContext
from watchtower.gui.worker import run_in_background


class _Lines(QObject):
    line = Signal(str)


class HostAuditTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.hosts: dict = {}
        self.cancel_event: threading.Event | None = None
        self._lines = _Lines()

        self.host_list = QListWidget()
        self.host_input = QLineEdit(placeholderText="host or IP (must be an authorized target)")
        add_btn = QPushButton("Add")
        hl = QVBoxLayout()
        hl.addWidget(QLabel("<b>Hosts</b> (scanned and in scope)"))
        hl.addWidget(self.host_list)
        r = QHBoxLayout()
        r.addWidget(self.host_input)
        r.addWidget(add_btn)
        hl.addLayout(r)
        left = QWidget()
        left.setLayout(hl)

        self.title = QLabel("<i>Select a host</i>")
        tls_box = QGroupBox("TLS audit")
        self.tls_port = QComboBox(editable=True)
        self.tls_backend = QComboBox()
        self.tls_btn = QPushButton("Run TLS audit")
        tf = QFormLayout(tls_box)
        tf.addRow("Port:", self.tls_port)
        tf.addRow("Tool:", self.tls_backend)
        tf.addRow(self.tls_btn)
        snmp_box = QGroupBox("SNMP check (read-only GET)")
        self.communities = QLineEdit(", ".join(snmp_audit.DEFAULT_COMMUNITIES))
        self.communities.setToolTip("Community strings to test, comma-separated. Add your own to check that it works.")
        self.v1 = QCheckBox("v1", checked=True)
        self.v2c = QCheckBox("v2c", checked=True)
        self.snmp_port = QSpinBox(minimum=1, maximum=65535, value=161)
        self.snmp_btn = QPushButton("Run SNMP check")
        sf = QFormLayout(snmp_box)
        sf.addRow("Communities:", self.communities)
        vrow = QHBoxLayout()
        vrow.addWidget(self.v1)
        vrow.addWidget(self.v2c)
        vrow.addWidget(QLabel("UDP port:"))
        vrow.addWidget(self.snmp_port)
        vrow.addStretch()
        sf.addRow("Versions:", vrow)
        sf.addRow(self.snmp_btn)
        boxes = QHBoxLayout()
        boxes.addWidget(tls_box)
        boxes.addWidget(snmp_box)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.status = QLabel()
        self.status.setWordWrap(True)
        srow = QHBoxLayout()
        srow.addWidget(self.cancel_btn)
        srow.addWidget(self.status, 1)

        self.results = QTextBrowser(openExternalLinks=True)
        self.output = QPlainTextEdit(readOnly=True)
        self.output.setFont(QFont("monospace"))
        self.output.setMaximumBlockCount(20000)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.results, "Results")
        self.tabs.addTab(self.output, "Live output")

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.title)
        rl.addLayout(boxes)
        rl.addLayout(srow)
        rl.addWidget(self.tabs, 1)
        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(1, 3)
        split.setSizes([250, 900])
        lay = QVBoxLayout(self)
        lay.addWidget(split)

        add_btn.clicked.connect(self._add_host)
        self.host_input.returnPressed.connect(self._add_host)
        self.host_list.currentTextChanged.connect(self._host_selected)
        self.tls_btn.clicked.connect(self.run_tls)
        self.snmp_btn.clicked.connect(self.run_snmp)
        self.cancel_btn.clicked.connect(lambda: self.cancel_event and self.cancel_event.set())
        self._lines.line.connect(self.output.appendPlainText)
        for sig in (ctx.bus.scan_finished, ctx.bus.targets_changed, ctx.bus.audit_finished):
            sig.connect(self.reload)
        ctx.bus.dependencies_changed.connect(self._gate)
        self.reload()

    # ---- hosts ----
    def reload(self):
        cur = self.current_host()
        self.hosts = {a: hs for a, hs in latest_hosts(self.ctx.scans.with_output()).items()
                      if self.ctx.targets.covers(a)}
        extra = {r["host"] for r in self.ctx.audits.latest() if self.ctx.targets.covers(r["host"])}
        names = sorted(set(self.hosts) | extra | ({cur} if cur else set()), key=_sort_key)
        self.host_list.blockSignals(True)
        self.host_list.clear()
        for n in names:
            h = self.hosts.get(n)
            self.host_list.addItem(n)
            if h:
                self.host_list.item(self.host_list.count() - 1).setToolTip(h[0].label)
        self.host_list.blockSignals(False)
        items = self.host_list.findItems(cur, Qt.MatchFlag.MatchExactly) if cur else []
        if items:
            self.host_list.setCurrentItem(items[0])
        elif self.host_list.count():
            self.host_list.setCurrentRow(0)
        self._host_selected(self.current_host() or "")

    def current_host(self) -> str | None:
        it = self.host_list.currentItem()
        return it.text() if it else None

    def _add_host(self):
        text = self.host_input.text().strip()
        try:
            parse_target(text)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid host", str(exc))
            return
        if "/" in text or "-" in text.split(".")[-1]:
            QMessageBox.warning(self, "One host", "Enter a single host, not a range.")
            return
        if not self.ctx.targets.covers(text):
            QMessageBox.warning(self, "Not authorized", f"{text} isn't covered by your authorized targets. Add it "
                                "under Scan a Target first.")
            return
        self.host_input.clear()
        if not self.host_list.findItems(text, Qt.MatchFlag.MatchExactly):
            self.host_list.addItem(text)
        self.host_list.setCurrentItem(self.host_list.findItems(text, Qt.MatchFlag.MatchExactly)[0])

    def _host_selected(self, host: str):
        self.tls_port.clear()
        if host and host in self.hosts:
            h = self.hosts[host][0]
            for p in tls_audit.tls_ports(h):
                svc = next((x for x in h.ports if x.portid == p), None)
                self.tls_port.addItem(f"{p}" + (f"  ({svc.service})" if svc else ""), p)
        if not self.tls_port.count():
            self.tls_port.addItem("443", 443)
        self.title.setText(f"<h3>{self.hosts[host][0].label if host in self.hosts else host}</h3>" if host
                           else "<i>Select a host</i>")
        self.render()
        self._gate()

    def _gate(self):
        host = self.current_host()
        busy = self.cancel_event is not None
        in_scope = bool(host and self.ctx.targets.covers(host))
        self.tls_backend.clear()
        for name in tls_audit.backends():
            self.tls_backend.addItem(name)
        tls_ok = self.tls_backend.count() > 0
        self.tls_btn.setEnabled(in_scope and tls_ok and not busy)
        self.tls_btn.setToolTip("" if tls_ok else "requires sslyze (pip install sslyze) or testssl.sh")
        snmp_ok = bool(deps.find_binary("snmpget"))
        self.snmp_btn.setEnabled(in_scope and snmp_ok and not busy)
        self.snmp_btn.setToolTip("" if snmp_ok else self.ctx.deps.reason("snmp"))
        if host and not in_scope:
            self.status.setText(f"{host} is no longer covered by your authorized targets.")

    # ---- running ----
    def _begin(self, msg):
        self.cancel_event = threading.Event()
        self.output.clear()
        self.tabs.setCurrentWidget(self.output)
        self.cancel_btn.setEnabled(True)
        self.status.setText(msg)
        self._gate()

    def _end(self, msg):
        self.cancel_event = None
        self.cancel_btn.setEnabled(False)
        self.status.setText(msg)
        self._gate()
        self.ctx.bus.audit_finished.emit()
        self.tabs.setCurrentWidget(self.results)

    def _fail(self, msg):
        self._end("Failed: " + msg.split("\n\n")[0])

    def run_tls(self):
        host = self.current_host()
        if not host or not self.ctx.targets.covers(host):
            return
        try:
            port = int(self.tls_port.currentData() or self.tls_port.currentText().split()[0])
        except (ValueError, IndexError):
            QMessageBox.warning(self, "Port", "Enter a port number.")
            return
        backend = self.tls_backend.currentText()
        out_dir = Path(tempfile.mkdtemp(prefix="watchtower-tls-"))
        os.chmod(out_dir, 0o700)
        out_json = out_dir / "result.json"
        argv = tls_audit.build_argv(backend, host, port, str(out_json))
        audit_id = self.ctx.audits.start("tls", host, port, backend, format_command(argv))
        self._begin(f"TLS audit of {host}:{port} with {backend} (can take a few minutes)…")

        def work():
            try:
                res = self.ctx.runner.stream(argv, purpose=f"TLS audit ({backend})", target=f"{host}:{port}",
                                             on_line=self._lines.line.emit, cancel=self.cancel_event)
                raw = out_json.read_text(encoding="utf-8", errors="replace") if out_json.exists() else ""
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)
            issues = []
            if raw:
                issues = (tls_audit.parse_testssl(raw) if backend == "testssl.sh" else tls_audit.parse_sslyze(raw))
            self.ctx.audits.finish(audit_id, res.exit_code, raw, tls_audit.issues_to_json(issues))
            return res.exit_code, bool(raw), len(issues)

        def done(r):
            code, got, n = r
            self._end(f"TLS audit finished: {n} issue(s) found." if got else
                      f"TLS audit produced no results (exit {code}); see Live output.")
        run_in_background(work, on_done=done, on_error=self._fail)

    def run_snmp(self):
        host = self.current_host()
        if not host or not self.ctx.targets.covers(host):
            return
        comms = [c.strip() for c in self.communities.text().split(",") if c.strip()]
        bad = [c for c in comms if not snmp_audit.valid_community(c)]
        versions = [v for v, cb in (("1", self.v1), ("2c", self.v2c)) if cb.isChecked()]
        if bad or not comms or not versions:
            QMessageBox.warning(self, "SNMP", "Enter at least one community string (no spaces) and pick a version.")
            return
        port = self.snmp_port.value()
        argvs = [(v, c, snmp_audit.build_argv(host, c, v, port)) for c in comms for v in versions]
        audit_id = self.ctx.audits.start("snmp", host, port, "snmpget",
                                         "\n".join(format_command(a) for _v, _c, a in argvs))
        self._begin(f"SNMP GET to {host} UDP {port}: {len(argvs)} request(s)…")

        def work():
            attempts, raw = [], []
            for v, c, argv in argvs:
                if self.cancel_event and self.cancel_event.is_set():
                    break
                res = self.ctx.runner.run(argv, purpose="SNMP read-only check (GET)", target=f"{host}:{port}/udp",
                                          timeout=15)
                self._lines.line.emit(f"$ {res.command}\n{res.output.strip()}\n")
                raw.append(f"$ {res.command}\n{res.output}")
                attempts.append(snmp_audit.attempt_from_output(v, c, res.exit_code, res.output))
            self.ctx.audits.finish(audit_id, 0, "\n".join(raw), snmp_audit.attempts_to_json(attempts))
            return attempts

        def done(attempts):
            ok = sorted({f"'{a.community}'" for a in attempts if a.responded})
            self._end(f"SNMP readable with {', '.join(ok)}." if ok else "No community string got an answer.")
        run_in_background(work, on_done=done, on_error=self._fail)

    # ---- results ----
    def render(self):
        host = self.current_host()
        if not host:
            self.results.setMarkdown("Scan a host in **Scan a Target** (or add one above), then select it here.")
            return
        self.results.setMarkdown(host_markdown(host, self.hosts.get(host, (None, None))[0],
                                               self.ctx.audits.latest(host)))


def _sort_key(addr: str):
    try:
        t = parse_target(addr)
        return (0, t.lo or 0, addr)
    except ValueError:
        return (1, 0, addr)


def _c(v) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


def host_markdown(host: str, h, audits: list[dict]) -> str:
    lines = ["### Default credentials", "",
             "*From the scan fingerprint only: nothing is sent to the host and no login is tried.*", ""]
    if h is None:
        lines += ["No nmap results for this host yet, so there's nothing to fingerprint. Run a scan with version "
                  "detection (-sV) first.", ""]
    else:
        hits = default_creds.match(h)
        if hits:
            lines += ["| Device type | Default login | Services | Matched in | Note |", "|---|---|---|---|---|"]
            for e, where, ev in hits:
                creds = ", ".join(f"{u} / {p}" for u, p in e["credentials"])
                lines.append(f"| {_c(e['vendor'] + ' ' + e['model'])} | **{_c(creds)}** | {_c(e['services'])} | "
                             f"{_c(where)}: {_c(ev[:80])} | {_c(e['note'])} |")
            lines += ["", "Check that these defaults were changed. Findings has remediation details.", ""]
        else:
            lines += ["No known default-credential fingerprint matched.", ""]
    tls = [a for a in audits if a["kind"] == "tls"]
    lines += ["### TLS", ""]
    if not tls:
        lines += ["Not audited yet. Pick a port and click **Run TLS audit**.", ""]
    for a in tls:
        issues = tls_audit.issues_from_json(a["result_json"])
        lines += [f"**Port {a['port']}**, {a['tool']}, {(a['finished'] or '')[:19].replace('T', ' ')} UTC", ""]
        if not a["raw_output"]:
            lines += [f"No results (exit code {a['exit_code']}): the port may not speak TLS.", ""]
        elif not issues:
            lines += ["No TLS weaknesses found.", ""]
        else:
            lines += ["| Severity | Issue | Detail | CVE |", "|---|---|---|---|"]
            lines += [f"| {i.severity} | {_c(i.title)} | {_c(i.detail[:120])} | {_c(i.cve)} |" for i in issues]
            lines.append("")
    snmp = [a for a in audits if a["kind"] == "snmp"]
    lines += ["### SNMP", ""]
    if not snmp:
        lines += ["Not checked yet. Click **Run SNMP check** (read-only GET requests).", ""]
    for a in snmp:
        atts = snmp_audit.attempts_from_json(a["result_json"])
        lines += [f"**UDP {a['port']}**, {(a['finished'] or '')[:19].replace('T', ' ')} UTC", "",
                  "| Version | Community | Answered | Disclosed |", "|---|---|---|---|"]
        for t in atts:
            disclosed = "; ".join(f"{k}: {v}" for k, v in t.values.items()) if t.responded else t.error
            lines.append(f"| v{t.version} | {_c(t.community)} | {'**yes**' if t.responded else 'no'} | "
                         f"{_c(disclosed[:160])} |")
        lines.append("")
    return "\n".join(lines)
