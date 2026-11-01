from __future__ import annotations

import os
import shutil
import tempfile
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
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

from watchtower.core import header_audit, web_scanner
from watchtower.core.assessment import WEB_KINDS
from watchtower.core.runner import format_command
from watchtower.core.targets import parse_url
from watchtower.gui.context import AppContext
from watchtower.gui.worker import run_in_background


class _Lines(QObject):
    line = Signal(str)


class WebAuditTab(QWidget):
    """Security headers (one HTTP request) and a nikto scan of URLs whose host is an authorized target."""

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.cancel_event: threading.Event | None = None
        self._lines = _Lines()

        self.url_list = QListWidget()
        self.url_input = QLineEdit(placeholderText="https://nas.lan:5001/  (host must be an authorized target)")
        add_btn = QPushButton("Add")
        ll = QVBoxLayout()
        ll.addWidget(QLabel("<b>URLs</b> (on authorized hosts)"))
        ll.addWidget(self.url_list)
        r = QHBoxLayout()
        r.addWidget(self.url_input)
        r.addWidget(add_btn)
        ll.addLayout(r)
        left = QWidget()
        left.setLayout(ll)

        self.title = QLabel("<i>Add or select a URL</i>")
        hdr_box = QGroupBox("Security headers && cookies")
        self.headers_btn = QPushButton("Check headers")
        hf = QVBoxLayout(hdr_box)
        hl = QLabel("Ordinary GET request(s) to the URL, like a browser. Redirects are followed only while they "
                    "stay on authorized hosts.")
        hl.setWordWrap(True)
        hf.addWidget(hl)
        hf.addWidget(self.headers_btn)
        nikto_box = QGroupBox("Web server scan (nikto)")
        self.nikto_minutes = QSpinBox(minimum=1, maximum=240, value=30, suffix=" min")
        self.nikto_minutes.setToolTip("nikto -maxtime: stop the scan after this long.")
        self.nikto_btn = QPushButton("Run nikto")
        nf = QFormLayout(nikto_box)
        nl = QLabel("Requests thousands of known paths. Runs without nikto's <code>auth</code> plugin (it tries "
                    "default logins) and without its denial-of-service tests.")
        nl.setWordWrap(True)
        nf.addRow(nl)
        nf.addRow("Time limit:", self.nikto_minutes)
        nf.addRow(self.nikto_btn)
        boxes = QHBoxLayout()
        boxes.addWidget(hdr_box)
        boxes.addWidget(nikto_box)
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
        split.setSizes([300, 900])
        QVBoxLayout(self).addWidget(split)

        add_btn.clicked.connect(self.add_url)
        self.url_input.returnPressed.connect(self.add_url)
        self.url_list.currentTextChanged.connect(self._selected)
        self.headers_btn.clicked.connect(self.run_headers)
        self.nikto_btn.clicked.connect(self.run_nikto)
        self.cancel_btn.clicked.connect(lambda: self.cancel_event and self.cancel_event.set())
        self._lines.line.connect(self.output.appendPlainText)
        ctx.bus.targets_changed.connect(self.reload)
        ctx.bus.audit_finished.connect(self.reload)
        ctx.bus.dependencies_changed.connect(self._gate)
        self.reload()

    # ---- URLs ----
    def reload(self):
        cur = self.current_url()
        urls = {r["host"] for r in self.ctx.audits.latest(kinds=WEB_KINDS)}
        if cur:
            urls.add(cur)
        self.url_list.blockSignals(True)
        self.url_list.clear()
        for u in sorted(urls):
            self.url_list.addItem(u)
            if not self.ctx.targets.covers_url(u):
                it = self.url_list.item(self.url_list.count() - 1)
                it.setForeground(Qt.GlobalColor.gray)
                it.setToolTip("Host no longer in your authorized targets")
        self.url_list.blockSignals(False)
        items = self.url_list.findItems(cur, Qt.MatchFlag.MatchExactly) if cur else []
        if items:
            self.url_list.setCurrentItem(items[0])
        elif self.url_list.count():
            self.url_list.setCurrentRow(0)
        self._selected(self.current_url() or "")

    def current_url(self) -> str | None:
        it = self.url_list.currentItem()
        return it.text() if it else None

    def add_url(self, confirm=None) -> bool:
        """Add the URL in the input box. If its host isn't an authorized target, ask
        before adding the host to the authorized-target list (a logged scope change)."""
        try:
            u = parse_url(self.url_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid URL", str(exc))
            return False
        if not self.ctx.targets.covers(u.host):
            ask = confirm or (lambda: QMessageBox.question(
                self, "Authorize host?",
                f"{u.host} isn't in your authorized targets.\n\nAdd it? Only do this for a server you own or have "
                "written permission to test. The change is recorded in the audit log.") ==
                QMessageBox.StandardButton.Yes)
            if not ask():
                return False
            self.ctx.targets.add(u.host, note="added from Web Audit")
            self.ctx.bus.targets_changed.emit()
        self.url_input.clear()
        if not self.url_list.findItems(u.url, Qt.MatchFlag.MatchExactly):
            self.url_list.addItem(u.url)
        self.url_list.setCurrentItem(self.url_list.findItems(u.url, Qt.MatchFlag.MatchExactly)[0])
        return True

    def _selected(self, url: str):
        self.title.setText(f"<h3>{url}</h3>" if url else "<i>Add or select a URL</i>")
        self.render()
        self._gate()

    def _gate(self):
        url = self.current_url()
        busy = self.cancel_event is not None
        in_scope = bool(url and self.ctx.targets.covers_url(url))
        self.headers_btn.setEnabled(in_scope and not busy)
        nikto_ok = bool(web_scanner.binary())
        self.nikto_btn.setEnabled(in_scope and nikto_ok and not busy)
        self.nikto_btn.setToolTip("" if nikto_ok else self.ctx.deps.reason("nikto") or "requires nikto")
        if url and not in_scope:
            self.status.setText(f"{url}: host isn't covered by your authorized targets.")

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
        self.ctx.bus.audit_finished.emit()
        self._gate()
        self.tabs.setCurrentWidget(self.results)

    def _fail(self, msg):
        self._end("Failed: " + msg.split("\n\n")[0])

    def run_headers(self):
        url = self.current_url()
        if not url or not self.ctx.targets.covers_url(url):
            return
        u = parse_url(url)
        audit_id = self.ctx.audits.start("headers", u.url, u.port, "HTTP GET", f"GET {u.url}")
        self._begin(f"Requesting {u.url}…")

        def on_request(method, req_url, note):
            self.ctx.log_network(f"{method} {req_url}", "Web Audit header check" + (f", {note}" if note else ""),
                                 target=u.host)
            self._lines.line.emit(f"{method} {req_url}" + (f"   ({note})" if note else ""))

        def work():
            import requests
            with requests.Session() as session:
                snap = header_audit.fetch(u.url, session, self.ctx.targets.covers, on_request=on_request)
            for h in snap.hops:
                self._lines.line.emit(f"  -> {h.status} redirect to {h.location}")
            raw = "\n".join(f"{k}: {v}" for k, v in snap.headers)
            self._lines.line.emit(f"\nHTTP {snap.status}\n{raw}" if snap.status else f"Error: {snap.error}")
            issues = header_audit.analyze(snap)
            self.ctx.audits.finish(audit_id, 0 if snap.status else 1, raw,
                                   header_audit.result_to_json(snap, issues))
            return snap, issues

        def done(r):
            snap, issues = r
            self._end(f"Header check finished: {len(issues)} issue(s)." if snap.status else
                      f"Request failed: {snap.error}")
        run_in_background(work, on_done=done, on_error=self._fail)

    def run_nikto(self):
        url = self.current_url()
        if not url or not self.ctx.targets.covers_url(url):
            return
        u = parse_url(url)
        out_dir = Path(tempfile.mkdtemp(prefix="watchtower-nikto-"))
        os.chmod(out_dir, 0o700)
        out_xml = out_dir / "nikto.xml"
        argv = web_scanner.build_argv(u.url, str(out_xml), self.nikto_minutes.value())
        audit_id = self.ctx.audits.start("nikto", u.url, u.port, "nikto", format_command(argv))
        self._begin(f"nikto scan of {u.url} (up to {self.nikto_minutes.value()} min)…")

        def work():
            try:
                res = self.ctx.runner.stream(argv, purpose="Web server scan (nikto, no auth plugin, no DoS tests)",
                                             target=u.url, on_line=self._lines.line.emit, cancel=self.cancel_event)
                raw = out_xml.read_text(encoding="utf-8", errors="replace") if out_xml.exists() else ""
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)
            items = web_scanner.parse_xml(raw) if raw else []
            self.ctx.audits.finish(audit_id, res.exit_code, raw, web_scanner.items_to_json(items))
            return res.exit_code, bool(raw), len(items)

        def done(r):
            code, got, n = r
            self._end(f"nikto finished: {n} item(s) reported." if got else
                      f"nikto produced no report (exit {code}); see Live output.")
        run_in_background(work, on_done=done, on_error=self._fail)

    # ---- results ----
    def render(self):
        url = self.current_url()
        if not url:
            self.results.setMarkdown("Add a URL of a web interface you run (router, NAS, home server), e.g. "
                                     "`https://nas.lan:5001/`. Its host must be in your authorized targets.")
            return
        self.results.setMarkdown(web_markdown(url, self.ctx.audits.latest(url, kinds=WEB_KINDS)))


def _c(v) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


def _when(row) -> str:
    return (row.get("finished") or "")[:19].replace("T", " ") + " UTC"


def web_markdown(url: str, audits: list[dict]) -> str:
    lines = ["### Security headers", ""]
    hdr = next((a for a in audits if a["kind"] == "headers"), None)
    if not hdr:
        lines += ["Not checked yet. Click **Check headers**.", ""]
    else:
        snap, issues = header_audit.result_from_json(hdr["result_json"])
        lines += [f"Checked {_when(hdr)}.", ""]
        if snap and snap.error:
            lines += [f"Request failed: `{_c(snap.error)}`", ""]
        elif snap:
            chain = " → ".join(f"{h.status} {h.location}" for h in snap.hops)
            lines += [f"**HTTP {snap.status}** from `{snap.final_url}`" + (f" (redirects: {_c(chain)})" if chain
                                                                          else ""), ""]
            if snap.stopped:
                lines += [f"*{_c(snap.stopped)}*", ""]
            if issues:
                lines += ["| Severity | Issue | Detail |", "|---|---|---|"]
                lines += [f"| {i.severity} | {_c(i.title)} | {_c(i.detail[:200])} |" for i in issues]
                lines.append("")
            else:
                lines += ["All checked headers and cookie flags are set well.", ""]
            shown = [(k, v) for k, v in snap.headers if k.lower() in (
                "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
                "x-content-type-options", "x-frame-options", "referrer-policy", "set-cookie", "server",
                "x-powered-by", "permissions-policy")]
            if shown:
                lines += ["**Relevant response headers**", "", "| Header | Value |", "|---|---|"]
                lines += [f"| {_c(k)} | `{_c(v[:300])}` |" for k, v in shown]
                lines += [""]
    lines += ["### Nikto", ""]
    nk = next((a for a in audits if a["kind"] == "nikto"), None)
    if not nk:
        lines += ["Not run yet. Click **Run nikto** (requires nikto).", ""]
    else:
        items = web_scanner.items_from_json(nk["result_json"])
        lines += [f"Scanned {_when(nk)}.", ""]
        if not nk["raw_output"]:
            lines += [f"No report (exit code {nk['exit_code']}).", ""]
        elif not items:
            lines += ["Nikto reported nothing.", ""]
        else:
            lines += ["| Rating | Item | Path | Ref |", "|---|---|---|---|"]
            for i in sorted(items, key=lambda i: web_scanner.SEV_RANK_LOCAL[i.severity]):
                ref = i.cves or (f"OSVDB {i.osvdb}" if i.osvdb else "")
                lines.append(f"| {i.severity} | {_c(i.description[:160])} | `{_c(i.uri)}` | {_c(ref)} |")
            lines += ["", "*Nikto doesn't rate its results; Watchtower's rating is based on the description.*", ""]
    return "\n".join(lines)
