from __future__ import annotations

import importlib.util
import os
import shutil
import tempfile
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
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

from watchtower.core import domain_audit, subdomain_enum
from watchtower.core.assessment import DOMAIN_KINDS
from watchtower.core.runner import format_command
from watchtower.core.targets import normalize_domain
from watchtower.gui.context import AppContext
from watchtower.gui.worker import run_in_background


class _Lines(QObject):
    line = Signal(str)


class Cancelled(RuntimeError):
    pass


def dns_available() -> bool:
    return importlib.util.find_spec("dns") is not None


class DomainAuditTab(QWidget):
    """SPF/DKIM/DMARC via DNS and passive subdomain discovery, for domains the user owns."""

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.cancel_event: threading.Event | None = None
        self._lines = _Lines()
        self._amass_help: str | None = None

        self.domain_list = QListWidget()
        self.domain_input = QLineEdit(placeholderText="example.com (a domain you own)")
        add_btn = QPushButton("Add")
        self.remove_btn = QPushButton("Remove")
        ll = QVBoxLayout()
        ll.addWidget(QLabel("<b>Domains you own</b>"))
        ll.addWidget(self.domain_list)
        r = QHBoxLayout()
        r.addWidget(self.domain_input)
        r.addWidget(add_btn)
        ll.addLayout(r)
        ll.addWidget(self.remove_btn)
        left = QWidget()
        left.setLayout(ll)

        self.title = QLabel("<i>Add or select a domain</i>")
        mail_box = QGroupBox("Email authentication (SPF / DKIM / DMARC)")
        self.selectors = QLineEdit(placeholderText="extra DKIM selectors, comma-separated (optional)")
        self.selectors.setToolTip("Your provider's DKIM selector is the s= value in the DKIM-Signature header of a "
                                  "message you sent. Common ones are tried anyway.")
        self.mail_btn = QPushButton("Check DNS records")
        mf = QFormLayout(mail_box)
        ml = QLabel("Public DNS lookups only (TXT/MX through your resolver). Nothing is sent to your mail servers.")
        ml.setWordWrap(True)
        mf.addRow(ml)
        mf.addRow("Selectors:", self.selectors)
        mf.addRow(self.mail_btn)
        sub_box = QGroupBox("Passive subdomain discovery")
        self.sub_backend = QComboBox()
        self.sub_minutes = QSpinBox(minimum=1, maximum=60, value=10, suffix=" min")
        self.sub_btn = QPushButton("Find subdomains")
        sf = QFormLayout(sub_box)
        sl = QLabel("Asks public data sources (Certificate Transparency logs, passive DNS). Never contacts your "
                    "servers; names aren't resolved or probed.")
        sl.setWordWrap(True)
        sf.addRow(sl)
        sf.addRow("Source:", self.sub_backend)
        sf.addRow("Time limit:", self.sub_minutes)
        sf.addRow(self.sub_btn)
        boxes = QHBoxLayout()
        boxes.addWidget(mail_box)
        boxes.addWidget(sub_box)
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
        split.setSizes([260, 900])
        QVBoxLayout(self).addWidget(split)

        add_btn.clicked.connect(self.add_domain)
        self.domain_input.returnPressed.connect(self.add_domain)
        self.remove_btn.clicked.connect(self.remove_domain)
        self.domain_list.currentTextChanged.connect(self._selected)
        self.mail_btn.clicked.connect(self.run_mail)
        self.sub_btn.clicked.connect(self.run_subdomains)
        self.sub_backend.currentIndexChanged.connect(lambda _i: self._gate())
        self.cancel_btn.clicked.connect(lambda: self.cancel_event and self.cancel_event.set())
        self._lines.line.connect(self.output.appendPlainText)
        ctx.bus.domains_changed.connect(self.reload)
        ctx.bus.audit_finished.connect(self.reload)
        ctx.bus.dependencies_changed.connect(self._fill_backends)
        self._fill_backends()
        self.reload()

    # ---- domains ----
    def reload(self):
        cur = self.current_domain()
        names = self.ctx.domains.values()
        self.domain_list.blockSignals(True)
        self.domain_list.clear()
        self.domain_list.addItems(names)
        self.domain_list.blockSignals(False)
        items = self.domain_list.findItems(cur, Qt.MatchFlag.MatchExactly) if cur else []
        if items:
            self.domain_list.setCurrentItem(items[0])
        elif self.domain_list.count():
            self.domain_list.setCurrentRow(0)
        self._selected(self.current_domain() or "")

    def current_domain(self) -> str | None:
        it = self.domain_list.currentItem()
        return it.text() if it else None

    def add_domain(self, confirm=None) -> bool:
        try:
            d = normalize_domain(self.domain_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid domain", str(exc))
            return False
        if not self.ctx.domains.covers(d):
            ask = confirm or (lambda: QMessageBox.question(
                self, "Add owned domain?",
                f"Add {d} to the domains you own?\n\nOnly add domains you own or administer. Domain Audit looks up "
                "public DNS records and public data sources about it. The change is recorded in the audit log.")
                == QMessageBox.StandardButton.Yes)
            if not ask():
                return False
            self.ctx.domains.add(d, note="added from Domain Audit")
            self.ctx.bus.domains_changed.emit()
        self.domain_input.clear()
        items = self.domain_list.findItems(d, Qt.MatchFlag.MatchExactly)
        if items:
            self.domain_list.setCurrentItem(items[0])
        return True

    def remove_domain(self):
        d = self.current_domain()
        if d and QMessageBox.question(self, "Remove domain", f"Remove {d} from the domains you own?") == \
                QMessageBox.StandardButton.Yes:
            self.ctx.domains.remove(d)
            self.ctx.bus.domains_changed.emit()

    def _selected(self, domain: str):
        self.title.setText(f"<h3>{domain}</h3>" if domain else "<i>Add or select a domain</i>")
        self.render()
        self._gate()

    def _fill_backends(self):
        cur = self.sub_backend.currentText()
        self.sub_backend.blockSignals(True)
        self.sub_backend.clear()
        for name, why in subdomain_enum.available(self._amass_help).items():
            label = name + ("  (built in, HTTPS to crt.sh)" if name == "crt.sh" else "")
            self.sub_backend.addItem(label, name)
            idx = self.sub_backend.count() - 1
            if why:
                self.sub_backend.model().item(idx).setEnabled(False)
                self.sub_backend.setItemData(idx, why, Qt.ItemDataRole.ToolTipRole)
        first_ok = next((i for i in range(self.sub_backend.count())
                         if self.sub_backend.model().item(i).isEnabled()), 0)
        idx = self.sub_backend.findData(cur.split()[0]) if cur else -1
        self.sub_backend.setCurrentIndex(idx if idx >= 0 and self.sub_backend.model().item(idx).isEnabled()
                                         else first_ok)
        self.sub_backend.blockSignals(False)
        self._gate()

    def _gate(self):
        d = self.current_domain()
        busy = self.cancel_event is not None
        owned = bool(d and self.ctx.domains.covers(d))
        self.remove_btn.setEnabled(bool(d) and not busy)
        self.mail_btn.setEnabled(owned and dns_available() and not busy)
        self.mail_btn.setToolTip("" if dns_available() else "requires dnspython (pip install dnspython)")
        self.sub_btn.setEnabled(owned and not busy and self.sub_backend.currentData() is not None)

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

    def run_mail(self, resolver_factory=None):
        d = self.current_domain()
        if not d or not self.ctx.domains.covers(d):
            return
        extra = [s.strip() for s in self.selectors.text().split(",") if s.strip()]
        bad = [s for s in extra if not domain_audit.valid_selector(s)]
        if bad:
            QMessageBox.warning(self, "Selector", f"Invalid DKIM selector: {bad[0]}")
            return
        audit_id = self.ctx.audits.start("email", d, None, "dnspython", f"DNS TXT/MX lookups for {d}")
        self._begin(f"Looking up SPF, DMARC and DKIM records for {d}…")
        cancel = self.cancel_event

        def on_query(name, rdtype):
            if cancel and cancel.is_set():
                raise Cancelled("cancelled")
            self.ctx.log_network(f"DNS {rdtype} {name}", "Domain Audit (SPF/DKIM/DMARC lookup)", target=d)
            self._lines.line.emit(f"DNS {rdtype} {name}")

        def work():
            resolve = (resolver_factory or domain_audit.dns_resolver)(on_query)
            try:
                rep = domain_audit.audit(d, resolve, extra)
            except Cancelled:
                self.ctx.audits.finish(audit_id, 1, "cancelled", "{}")
                return None
            self.ctx.audits.finish(audit_id, 0 if not rep.errors else 1, "\n".join(rep.errors),
                                   domain_audit.report_to_json(rep))
            return rep

        def done(rep):
            if rep is None:
                self._end("Cancelled.")
                return
            note = f" ({len(rep.errors)} lookup error(s), results may be incomplete)" if rep.errors else ""
            self._end(f"DNS check finished: {len(rep.issues)} issue(s){note}.")
        run_in_background(work, on_done=done, on_error=self._fail)

    def run_subdomains(self):
        d = self.current_domain()
        backend = self.sub_backend.currentData()
        if not d or not self.ctx.domains.covers(d) or not backend:
            return
        if backend == "crt.sh":
            return self._run_crtsh(d)
        out_dir = Path(tempfile.mkdtemp(prefix="watchtower-subs-"))
        os.chmod(out_dir, 0o700)
        out = out_dir / "out.txt"
        argv = subdomain_enum.build_argv(backend, d, str(out), self.sub_minutes.value())
        audit_id = self.ctx.audits.start("subdomains", d, None, backend, format_command(argv))
        self._begin(f"Passive subdomain discovery for {d} with {backend}…")

        def work():
            try:
                if backend == "amass":
                    # Only run amass if this build still has -passive (newer ones are active by default).
                    h = self.ctx.runner.run(subdomain_enum.amass_help_argv(), purpose="check amass supports -passive",
                                            timeout=30)
                    self._amass_help = h.output
                    if not subdomain_enum.amass_supports_passive(h.output):
                        self.ctx.audits.finish(audit_id, 1, "", "[]")
                        raise RuntimeError(subdomain_enum.available(h.output)["amass"])
                res = self.ctx.runner.stream(argv, purpose=f"Passive subdomain discovery ({backend})", target=d,
                                             on_line=self._lines.line.emit, cancel=self.cancel_event)
                raw = out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)
            subs = (subdomain_enum.parse_subfinder(raw, d) if backend == "subfinder" else
                    subdomain_enum.parse_amass(raw, d))
            self.ctx.audits.finish(audit_id, res.exit_code, raw, subdomain_enum.subs_to_json(subs))
            return len(subs)

        def done(n):
            self._end(f"{backend} finished: {n} name(s) found.")

        def failed(msg):
            self._fill_backends()
            self._fail(msg)
        run_in_background(work, on_done=done, on_error=failed)

    def _run_crtsh(self, d: str):
        params = subdomain_enum.crtsh_params(d)
        from urllib.parse import urlencode
        full = f"{subdomain_enum.CRTSH_URL}?{urlencode(params)}"
        audit_id = self.ctx.audits.start("subdomains", d, None, "crt.sh", f"GET {full}")
        self._begin(f"Searching Certificate Transparency logs (crt.sh) for {d}…")

        def work():
            import requests
            self.ctx.log_network(f"GET {full}", "Domain Audit: Certificate Transparency search (crt.sh)", target=d)
            self._lines.line.emit(f"GET {full}")
            resp = requests.get(subdomain_enum.CRTSH_URL, params=params, timeout=self.sub_minutes.value() * 60,
                                headers={"User-Agent": "Watchtower (passive CT lookup)"})
            if resp.status_code != 200:
                self.ctx.audits.finish(audit_id, resp.status_code, resp.text[:2000], "[]")
                raise RuntimeError(f"crt.sh returned HTTP {resp.status_code}")
            subs = subdomain_enum.parse_crtsh(resp.text, d)
            self.ctx.audits.finish(audit_id, 0, resp.text, subdomain_enum.subs_to_json(subs))
            return len(subs)

        run_in_background(work, on_done=lambda n: self._end(f"crt.sh: {n} name(s) found."), on_error=self._fail)

    # ---- results ----
    def render(self):
        d = self.current_domain()
        if not d:
            self.results.setMarkdown("Add a domain you own (e.g. the one your email address or website uses).")
            return
        self.results.setMarkdown(domain_markdown(d, self.ctx.audits.latest(d, kinds=DOMAIN_KINDS)))


def _c(v) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


def domain_markdown(domain: str, audits: list[dict]) -> str:
    lines = ["### Email authentication", ""]
    row = next((a for a in audits if a["kind"] == "email"), None)
    rep = domain_audit.report_from_json(row["result_json"]) if row else None
    if not rep:
        lines += ["Not checked yet. Click **Check DNS records**.", ""]
    else:
        lines += [f"Checked {(row.get('finished') or '')[:19].replace('T', ' ')} UTC.", ""]
        if rep.errors:
            lines += ["**Some lookups failed, results may be incomplete:** " + _c("; ".join(rep.errors[:5])), ""]
        table = ["| Record | Value |", "|---|---|", f"| MX | {_c(', '.join(rep.mx) or 'none')} |",
                 *[f"| SPF | `{_c(r)}` |" for r in rep.spf], *([] if rep.spf else ["| SPF | none |"])]
        if rep.spf_lookups is not None:
            table.append(f"| SPF DNS lookups | {domain_audit.lookups_text(rep.spf_lookups)} |")
        table += [f"| DMARC | `{_c(r)}` |" for r in rep.dmarc] or ["| DMARC | none |"]
        for s, k in sorted(rep.dkim_keys.items()):
            desc = "revoked (empty key)" if k["revoked"] else f"{k['type'].upper()}" + (
                f" {k['bits']} bits" if k.get("bits") else "") + (" (test mode)" if k["testing"] else "")
            table.append(f"| DKIM `{_c(s)}` | {_c(desc)} |")
        lines += [*table, ""]
        if rep.issues:
            lines += ["| Severity | Issue | Detail |", "|---|---|---|"]
            lines += [f"| {i.severity} | {_c(i.title)} | {_c(i.detail[:220])} |" for i in rep.issues]
        else:
            lines += ["SPF, DKIM and DMARC look good."]
        lines.append("")
    lines += ["### Subdomains (passive)", ""]
    srow = next((a for a in audits if a["kind"] == "subdomains"), None)
    if not srow:
        lines += ["Not searched yet. Pick a source and click **Find subdomains**.", ""]
    else:
        subs = subdomain_enum.subs_from_json(srow["result_json"])
        lines += [f"{len(subs)} name(s) from {srow.get('tool')}, "
                  f"{(srow.get('finished') or '')[:19].replace('T', ' ')} UTC. Names marked ⚠ look like admin, "
                  "development or infrastructure systems.", ""]
        if subs:
            lines += ["| Name | Sources |", "|---|---|"]
            lines += [f"| {'⚠ ' if s.sensitive else ''}{_c(s.name)} | {_c(', '.join(s.sources))} |"
                      for s in subs[:500]]
            if len(subs) > 500:
                lines.append(f"| … {len(subs) - 500} more | |")
        lines.append("")
    return "\n".join(lines)
