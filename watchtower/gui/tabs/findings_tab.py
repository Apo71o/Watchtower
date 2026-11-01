from __future__ import annotations

import getpass

from PySide6.QtCore import QObject, Qt, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import (
    attck_mapping,
    deps,
    domain_audit,
    exploit_xref,
    header_audit,
    interfaces,
    nvd,
    remediation,
    subdomain_enum,
)
from watchtower.core.assessment import Assessment, assess
from watchtower.core.findings_engine import SEV_RANK, SEVERITIES, Finding, latest_hosts
from watchtower.core.platform_utils import data_dir, is_linux
from watchtower.core.risk_scoring import KIND_LABEL
from watchtower.gui.context import AppContext
from watchtower.gui.run_dialog import RunPlanDialog
from watchtower.gui.worker import run_in_background
from watchtower.storage.audit_log import Event

SEV_COLORS = {"Critical": "#b71c1c", "High": "#e53935", "Medium": "#ef6c00", "Low": "#f9a825", "Info": "#757575"}
FCOLS = ["Severity", "Device", "Finding", "Port / service", "CVE", "CVSS", "ATT&CK", "Public exploit"]
RCOLS = ["Risk", "Device", "Type", "#", "Worst"]


def _item(text, color=None, bold=False):
    it = QTableWidgetItem(str(text))
    if color:
        it.setForeground(QBrush(QColor(color)))
    if bold:
        f = it.font()
        f.setBold(True)
        it.setFont(f)
    return it


class _Progress(QObject):
    text = Signal(str)


class _SortItem(QTableWidgetItem):
    def __lt__(self, other):
        a, b = self.data(Qt.ItemDataRole.UserRole + 1), other.data(Qt.ItemDataRole.UserRole + 1)
        if a is not None and b is not None:
            return a < b
        return super().__lt__(other)


def _sitem(text, sort, color=None, bold=False):
    it = _SortItem(str(text))
    it.setData(Qt.ItemDataRole.UserRole + 1, sort)
    if color:
        it.setForeground(QBrush(QColor(color)))
    if bold:
        f = it.font()
        f.setBold(True)
        it.setFont(f)
    return it


class FindingsTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.assessment: Assessment | None = None
        self.shown: list[Finding] = []
        self.device_filter: str | None = None
        self._selected_key: str | None = None   # keep the selected finding across refreshes

        self.summary = QLabel()
        self.min_sev = QComboBox()
        self.min_sev.addItems(["All severities", "Low and above", "Medium and above", "High and above",
                               "Critical only"])
        self.include_unauth = QCheckBox("Include unauthorized Wi-Fi networks")
        self.include_unauth.setToolTip("Assess every network seen nearby, not just ones marked Authorized "
                                       "(uses only what they broadcast).")
        self.refresh_btn = QPushButton("Refresh")
        self.nvd_btn = QPushButton("Look up CVEs on NVD")
        self.nvd_btn.setToolTip("Queries the NIST National Vulnerability Database for the service versions nmap "
                                "found. Enable it in Settings; every request is logged.")
        self.nvd_btn.clicked.connect(lambda: self.nvd_lookup(manual=True))
        self.nvd_status = QLabel()
        self.export_btn = QPushButton("Export report…")
        self.export_btn.clicked.connect(self.export_report)
        top = QHBoxLayout()
        top.addWidget(self.summary, 1)
        top.addWidget(self.include_unauth)
        top.addWidget(self.min_sev)
        top.addWidget(self.nvd_status)
        top.addWidget(self.nvd_btn)
        top.addWidget(self.refresh_btn)
        top.addWidget(self.export_btn)

        self.risks = QTableWidget(0, len(RCOLS))
        self.risks.setHorizontalHeaderLabels(RCOLS)
        self.risks.verticalHeader().setVisible(False)
        self.risks.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.risks.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.risks.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.risks.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.risks.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.risks.setSortingEnabled(True)
        self.risks.horizontalHeader().setSortIndicator(0, Qt.SortOrder.DescendingOrder)  # highest risk first
        self.show_all_btn = QPushButton("Show all devices")
        rbox = QWidget()
        rl = QVBoxLayout(rbox)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(QLabel("<b>Top risks</b> (0-100, highest first)"))
        rl.addWidget(self.risks)
        rl.addWidget(self.show_all_btn)

        self.table = QTableWidget(0, len(FCOLS))
        self.table.setHorizontalHeaderLabels(FCOLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicator(0, Qt.SortOrder.AscendingOrder)   # Critical first
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        for col, width in ((1, 170), (3, 110), (4, 115), (6, 110), (7, 95)):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            hh.resizeSection(col, width)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.detail = QTextBrowser(openExternalLinks=True)
        self.detail.setPlaceholderText(
            "Select a finding to see the details, the technique explained, and how to fix it.")

        self.fix_bar = QWidget()
        self.fix_layout = QHBoxLayout(self.fix_bar)
        self.fix_layout.setContentsMargins(0, 0, 0, 0)
        self.fix_label = QLabel("<b>Fix:</b>")
        self.fix_bar.setVisible(False)
        detail_box = QWidget()
        dl = QVBoxLayout(detail_box)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.addWidget(self.fix_bar)
        dl.addWidget(self.detail)
        self._local_addrs: list[str] | None = None
        self._gateway: str | None = None

        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self.table)
        right.addWidget(detail_box)
        right.setStretchFactor(0, 1)
        right.setStretchFactor(1, 1)
        split = QSplitter()
        split.addWidget(rbox)
        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([330, 820])
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split)

        self.refresh_btn.clicked.connect(self.refresh)
        self.include_unauth.toggled.connect(self.refresh)
        self.min_sev.currentIndexChanged.connect(self._fill_findings)
        self.risks.itemSelectionChanged.connect(self._risk_selected)
        self.show_all_btn.clicked.connect(self._show_all)
        self.table.itemSelectionChanged.connect(self._finding_selected)
        ctx.bus.scan_finished.connect(self.refresh)
        ctx.bus.networks_changed.connect(self.refresh)
        ctx.bus.audit_finished.connect(self.refresh)
        ctx.bus.captures_changed.connect(self.refresh)
        ctx.bus.scan_finished.connect(lambda: self.nvd_lookup(manual=False))
        self._msf_index: dict | None = None
        self.refresh()
        self._load_msf_index()

    def nvd_lookup(self, manual: bool = True):
        if not self.ctx.nvd_enabled() or getattr(self, "_nvd_running", False):
            return
        hosts = [h for h, _ in latest_hosts(self.ctx.scans.with_output()).values()]
        cpes = nvd.host_cpes(hosts)
        if not cpes:
            if manual:
                self.nvd_status.setText("No versioned CPEs to look up: run a scan with version detection (-sV).")
            return
        self._nvd_running = True
        self.nvd_btn.setEnabled(False)
        # Keep a reference: a local QObject would be garbage-collected while the worker still emits on it.
        self._nvd_progress = progress = _Progress()
        progress.text.connect(self.nvd_status.setText)

        def done(r):
            self._nvd_running = False
            self.nvd_btn.setEnabled(True)
            fetched, found = r
            self.nvd_status.setText(f"NVD: {found} CVE(s) from {fetched} new lookup(s)" if fetched
                                    else "NVD: up to date (cached for 7 days)")
            self.refresh()

        def failed(msg):
            self._nvd_running = False
            self.nvd_btn.setEnabled(True)
            self.nvd_status.setText(msg.split("\n\n")[0][:160])
            self.refresh()
        run_in_background(self.ctx.nvd_lookup, cpes, progress.text.emit, on_done=done, on_error=failed)

    def export_report(self):
        from watchtower.gui.report_export import ExportDialog
        ExportDialog(self.ctx, self.include_unauth.isChecked(), self._msf_index, self).exec()

    def _load_msf_index(self):
        """Index local Metasploit module metadata once (reads files only), then refresh."""
        if exploit_xref.find_modules_dir() is None:
            return

        def done(index):
            self._msf_index = index
            self.refresh()
        run_in_background(exploit_xref.load_index, data_dir() / "msf_index.json", on_done=done)

    def refresh(self):
        self.assessment = assess(self.ctx.scans.with_output(), self.ctx.networks.all(),
                                 self.include_unauth.isChecked(), self.ctx.audits.latest(), self._msf_index,
                                 self.ctx.nvd.all() if self.ctx.nvd_enabled() else None,
                                 captures=self.ctx.captures.latest_per_source())
        self.nvd_btn.setVisible(self.ctx.nvd_enabled())
        a = self.assessment
        c = a.counts()
        parts = [f"<span style='color:{SEV_COLORS[s]}'><b>{c[s]}</b> {s}</span>" for s in SEVERITIES if c[s]]
        self.summary.setText(
            f"{len(a.findings)} finding(s) across {a.scope_summary()}" + (": " + " · ".join(parts) if parts else
                                   ". Run a scan or mark networks Authorized to see findings."))
        self.risks.setSortingEnabled(False)
        self.risks.setRowCount(len(a.risks))
        for r, d in enumerate(a.risks):
            color = SEV_COLORS[d.worst] if d.findings else None
            vals = [_sitem(d.score, d.score, color, bold=True), _item(d.label),
                    _item(KIND_LABEL.get(d.kind, "Host")), _sitem(len(d.findings), len(d.findings)),
                    _sitem(d.worst if d.findings else "-", SEV_RANK[d.worst], color)]
            vals[1].setData(Qt.ItemDataRole.UserRole, d.device)
            vals[1].setToolTip(f"{d.open_ports} open port(s)" if d.kind == "host" else d.device)
            for c_, it in enumerate(vals):
                self.risks.setItem(r, c_, it)
        self.risks.setSortingEnabled(True)
        if self.device_filter and not any(d.device == self.device_filter for d in a.risks):
            self.device_filter = None
        self._fill_findings()

    def _show_all(self):
        self.risks.clearSelection()
        self.device_filter = None
        self._fill_findings()

    def _risk_selected(self):
        rows = self.risks.selectionModel().selectedRows()
        if rows:
            self.device_filter = self.risks.item(rows[0].row(), 1).data(Qt.ItemDataRole.UserRole)
            self._selected_key = None
            self._fill_findings()

    def _fill_findings(self):
        if not self.assessment:
            return
        max_rank = {0: 4, 1: 3, 2: 2, 3: 1, 4: 0}[self.min_sev.currentIndex()]
        dev = self.device_filter
        self.shown = [f for f in self.assessment.findings
                      if SEV_RANK[f.severity] <= max_rank and (not dev or f.device == dev)]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.shown))
        for r, f in enumerate(self.shown):
            color = SEV_COLORS[f.severity]
            sev = _sitem(f.severity, SEV_RANK[f.severity], color, bold=True)
            sev.setData(Qt.ItemDataRole.UserRole, r)
            vals = [sev, _item(f.device_label), _item(f.title), _item(f.port or f.service),
                    _item(f.cve_id), _sitem("" if f.cvss is None else f"{f.cvss:.1f}", f.cvss or 0),
                    _item(", ".join(f.attck)),
                    _sitem(f"yes ({len(f.exploits)})" if f.exploits else "", -len(f.exploits),
                           "#b71c1c" if f.exploits and not f.patched else None)]
            vals[2].setToolTip(f.title)
            vals[6].setToolTip("\n".join(attck_mapping.label(t) for t in f.attck))
            for c, it in enumerate(vals):
                self.table.setItem(r, c, it)
        self.table.setSortingEnabled(True)
        self.table.clearSelection()
        if self._selected_key:
            for row in range(self.table.rowCount()):
                if self.shown[self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)].key == self._selected_key:
                    self.table.selectRow(row)       # re-renders the details
                    return
        self._show_device_or_hint()

    # ---- one-click fixes ----
    def _network_facts(self):
        """Local IPs and default gateway, looked up once (read-only `ip` commands, logged)."""
        if self._local_addrs is None:
            self._local_addrs = []
            if is_linux():
                addrs = interfaces.local_addresses(self.ctx.runner)
                self._local_addrs = [a for lst in addrs.values() for a in lst]
                ip = deps.find_binary("ip")
                if ip:
                    res = self.ctx.runner.run([ip, "route", "show", "default"], purpose="find default gateway",
                                              timeout=10)
                    self._gateway = remediation.gateway_from_ip_route(res.stdout)
        return self._local_addrs, self._gateway

    def _show_fixes(self, f: Finding):
        while self.fix_layout.count():
            w = self.fix_layout.takeAt(0).widget()
            if w and w is not self.fix_label:
                w.deleteLater()
        addrs, gw = self._network_facts()
        local = remediation.is_local(f.device, addrs)
        self.fix_actions = remediation.fixes_for(f, local, gateway=gw)
        self.fix_layout.addWidget(self.fix_label)
        for act in self.fix_actions:
            b = QPushButton(act.label)
            b.setToolTip(act.description)
            b.clicked.connect(lambda _=False, a=act, fi=f: self._apply_fix(a, fi))
            if act.kind == "local" and not is_linux():
                b.setEnabled(False)
                b.setToolTip("Automatic local fixes are available on Debian/Ubuntu.")
            self.fix_layout.addWidget(b)
        self.fix_layout.addStretch()
        self.fix_bar.setVisible(bool(self.fix_actions))
        if local:
            self.fix_label.setText("<b>Fix (this machine):</b>")
        else:
            self.fix_label.setText("<b>Fix:</b>")

    def _apply_fix(self, act, f: Finding):
        self.ctx.audit.append(Event.REMEDIATION, target=f.device,
                              detail={"finding": f.title, "action": act.label, "kind": act.kind})
        if act.kind == "local":
            dlg = RunPlanDialog(self.ctx, act.label, act.description, act.plan, self)
            dlg.exec()
            self._offer_rescan(f)
        elif act.kind == "copy":
            QGuiApplication.clipboard().setText("\n".join(act.commands))
            QMessageBox.information(self, "Copied", f"Commands to run on {f.device} (as a user with sudo):\n\n"
                                    + "\n".join(act.commands))
        elif act.kind == "ssh":
            user, ok = QInputDialog.getText(self, "Run via SSH", f"SSH user name on {f.device}:",
                                            text=getpass.getuser())
            if not ok or not user:
                return
            try:
                argv = remediation.ssh_terminal_argv(user.strip(), f.device, act.commands)
            except ValueError as exc:
                QMessageBox.warning(self, "SSH", str(exc))
                return
            if argv is None:
                QMessageBox.warning(self, "SSH", "No terminal emulator found. Use Copy fix commands instead.")
                return
            msg = (f"This opens a terminal and runs, on {f.device} as {user}:\n\n" + "\n".join(act.commands)
                   + "\n\nYou'll be asked for the SSH login and the sudo password there.")
            if QMessageBox.question(self, "Run via SSH", msg) != QMessageBox.StandardButton.Yes:
                self.ctx.audit.append(Event.DECLINED, target=f.device, detail={"action": act.label})
                return
            self.ctx.runner.spawn(argv, purpose=f"remediation over SSH: {f.title}")
        elif act.kind == "open_url":
            QDesktopServices.openUrl(QUrl(act.url))
        elif act.kind == "rescan":
            self.ctx.bus.request_scan.emit(f.device)

    def _offer_rescan(self, f: Finding):
        if QMessageBox.question(self, "Verify", f"Re-scan {f.device} now to check the fix?") \
                == QMessageBox.StandardButton.Yes:
            self.ctx.bus.request_scan.emit(f.device)

    def _show_device_or_hint(self):
        self.fix_bar.setVisible(False)
        a = self.assessment
        if a and self.device_filter:
            self.detail.setMarkdown(device_markdown(a, self.device_filter))
        elif a and not a.findings and not a.risks:
            self.detail.setMarkdown("Nothing assessed yet. Run a scan in **Scan a Target**, or tick **Authorized** "
                                    "for networks in **Nearby Networks** (or tick *Include unauthorized Wi-Fi "
                                    "networks* above).")
        else:
            self.detail.clear()

    def _finding_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        f = self.shown[self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)]
        self._selected_key = f.key
        self._show_fixes(f)
        md = finding_markdown(f) + fix_markdown(self.fix_actions)
        if self.assessment:
            md += "\n\n---\n\n" + device_markdown(self.assessment, f.device, exclude=f.key)
        self.detail.setMarkdown(md)


def fix_markdown(actions) -> str:
    rows = [a for a in actions if a.kind in ("local", "ssh", "copy", "open_url")]
    if not rows:
        return ""
    lines = ["", "### One-click fix", ""]
    seen_cmds = False
    for a in rows:
        lines.append(f"- **{a.label}**: {a.description}")
        if a.kind == "local" and a.plan:
            lines += ["", "  Runs as root on this machine:", ""]
            lines += [f"  `{st.script}`" for st in a.plan.steps]
            lines.append("")
        elif a.kind in ("ssh", "copy") and not seen_cmds:
            seen_cmds = True
            lines += ["", "  Commands for the host:", ""] + [f"  `{c}`" for c in a.commands] + [""]
    return "\n".join(lines)


def finding_markdown(f: Finding) -> str:
    lines = [f"## {f.title}", "",
             f"**{f.severity}** · {f.device_label}" + (f" · {f.service}" if f.service else ""), ""]
    meta = []
    if f.cve_id:
        links = ", ".join(f"[{c.strip()}](https://nvd.nist.gov/vuln/detail/{c.strip()})" for c in f.cve_id.split(","))
        meta.append(f"**CVE:** {links}")
    if f.cvss is not None:
        meta.append(f"**CVSS:** {f.cvss:.1f}")
    meta.append(f"**Confidence:** {f.confidence}")
    meta.append(f"**Source:** {f.source}")
    lines += [" · ".join(meta), ""]
    lines += ["### What was found", "", f.description, ""]
    if f.patch_check:
        lines += _patch_section(f)
    if f.cve_id:
        lines += _cve_section(f)
    if f.exploits:
        lines += _exploit_section(f)
    if f.technique:
        lines += ["### How the attack works", "", f.technique, ""]
    lines += ["### How to fix it", "", f.remediation, ""]
    if f.attck:
        lines += ["### MITRE ATT&CK", ""]
        lines += [f"- [{t}]({attck_mapping.url(t)}) {attck_mapping.name(t)}" for t in f.attck]
    return "\n".join(lines)


def _cell(v) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


def _table(rows: list[tuple[str, object]]) -> list[str]:
    rows = [(k, v) for k, v in rows if v not in (None, "", [])]
    return ["| Field | Value |", "|---|---|"] + [f"| **{k}** | {_cell(v)} |" for k, v in rows] + [""]


VERDICT_TEXT = {
    "patched": "**Fixed on this host** by a distribution security update.",
    "vulnerable": "**Not fixed:** the distribution's security update is not installed.",
    "unknown": "**Can't tell from the network:** verify on the host.",
    "upstream": "**Upstream build:** the version match applies directly.",
}


def _patch_section(f: Finding) -> list[str]:
    c = f.patch_check
    lines = ["### Is it fixed on this system?", "", VERDICT_TEXT.get(c.get("verdict"), ""), "",
             c.get("explanation", ""), ""]
    lines += _table([("Upstream version", c.get("upstream")), ("Distribution", c.get("distro")),
                     ("Package revision (from banner)", c.get("revision") or ("not in banner" if c.get("distro")
                                                                              else "")),
                     ("Fixed in revision", c.get("fixed_revision")), ("Release", c.get("release")),
                     ("Advisory", _advisory_link(c.get("advisory", "")))])
    fixes = f.cve_info.get("distro_fixes", [])
    if fixes:
        lines += ["**Known distribution fixes for this CVE:**", "",
                  "| Distribution | Release | Upstream | Fixed package revision | Advisory |", "|---|---|---|---|---|"]
        lines += [f"| {x['distro']} | {x['release']} | {x['upstream']} | {x['upstream']}-{x['fixed_revision']} | "
                  f"{_advisory_link(x['advisory'])} |" for x in fixes]
        lines.append("")
    if c.get("verdict") in ("unknown", "vulnerable", "patched") and c.get("distro"):
        pkg = c.get("package") or next((x.get("package") for x in fixes if x.get("package")), "") or "<package>"
        cve = f.cve_id.split(",")[0].strip()
        lines += ["**Check on the host itself:**", "",
                  f"- Installed version: `apt policy {pkg}`",
                  f"- Whether the fix is in its changelog: `apt changelog {pkg} | grep {cve}`",
                  "- Install pending security updates: `sudo apt update && sudo apt upgrade`", ""]
    return lines


def _exploit_section(f: Finding) -> list[str]:
    lines = ["### Public exploit modules", "",
             ("A ready-made Metasploit module exists for this issue, so exploiting it takes no skill. That's why it "
              "ranks higher. " if not f.patched else "Public modules exist, but this host has the fix installed. ")
             + "Watchtower never runs these; they're listed so you can prioritize.", "",
             "| Module | Name | Rank | CVE |", "|---|---|---|---|"]
    lines += [f"| `{m['module']}` | {_cell(m['name'])} | {m['rank']} | {m['cve']} |" for m in f.exploits]
    lines.append("")
    return lines


def _advisory_link(adv: str) -> str:
    if adv.startswith("USN-"):
        return f"[{adv}](https://ubuntu.com/security/notices/{adv})"
    if adv.startswith("DSA-"):
        num = adv[4:].split("-")[0]
        return f"[{adv}](https://www.debian.org/security/dsa-{num})"
    return adv


def _cve_section(f: Finding) -> list[str]:
    info = f.cve_info
    cves = [c.strip() for c in f.cve_id.split(",") if c.strip()]
    lines = ["### CVE details", ""]
    affected = []
    for lo, hi in info.get("ranges", []):
        if lo and hi:
            affected.append(f"{lo} up to (not including) {hi}")
        elif hi:
            affected.append(f"below {hi}")
        elif lo:
            affected.append(f"{lo} and later")
        else:
            affected.append("all versions")
    if info.get("exact"):
        affected.append(", ".join(info["exact"]))
    lines += _table([
        ("CVE", ", ".join(cves)), ("CVSS v3", f"{f.cvss:.1f} ({f.severity if not f.patched else 'patched'})"
                                   if f.cvss is not None else ""),
        ("Weakness (CWE)", info.get("cwe")), ("Disclosed", info.get("disclosed")),
        ("Affected upstream versions", "; ".join(affected)), ("Fixed upstream in", info.get("fixed_in")),
        ("Version seen on host", f.version), ("CVSS vector", info.get("vector")),
    ])
    if info.get("exploit_refs"):
        lines += ["**NVD references tagged as exploits:**", ""] + [f"- <{u}>" for u in info["exploit_refs"]] + [""]
    if info.get("references"):
        lines += ["**References:**", ""] + [f"- <{u}>" for u in info["references"][:8]] + [""]
    for c in cves:
        lines.append(f"- {c}: [NVD](https://nvd.nist.gov/vuln/detail/{c}) · "
                     f"[MITRE](https://www.cve.org/CVERecord?id={c}) · "
                     f"[Ubuntu](https://ubuntu.com/security/{c}) · "
                     f"[Debian](https://security-tracker.debian.org/tracker/{c})")
    lines.append("")
    return lines


def device_markdown(a: Assessment, device: str, exclude: str | None = None) -> str:
    """Everything known about one device: identity, what was observed, how its
    risk score adds up, and its findings."""
    risk = a.risk_for(device)
    lines: list[str] = []
    if device in a.networks:
        n = a.networks[device]
        lines += [f"## Network: {n.get('ssid') or '(hidden)'}", ""]
        freq = f" ({n['freq']} MHz)" if n.get("freq") else ""
        signal = (f"{n['signal_dbm']} dBm" if n.get("signal_dbm") is not None else
                  f"{n['signal_pct']}%" if n.get("signal_pct") is not None else "")
        lines += _table([
            ("SSID", n.get("ssid") or "(hidden)"), ("BSSID", n["bssid"]),
            ("Authorized", "yes" if n.get("authorized") else "no (assessed from its broadcast only)"),
            ("Security", n.get("security")), ("Authentication", n.get("auth")), ("Cipher", n.get("cipher")),
            ("WPS", {1: "advertised", 0: "not advertised"}.get(n.get("wps"), "unknown (scan with iw to check)")),
            ("Channel", f"{n['channel']}{freq}" if n.get("channel") else ""), ("Signal", signal),
            ("Clients seen", n.get("clients") or ""),
            ("First seen", (n.get("first_seen") or "")[:19].replace("T", " ")),
            ("Last seen", (n.get("last_seen") or "")[:19].replace("T", " ")), ("Seen by", n.get("source")),
        ])
    elif device in a.hosts:
        h, scan = a.hosts[device]
        lines += [f"## Host: {h.label}", ""]
        os_guess = "; ".join(f"{name} ({acc}%)" for name, acc in h.os_matches[:3])
        lines += _table([
            ("Address", h.address), ("Hostnames", ", ".join(h.hostnames)),
            ("MAC", f"{h.mac} {h.vendor}".strip()), ("Status", h.status), ("OS guess", os_guess),
            ("Not shown", h.closed_summary),
            ("Last scan", f"#{scan.get('id')} at {(scan.get('started') or '')[:19].replace('T', ' ')}"),
            ("Scan command", f"`{scan.get('command', '')}`"),
        ])
        ports = [p for p in h.ports if p.state.startswith("open")]
        if ports:
            lines += ["### Open ports", "", "| Port | Service | Version |", "|---|---|---|"]
            lines += [f"| {p.portid}/{p.protocol} | {_cell(p.service + (' (' + p.tunnel + ')' if p.tunnel else ''))} "
                      f"| {_cell(p.version_string)} |" for p in ports]
            lines.append("")
    elif device in a.web:
        lines += [f"## Web: {device}", ""]
        rows = a.web[device]
        h = rows.get("headers")
        if h:
            snap, _issues = header_audit.result_from_json(h["result_json"])
            if snap:
                lines += _table([
                    ("Header audit", (h.get("finished") or "")[:19].replace("T", " ") + " UTC"),
                    ("Final URL", snap.final_url), ("HTTP status", snap.status or snap.error),
                    ("Redirects", " → ".join(f"{x.status} {x.location}" for x in snap.hops)),
                    ("Note", snap.stopped), ("Server", snap.get("Server") or ""),
                ])
        n = rows.get("nikto")
        if n:
            lines += _table([("Nikto scan", (n.get("finished") or "")[:19].replace("T", " ") + " UTC"),
                             ("Command", f"`{n.get('command', '')}`")])
    elif device in a.domains:
        lines += [f"## Domain: {device}", ""]
        e = a.domains[device].get("email")
        rep = domain_audit.report_from_json(e["result_json"]) if e else None
        if rep:
            lines += _table([
                ("Mail servers (MX)", ", ".join(rep.mx) or "none"), ("SPF", " · ".join(rep.spf) or "none"),
                ("SPF DNS lookups", domain_audit.lookups_text(rep.spf_lookups)),
                ("DMARC", " · ".join(rep.dmarc) or "none"),
                ("DKIM selectors found", ", ".join(sorted(rep.dkim)) or "none of those tried"),
            ])
        s = a.domains[device].get("subdomains")
        if s:
            lines += _table([("Subdomains found", len(subdomain_enum.subs_from_json(s["result_json"]))),
                             ("Source", s.get("tool"))])
    else:
        lines += [f"## {device}", ""]
    if risk:
        b = risk.breakdown
        lines += ["### Risk score", "",
                  f"**{risk.score} / 100** = {b.get('cvss_points', 0):.0f} (6 × worst CVSS "
                  f"{b.get('worst_cvss', 0):.1f}) + {b.get('finding_points', 0):.0f} (finding weights, max 70) + "
                  f"{b.get('port_points', 0):.0f} (open ports, max 15), capped at 100.", ""]
        others = [f for f in risk.findings if f.key != exclude]
        title = "Other findings on this device" if exclude else "Findings on this device"
        if others:
            lines += [f"### {title}", ""]
            lines += [f"- **{f.severity}**: {f.title}" + (f" ({f.port})" if f.port else "") for f in others]
        elif not exclude:
            lines += ["### Findings", "", "No weaknesses found for this device."]
            sec = a.networks.get(device, {}).get("security", "")
            if sec == "WPA3":
                lines += ["", "WPA3-Personal (SAE) only: resistant to offline passphrase guessing, with "
                          "protected management frames. This is the recommended configuration."]
    return "\n".join(lines)
