from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
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
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import hash_cracker as hc
from watchtower.core import password_strength as ps
from watchtower.core import pwned_check as pw
from watchtower.core import wordlist_builder as wl
from watchtower.core.platform_utils import data_dir
from watchtower.core.runner import CommandUnavailable, format_command
from watchtower.gui.context import AppContext
from watchtower.gui.ui import restore_tip, tip
from watchtower.gui.worker import run_in_background
from watchtower.storage.audit_log import Event

SCORE_COLORS = ["#b71c1c", "#e53935", "#ef6c00", "#2e7d32", "#1b5e20"]
CHECK_MARK = {True: "✓", False: "✗", None: "–"}
CHECK_COLOR = {True: "#2e7d32", False: "#c62828", None: "#757575"}


class PasswordTab(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.tabs = QTabWidget()
        self.strength = StrengthPanel(ctx)
        self.breach = BreachPanel(ctx)
        self.hashrec = HashRecoveryPanel(ctx)
        self.wordlists = WordlistPanel(ctx, on_use_wordlist=self._use_wordlist)
        self.tabs.addTab(self.strength, "Strength Analyzer")
        self.tabs.addTab(self.breach, "Breach Check")
        self.tabs.addTab(self.hashrec, "Hash Recovery")
        self.tabs.addTab(self.wordlists, "Wordlists")
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)

    def _use_wordlist(self, path: str):
        """Wordlists panel -> put a list into the Hash Recovery panel and show it."""
        self.hashrec.set_wordlist(path)
        self.tabs.setCurrentWidget(self.hashrec)


# --------------------------------------------------------------------------- #
# Strength Analyzer                                                           #
# --------------------------------------------------------------------------- #

class StrengthPanel(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._breached: int | None = None

        self.pw_input = QLineEdit()
        tip(self.pw_input, 'The password to analyze. It never leaves this computer and is never saved or logged.')
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.setPlaceholderText("type or paste a password to analyze (stays on this machine)")
        self.show_box = QCheckBox("Show")
        tip(self.show_box, 'Show the password instead of dots.')
        self.context_input = QLineEdit()
        tip(self.context_input, ("Words about you or the site (name, email, site name). The analysis flags a password"
                                 " that contains them, since attackers try those first."))
        self.context_input.setPlaceholderText("optional: your name, email, site — flagged if reused in the password")

        top = QFormLayout()
        row = QHBoxLayout()
        row.addWidget(self.pw_input, 1)
        row.addWidget(self.show_box)
        top.addRow("Password:", row)
        top.addRow("Context:", self.context_input)

        self.bar = QProgressBar()
        self.bar.setRange(0, 4)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(14)
        self.score_lbl = QLabel("Enter a password.")
        self.score_lbl.setStyleSheet("font-weight: bold;")

        self.crack_table = QTableWidget(0, 2)
        self.crack_table.setHorizontalHeaderLabels(["Attack scenario", "Time to guess"])
        self.crack_table.verticalHeader().setVisible(False)
        self.crack_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.crack_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.crack_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.crack_table.setMaximumHeight(150)

        self.feedback = QLabel()
        self.feedback.setWordWrap(True)
        self.feedback.setStyleSheet("color: #ef6c00;")

        self.checklist = QTableWidget(0, 2)
        self.checklist.setHorizontalHeaderLabels(["NIST 800-63B", "Detail"])
        self.checklist.verticalHeader().setVisible(False)
        self.checklist.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.checklist.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.checklist.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.breach_btn = QPushButton("Also check this password for breaches")
        tip(self.breach_btn, 'Send this password to the Breach Check panel and check it there.')
        self.breach_btn.clicked.connect(self._breach_check)
        self.breach_lbl = QLabel()
        self.breach_lbl.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.bar)
        lay.addWidget(self.score_lbl)
        lay.addWidget(QLabel("<b>Estimated time to guess</b>"))
        lay.addWidget(self.crack_table)
        lay.addWidget(self.feedback)
        lay.addWidget(QLabel("<b>NIST SP 800-63B checklist</b>"))
        lay.addWidget(self.checklist, 1)
        brow = QHBoxLayout()
        brow.addWidget(self.breach_btn)
        brow.addWidget(self.breach_lbl, 1)
        lay.addLayout(brow)

        self.show_box.toggled.connect(
            lambda on: self.pw_input.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        self.pw_input.textChanged.connect(self._reset_breach)
        self.context_input.textChanged.connect(self._analyze)

    def _reset_breach(self):
        self._breached = None
        self.breach_lbl.setText("")
        self.breach_btn.setEnabled(bool(self.pw_input.text()))
        self._analyze()

    def _context_words(self) -> list[str]:
        return [w.strip() for w in self.context_input.text().replace(",", " ").split() if w.strip()]

    def _analyze(self):
        pwd = self.pw_input.text()
        if not pwd:
            self.bar.setValue(0)
            self.score_lbl.setText("Enter a password.")
            self.crack_table.setRowCount(0)
            self.checklist.setRowCount(0)
            self.feedback.setText("")
            return
        r = ps.analyze(pwd, user_inputs=self._context_words(), breached=self._breached)
        self.bar.setValue(r.score)
        self.bar.setStyleSheet(
            f"QProgressBar::chunk {{ background: {SCORE_COLORS[r.score]}; }}"
            " QProgressBar { border: 1px solid #999; }")
        self.score_lbl.setText(f"{r.label}  (score {r.score}/4, zxcvbn backend: {r.backend})")
        self.score_lbl.setStyleSheet(f"font-weight: bold; color: {SCORE_COLORS[r.score]};")
        self.crack_table.setRowCount(len(r.crack_times))
        for i, (scenario, t) in enumerate(r.crack_times.items()):
            self.crack_table.setItem(i, 0, QTableWidgetItem(scenario))
            self.crack_table.setItem(i, 1, QTableWidgetItem(str(t)))
        bits = []
        if r.warning:
            bits.append(f"⚠ {r.warning}")
        bits += [f"• {s}" for s in r.suggestions]
        self.feedback.setText("\n".join(bits))
        self.checklist.setRowCount(len(r.checklist))
        for i, c in enumerate(r.checklist):
            mark = QTableWidgetItem(f"{CHECK_MARK[c.passed]}  {c.name}")
            mark.setForeground(QBrush(QColor(CHECK_COLOR[c.passed])))
            self.checklist.setItem(i, 0, mark)
            detail = QTableWidgetItem(c.detail)
            detail.setToolTip(c.detail)
            self.checklist.setItem(i, 1, detail)

    def _breach_check(self):
        pwd = self.pw_input.text()
        if not pwd:
            return
        self.breach_btn.setEnabled(False)
        self.breach_lbl.setText("Checking (sends only a hash prefix)…")
        run_in_background(self.ctx.pwned_online, pwd, on_done=self._breach_done, on_error=self._breach_err)

    def _breach_done(self, result):
        self.breach_btn.setEnabled(True)
        self._breached = result.count
        if result.breached:
            self.breach_lbl.setText(f"⚠ Seen {result.count:,} times in known breaches — do not use it.")
            self.breach_lbl.setStyleSheet("color: #c62828; font-weight: bold;")
        else:
            self.breach_lbl.setText("Not found in the Pwned Passwords set.")
            self.breach_lbl.setStyleSheet("color: #2e7d32;")
        self._analyze()

    def _breach_err(self, msg):
        self.breach_btn.setEnabled(True)
        self.breach_lbl.setText("Breach check failed: " + msg.split("\n")[0])
        self.breach_lbl.setStyleSheet("color: #c62828;")


# --------------------------------------------------------------------------- #
# Breach Check                                                                #
# --------------------------------------------------------------------------- #

class BreachPanel(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._running = False

        # mode
        mode_box = QGroupBox("Lookup mode")
        self.online = QRadioButton("Online (HaveIBeenPwned, k-anonymity — only a 5-char hash prefix is sent)")
        tip(self.online, ("Ask HaveIBeenPwned. Only the first 5 characters of the password's SHA-1 hash are sent; the"
                          " match is made on this computer."))
        self.offline = QRadioButton("Offline (local Pwned Passwords file — no network at all)")
        tip(self.offline, 'Search a Pwned Passwords file you downloaded. Nothing is sent anywhere.')
        self.online.setChecked(True)
        grp = QButtonGroup(self)
        grp.addButton(self.online)
        grp.addButton(self.offline)
        self.offline_path = QLineEdit()
        tip(self.offline_path, "Path to the downloaded Pwned Passwords file (sorted 'HASH:COUNT' lines).")
        self.offline_path.setPlaceholderText("path to a sorted 'HASH:COUNT' file from the HIBP downloader")
        self.offline_browse = QPushButton("Browse…")
        tip(self.offline_browse, 'Choose the downloaded Pwned Passwords file.')
        self.offline_browse.clicked.connect(self._browse_offline)
        mrow = QHBoxLayout()
        mrow.addWidget(self.offline_path, 1)
        mrow.addWidget(self.offline_browse)
        ml = QVBoxLayout(mode_box)
        ml.addWidget(self.online)
        ml.addWidget(self.offline)
        ml.addLayout(mrow)

        # single
        single_box = QGroupBox("Check one password")
        self.single_input = QLineEdit()
        tip(self.single_input, 'A password to check against known breaches. Never saved or logged.')
        self.single_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.single_show = QCheckBox("Show")
        tip(self.single_show, 'Show the password instead of dots.')
        self.single_btn = QPushButton("Check")
        tip(self.single_btn, 'Check whether this password appears in known data breaches.')
        self.single_result = QLabel()
        self.single_result.setWordWrap(True)
        sr = QHBoxLayout()
        sr.addWidget(self.single_input, 1)
        sr.addWidget(self.single_show)
        sr.addWidget(self.single_btn)
        sl = QVBoxLayout(single_box)
        sl.addLayout(sr)
        sl.addWidget(self.single_result)

        # batch
        batch_box = QGroupBox("Check a list (e.g. an export from your own password manager)")
        self.batch_input = QPlainTextEdit()
        self.batch_input.setPlaceholderText("one password per line")
        self.batch_import = QPushButton("Import file…")
        tip(self.batch_import, ("Load passwords from a text file (one per line), for example a password-manager "
                                "export. Nothing is saved."))
        self.batch_btn = QPushButton("Check all")
        tip(self.batch_btn, 'Check every password in the list and flag the breached ones.')
        self.batch_status = QLabel()
        self.batch_table = QTableWidget(0, 3)
        self.batch_table.setHorizontalHeaderLabels(["Password", "Breach count", "Status"])
        self.batch_table.verticalHeader().setVisible(False)
        self.batch_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.batch_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.batch_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        brow = QHBoxLayout()
        brow.addWidget(self.batch_import)
        brow.addWidget(self.batch_btn)
        brow.addWidget(self.batch_status, 1)
        bl = QVBoxLayout(batch_box)
        bl.addWidget(self.batch_input)
        bl.addLayout(brow)
        bl.addWidget(self.batch_table, 1)

        note = QLabel("Passwords are never shown in full in the audit log, and in online mode only the first 5 "
                      "hex characters of each password's SHA-1 are ever sent — the API returns a batch of "
                      "suffixes and the match is made here.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #757575;")

        lay = QVBoxLayout(self)
        lay.addWidget(mode_box)
        lay.addWidget(single_box)
        lay.addWidget(batch_box, 1)
        lay.addWidget(note)

        self.single_show.toggled.connect(
            lambda on: self.single_input.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        self.single_btn.clicked.connect(self._check_single)
        self.single_input.returnPressed.connect(self._check_single)
        self.batch_import.clicked.connect(self._import_batch)
        self.batch_btn.clicked.connect(self._check_batch)

    def _browse_offline(self):
        path, _ = QFileDialog.getOpenFileName(self, "Pwned Passwords hash file")
        if path:
            self.offline_path.setText(path)
            self.offline.setChecked(True)

    def _checker(self):
        """Returns a callable(password) -> BreachResult for the current mode, or raises."""
        if self.offline.isChecked():
            path = self.offline_path.text().strip()
            if not path:
                raise ValueError("Choose an offline Pwned Passwords file, or switch to Online mode.")
            return lambda pwd: pw.check_offline(pwd, path)
        return self.ctx.pwned_online

    # ---- single ----
    def _check_single(self):
        pwd = self.single_input.text()
        if not pwd or self._running:
            return
        try:
            checker = self._checker()
        except ValueError as exc:
            self.single_result.setText(str(exc))
            return
        self._running = True
        self.single_btn.setEnabled(False)
        self.single_result.setText("Checking…")
        run_in_background(checker, pwd, on_done=self._single_done, on_error=self._single_err)

    def _single_done(self, result):
        self._running = False
        self.single_btn.setEnabled(True)
        if result.breached:
            self.single_result.setText(f"⚠ '{result.password_label}' seen {result.count:,} times in breaches — "
                                       "do not use it.")
            self.single_result.setStyleSheet("color: #c62828; font-weight: bold;")
        else:
            self.single_result.setText(f"'{result.password_label}' not found in the Pwned Passwords set.")
            self.single_result.setStyleSheet("color: #2e7d32;")

    def _single_err(self, msg):
        self._running = False
        self.single_btn.setEnabled(True)
        self.single_result.setText("Failed: " + msg.split("\n")[0])
        self.single_result.setStyleSheet("color: #c62828;")

    # ---- batch ----
    def _import_batch(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import password list", "", "Text (*.txt *.csv);;All files (*)")
        if path:
            try:
                self.batch_input.setPlainText(open(path, encoding="utf-8", errors="replace").read())
            except OSError as exc:
                self.batch_status.setText(f"Couldn't read file: {exc}")

    def _check_batch(self):
        if self._running:
            return
        passwords = [line for line in self.batch_input.toPlainText().splitlines() if line]
        if not passwords:
            self.batch_status.setText("Paste or import at least one password.")
            return
        try:
            checker = self._checker()
        except ValueError as exc:
            self.batch_status.setText(str(exc))
            return
        self._running = True
        self.batch_btn.setEnabled(False)
        unique = len(set(passwords))
        self.batch_status.setText(f"Checking {unique} unique password(s)…")

        def work():
            return pw.check_batch(passwords, checker)

        run_in_background(work, on_done=self._batch_done, on_error=self._batch_err)

    def _batch_done(self, results):
        self._running = False
        self.batch_btn.setEnabled(True)
        self.batch_table.setRowCount(len(results))
        breached = 0
        for r, res in enumerate(results):
            self.batch_table.setItem(r, 0, QTableWidgetItem(res.password_label))
            count = QTableWidgetItem(f"{res.count:,}" if res.count else "0")
            self.batch_table.setItem(r, 1, count)
            status = QTableWidgetItem("BREACHED" if res.breached else "ok")
            status.setForeground(QBrush(QColor("#c62828" if res.breached else "#2e7d32")))
            if res.breached:
                breached += 1
                f = status.font()
                f.setBold(True)
                status.setFont(f)
            self.batch_table.setItem(r, 2, status)
        self.batch_status.setText(f"{breached} of {len(results)} password(s) found in breaches.")

    def _batch_err(self, msg):
        self._running = False
        self.batch_btn.setEnabled(True)
        self.batch_status.setText("Failed: " + msg.split("\n")[0])


# --------------------------------------------------------------------------- #
# Hash Recovery (own hashes/files only)                                       #
# --------------------------------------------------------------------------- #

class _LineEmitter(QObject):
    line = Signal(str)


class HashRecoveryPanel(QWidget):
    """Recover a password from a hash or file you own (a forgotten ZIP/PDF/Office
    password, an /etc/shadow backup from your own machine, …) with hashcat or John.

    You can either **Run** the recovery here — gated on an ownership confirmation
    and a warning, run through CommandRunner (argv, logged) with live output and a
    Cancel button — or **Copy** the exact command and run it yourself in a terminal.
    Per CLAUDE.md non-negotiable #1, in-app execution is permitted ONLY for
    recovering your own hashes/files; the app still never runs network attacks,
    deauth, or any login/default-credential attempts.
    """

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._job: hc.CrackJob | None = None

        self.tool_combo = QComboBox()
        tool_labels = {"hashcat": "hashcat", "john": "John the Ripper"}
        tools = hc.available_tools()
        for t in tools:
            self.tool_combo.addItem(tool_labels.get(t, t), t)
        tip(self.tool_combo, "Which recovery engine the command is built for. Add more under the Dependency check.")

        self.type_combo = QComboBox()
        for ht in hc.HASH_TYPES:
            self.type_combo.addItem(ht.label, ht)
        tip(self.type_combo, ("The kind of hash or file you're recovering. Document types (ZIP, RAR, 7-Zip, Office, "
                              "PDF) need a one-off *2john extraction first — the command for that is shown too."))

        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("file containing the hash (for documents, the *2john output)")
        tip(self.hash_input, ("Path to the file holding the hash you want to recover. It stays on this computer; only "
                              "its path (never its contents) is written to the audit log."))
        self.hash_browse = QPushButton("Browse…")
        tip(self.hash_browse, "Choose the hash file.")

        self.word_picker = QComboBox()
        tip(self.word_picker, ("Pick one of your saved wordlists — lists you've built, downloaded or added in the "
                               "Wordlists tab. Choosing one fills in the path below, so you don't retype it."))
        self.word_input = QLineEdit()
        self.word_input.setPlaceholderText("wordlist (dictionary) file, e.g. /usr/share/wordlists/rockyou.txt")
        tip(self.word_input, ("A wordlist of candidate passwords to try (a dictionary attack). Your own file; nothing "
                              "is sent anywhere."))
        self.word_browse = QPushButton("Browse…")
        tip(self.word_browse, ("Choose a wordlist file. It's remembered in your saved lists so you can pick it next "
                               "time."))
        self.word_forget = QPushButton("Forget")
        tip(self.word_forget, ("Remove the selected saved wordlist from the list above (the file itself is not "
                               "deleted)."))

        self.rules_input = QLineEdit()
        self.rules_input.setPlaceholderText("optional: rules file (hashcat -r) or a John rule name")
        tip(self.rules_input, ("Optional transformation rules — a hashcat rules file, or a John rules name. Leave "
                               "blank for a plain dictionary run."))

        self.own_box = QCheckBox("I confirm I own these hashes/files, or am authorized to recover them.")
        tip(self.own_box, ("Required. Watchtower only builds recovery commands for hashes and files you own or are "
                           "authorized to recover. Your confirmation is recorded in the audit log."))

        self.run_btn = QPushButton("Run recovery")
        tip(self.run_btn, ("Run the recovery here against the hash file above. You'll see the exact command and a "
                           "warning first. Only for hashes/files you own."))
        self.run_btn.setEnabled(False)
        self.cancel_btn = QPushButton("Cancel")
        tip(self.cancel_btn, "Stop the running recovery.")
        self.cancel_btn.setEnabled(False)
        self.gen_btn = QPushButton("Show command")
        tip(self.gen_btn, "Build and show the exact command without running it (for running yourself in a terminal).")
        self.gen_btn.setEnabled(False)
        self.copy_btn = QPushButton("Copy command")
        tip(self.copy_btn, "Copy the recovery command so you can run it in a terminal.")
        self.copy_btn.setEnabled(False)

        self.output = QPlainTextEdit(readOnly=True)
        self.output.setFont(QFont("monospace"))
        self.output.setPlaceholderText("The command and any live output / recovered passwords appear here.")
        self._lines = _LineEmitter()
        self._lines.line.connect(self.output.appendPlainText)
        self._running = False
        self.cancel_event: threading.Event | None = None
        self._run_job: hc.CrackJob | None = None

        form = QFormLayout()
        form.addRow("Tool:", self.tool_combo)
        form.addRow("Hash type:", self.type_combo)
        hrow = QHBoxLayout()
        hrow.addWidget(self.hash_input, 1)
        hrow.addWidget(self.hash_browse)
        form.addRow("Hash file:", hrow)
        prow = QHBoxLayout()
        prow.addWidget(self.word_picker, 1)
        prow.addWidget(self.word_forget)
        form.addRow("Saved lists:", prow)
        wrow = QHBoxLayout()
        wrow.addWidget(self.word_input, 1)
        wrow.addWidget(self.word_browse)
        form.addRow("Wordlist:", wrow)
        form.addRow("Rules:", self.rules_input)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.run_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.gen_btn)
        btn_row.addWidget(self.copy_btn)

        note = QLabel("Only run this for hashes or files you own. The recovery runs locally (nothing is sent "
                      "anywhere); the exact command and its start/finish are written to the audit log, but recovered "
                      "passwords are shown only here, never logged. Prefer your own terminal? Use Copy command.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #757575;")

        lay = QVBoxLayout(self)
        if not tools:
            warn = QLabel("Neither hashcat nor John the Ripper is installed, so no command can be built. "
                          "Install one from the Dependency check, then reopen this tab.")
            warn.setWordWrap(True)
            warn.setStyleSheet("color: #c62828;")
            lay.addWidget(warn)
            self.own_box.setEnabled(False)
            restore_tip(self.own_box, "Install hashcat or John the Ripper first.")
        lay.addLayout(form)
        lay.addWidget(self.own_box)
        lay.addLayout(btn_row)
        lay.addWidget(self.output, 1)
        lay.addWidget(note)

        self.hash_browse.clicked.connect(self._browse_hash)
        self.word_browse.clicked.connect(self._browse_word)
        self.word_picker.activated.connect(self._pick_wordlist)
        self.word_forget.clicked.connect(self._forget_wordlist)
        self.own_box.toggled.connect(self._update_enabled)
        self.run_btn.clicked.connect(self._run)
        self.cancel_btn.clicked.connect(self._cancel)
        self.gen_btn.clicked.connect(self._generate)
        self.copy_btn.clicked.connect(self._copy)
        self.ctx.bus.wordlists_changed.connect(self._refresh_wordlists)
        self._refresh_wordlists()

    def _refresh_wordlists(self):
        self.word_picker.blockSignals(True)
        self.word_picker.clear()
        self.word_picker.addItem("— choose a saved wordlist —", "")
        known = wl.known_wordlists(self.ctx.settings)
        for label, path in known:
            self.word_picker.addItem(label, path)
        cur = self.word_input.text().strip()
        if not cur and known:                       # sensible default on first open
            cur = known[0][1]
            self.word_input.setText(cur)
        match = next((i for i in range(self.word_picker.count()) if self.word_picker.itemData(i) == cur), 0)
        self.word_picker.setCurrentIndex(match)
        self.word_picker.blockSignals(False)

    def _pick_wordlist(self, index: int):
        path = self.word_picker.itemData(index)
        if path:
            self.word_input.setText(path)

    def _forget_wordlist(self):
        path = self.word_picker.currentData()
        if path:
            wl.remove_wordlist(self.ctx.settings, path)
            self.ctx.bus.wordlists_changed.emit()

    def _update_enabled(self):
        have_tool = bool(hc.available_tools())
        ok = self.own_box.isChecked() and have_tool and not self._running
        why = "" if ok else ("Install hashcat or John the Ripper first." if not have_tool
                             else "Finish the running recovery first." if self._running
                             else "Confirm ownership first.")
        for btn in (self.run_btn, self.gen_btn):
            btn.setEnabled(ok)
            restore_tip(btn, why)

    def _browse_hash(self):
        path, _ = QFileDialog.getOpenFileName(self, "Hash file")
        if path:
            self.hash_input.setText(path)

    def _browse_word(self):
        path, _ = QFileDialog.getOpenFileName(self, "Wordlist")
        if path:
            self.word_input.setText(path)
            wl.add_wordlist(self.ctx.settings, path)
            self.ctx.bus.wordlists_changed.emit()

    def _make_job(self):
        """Build the CrackJob from the current inputs. Returns (job, error_str)."""
        workdir = str(data_dir() / "hash_recovery")
        try:
            Path(workdir).mkdir(parents=True, exist_ok=True)
            job = hc.build(self.tool_combo.currentData(), self.hash_input.text().strip(),
                           self.type_combo.currentData(), self.word_input.text().strip(), workdir,
                           self.rules_input.text().strip() or None)
            return job, None
        except hc.CrackError as exc:
            return None, str(exc)

    def _generate(self):
        if not self.own_box.isChecked():
            return
        job, err = self._make_job()
        if err:
            self._job = None
            self.copy_btn.setEnabled(False)
            self.output.setPlainText(f"# Could not build the command:\n# {err}")
            return

        self._job = job
        htype = self.type_combo.currentData()
        crack_cmd = format_command(job.argv)
        show_cmd = format_command(hc.show_argv(job))
        lines: list[str] = []
        if job.extract_argv:
            lines += [f"# Step 1 — extract the hash from {job.document}:",
                      format_command(job.extract_argv) + "  > " + job.hash_file, "",
                      "# Step 2 — recover the password from that hash:"]
        else:
            lines.append("# Recover the password:")
        lines += [crack_cmd, "", "# Afterwards, list any recovered passwords:", show_cmd]
        self.output.setPlainText("\n".join(lines))
        self.copy_btn.setEnabled(True)

        # Audit: records the ownership confirmation and the exact command (this path does not run it).
        self.ctx.audit.append(
            Event.CONFIRMATION, command=crack_cmd, target=job.hash_file or None,
            detail={"purpose": "hash-recovery command generated (not run)",
                    "tool": job.tool, "hash_type": htype.label})

    def _copy(self):
        if self._job:
            QGuiApplication.clipboard().setText(format_command(self._job.argv))

    # ---- run it here (own hashes only; CLAUDE.md non-negotiable #1 carve-out) ----
    def _run(self):
        if self._running or not self.own_box.isChecked():
            return
        job, err = self._make_job()
        if err:
            self.output.setPlainText(f"# Could not build the command:\n# {err}")
            return
        command = format_command(job.argv)
        extra = (f"\nFirst it extracts the hash from the document with:\n    {format_command(job.extract_argv)}\n"
                 if job.extract_argv else "")
        confirm = QMessageBox.warning(
            self, "Run password recovery?",
            "This runs a password-cracking tool against:\n\n"
            f"    {job.document or job.hash_file}\n\n"
            "Only do this for hashes or files you own or are authorized to recover. It can use heavy CPU/GPU "
            f"and may run for a long time — you can Cancel.{extra}\nThe recovery command is:\n\n    {command}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            self.ctx.audit.append(Event.DECLINED, command=command, target=job.hash_file or None,
                                  detail={"purpose": "hash recovery (in-app run)"})
            return

        self._run_job = job
        self.ctx.audit.append(Event.CONFIRMATION, command=command, target=(job.document or job.hash_file) or None,
                              detail={"purpose": "hash recovery (in-app run authorized)",
                                      "tool": job.tool, "hash_type": job.hash_type.label})
        self._running = True
        self.cancel_event = threading.Event()
        self.cancel_btn.setEnabled(True)
        self.copy_btn.setEnabled(False)
        self._update_enabled()
        self.output.clear()
        cancel = self.cancel_event

        def work():
            if job.extract_argv:
                self._lines.line.emit("$ " + format_command(job.extract_argv) + "  > " + job.hash_file)
                ext = self.ctx.runner.run(job.extract_argv, purpose="extract document hash", target=job.document)
                if ext.exit_code != 0 or not ext.stdout.strip():
                    first = (ext.stdout or "no output").strip().splitlines()[0:1]
                    raise RuntimeError("could not extract a hash from the document"
                                       + (f" ({first[0][:160]})" if first else ""))
                Path(job.hash_file).write_text(ext.stdout, encoding="utf-8")
                self._lines.line.emit(f"# extracted hash -> {job.hash_file}")
            self._lines.line.emit("$ " + format_command(job.argv) + "\n")
            result = self.ctx.runner.stream(job.argv, purpose="hash recovery", target=job.hash_file,
                                             on_line=self._lines.line.emit, cancel=cancel)
            return self._recovered(job, result)

        run_in_background(work, on_done=self._run_done, on_error=self._run_error)

    def _recovered(self, job, result):
        """(hash, plaintext) pairs after a run. hashcat: from the potfile; John: from `--show`,
        but ONLY when John reports at least one cracked hash (otherwise its output is a diagnostic
        or error, not a result — never parse that as a password)."""
        if job.tool == "hashcat":
            return hc.read_cracked(job)
        try:
            shown = self.ctx.runner.run(hc.show_argv(job), purpose="list recovered passwords", target=job.hash_file)
        except CommandUnavailable:
            return []
        if hc.john_show_count(shown.stdout) > 0:
            return hc.parse_cracked("john", shown.stdout)
        return []

    def _cancel(self):
        if self.cancel_event:
            self.cancel_event.set()
            self._lines.line.emit("\n# Cancelling…")

    def _reset_after_run(self):
        self._running = False
        self.cancel_event = None
        self.cancel_btn.setEnabled(False)
        self.copy_btn.setEnabled(self._run_job is not None)
        self._update_enabled()

    def _run_done(self, recovered):
        self._reset_after_run()
        self._lines.line.emit("")
        if recovered:
            self._lines.line.emit(f"# Recovered {len(recovered)} password(s):")
            for h, pw in recovered:
                self._lines.line.emit(f"#   {h}:{pw}")
        else:
            self._lines.line.emit("# No password recovered (wordlist exhausted, or run cancelled).")

    def _run_error(self, msg: str):
        self._reset_after_run()
        self._lines.line.emit("\n# Failed: " + msg.split("\n")[0])

    def set_wordlist(self, path: str):
        """Fill in the wordlist path and remember it (used by the Wordlists panel)."""
        self.word_input.setText(path)
        wl.add_wordlist(self.ctx.settings, path)
        self.ctx.bus.wordlists_changed.emit()


# --------------------------------------------------------------------------- #
# Wordlists — build, clean up, and fetch wordlists (all local but installs)   #
# --------------------------------------------------------------------------- #

class WordlistPanel(QWidget):
    """Create and manage wordlists for the hashes/files you audit.

    A wordlist is just a text file of candidate passwords; building one is local
    and does no cracking. The only action that reaches the network is installing
    the big public lists, which runs a visible, logged command (apt / git) in
    RunPlanDialog — never a silent download.
    """

    def __init__(self, ctx: AppContext, on_use_wordlist=None, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._on_use = on_use_wordlist

        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.addWidget(self._build_group())
        lay.addWidget(self._starter_group())
        lay.addWidget(self._merge_group())
        lay.addWidget(self._install_group())
        lay.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ---- build a targeted list ----
    def _build_group(self) -> QGroupBox:
        box = QGroupBox("Build a targeted list")
        self.base_input = QPlainTextEdit()
        self.base_input.setPlaceholderText("one word per line: names, pets, dates, company, keywords…")
        self.base_input.setToolTip("Words related to whatever you're auditing. Watchtower builds the variations an "
                                   "attacker would try from them. Everything stays on this machine.")
        self.base_input.setMaximumHeight(110)

        self.cb_case = QCheckBox("Case variations (word, Word, WORD)")
        self.cb_case.setChecked(True)
        tip(self.cb_case, "Add lower-case, Capitalised and UPPER-CASE forms of each word.")
        self.cb_leet = QCheckBox("Leet-speak (a→@, e→3, o→0 …)")
        tip(self.cb_leet, "Also add a form with letters swapped for look-alike symbols/digits.")
        self.cb_digits = QCheckBox("Append common numbers (1, 123, 2024 …)")
        tip(self.cb_digits, "Add common trailing numbers people put on the end of passwords.")
        self.cb_years = QCheckBox("Append years")
        tip(self.cb_years, "Add a four-digit year on the end, across the range on the right.")
        self.year_from = QSpinBox()
        self.year_from.setRange(1950, wl._this_year() + 1)
        self.year_from.setValue(2000)
        tip(self.year_from, "First year to append.")
        self.year_to = QSpinBox()
        self.year_to.setRange(1950, wl._this_year() + 1)
        self.year_to.setValue(wl._this_year())
        tip(self.year_to, "Last year to append.")
        self.cb_symbols = QCheckBox("Append common symbols (!, @, # …)")
        tip(self.cb_symbols, "Add common trailing symbols.")
        self.cb_combine = QCheckBox("Combine pairs of words")
        tip(self.cb_combine, "Also try each pair of base words joined together (e.g. 'spot' + 'smith').")

        self.max_spin = QSpinBox()
        self.max_spin.setRange(100, 5_000_000)
        self.max_spin.setSingleStep(1000)
        self.max_spin.setValue(wl.BuildOptions.max_entries)
        self.max_spin.setGroupSeparatorShown(True)
        tip(self.max_spin, "Hard cap on how many entries to generate, so the list can't explode.")

        self.preview_btn = QPushButton("Preview")
        tip(self.preview_btn, "Build the list now and show how many entries it has, plus a sample.")
        self.save_btn = QPushButton("Save to file…")
        tip(self.save_btn, "Build the list and save it as a text file you can use in Hash Recovery.")
        self.build_count = QLabel()
        self.build_count.setWordWrap(True)
        self.preview_box = QPlainTextEdit(readOnly=True)
        self.preview_box.setFont(QFont("monospace"))
        self.preview_box.setPlaceholderText("A sample of the generated list appears here.")
        self.preview_box.setMaximumHeight(140)

        yrow = QHBoxLayout()
        yrow.addWidget(self.cb_years)
        yrow.addWidget(self.year_from)
        yrow.addWidget(QLabel("to"))
        yrow.addWidget(self.year_to)
        yrow.addStretch()

        opts = QVBoxLayout()
        opts.addWidget(self.cb_case)
        opts.addWidget(self.cb_leet)
        opts.addWidget(self.cb_digits)
        opts.addLayout(yrow)
        opts.addWidget(self.cb_symbols)
        opts.addWidget(self.cb_combine)

        maxrow = QHBoxLayout()
        maxrow.addWidget(QLabel("Max entries:"))
        maxrow.addWidget(self.max_spin)
        maxrow.addStretch()
        maxrow.addWidget(self.preview_btn)
        maxrow.addWidget(self.save_btn)

        lay = QVBoxLayout(box)
        lay.addWidget(QLabel("Base words (one per line):"))
        lay.addWidget(self.base_input)
        lay.addLayout(opts)
        lay.addLayout(maxrow)
        lay.addWidget(self.build_count)
        lay.addWidget(self.preview_box)

        self.preview_btn.clicked.connect(self._preview)
        self.save_btn.clicked.connect(self._save_build)
        return box

    def _options(self) -> wl.BuildOptions:
        return wl.BuildOptions(
            case_variants=self.cb_case.isChecked(), leet=self.cb_leet.isChecked(),
            append_digits=self.cb_digits.isChecked(), append_years=self.cb_years.isChecked(),
            append_symbols=self.cb_symbols.isChecked(), combine_words=self.cb_combine.isChecked(),
            year_start=min(self.year_from.value(), self.year_to.value()),
            year_end=max(self.year_from.value(), self.year_to.value()),
            max_entries=self.max_spin.value())

    def _generate(self):
        base = [ln for ln in self.base_input.toPlainText().splitlines() if ln.strip()]
        if not base:
            return None, None, False
        words, truncated = wl.generate(base, self._options())
        return base, words, truncated

    def _preview(self):
        base, words, truncated = self._generate()
        if base is None:
            self.build_count.setText("Enter at least one base word above.")
            self.preview_box.clear()
            return
        cap = " (capped — raise Max entries for more)" if truncated else ""
        self.build_count.setText(f"{len(words):,} entries{cap}. Showing the first 200.")
        self.preview_box.setPlainText("\n".join(words[:200]))

    def _save_build(self):
        base, words, truncated = self._generate()
        if base is None:
            self.build_count.setText("Enter at least one base word above.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save wordlist", "wordlist.txt", "Text (*.txt);;All files (*)")
        if not path:
            return
        try:
            n = wl.write_list(path, words)
        except OSError as exc:
            QMessageBox.warning(self, "Couldn't save", str(exc))
            return
        wl.add_wordlist(self.ctx.settings, path)       # remember it for the picker
        self.ctx.bus.wordlists_changed.emit()
        cap = " (list was capped — raise Max entries for more)" if truncated else ""
        self.build_count.setText(f"Saved {n:,} entries to {path}{cap} — added to your saved lists.")
        if self._on_use and QMessageBox.question(
                self, "Use this list?", f"Saved {n:,} entries.\n\nUse it in Hash Recovery now?"
        ) == QMessageBox.StandardButton.Yes:
            self._on_use(path)

    # ---- bundled starter lists ----
    def _starter_group(self) -> QGroupBox:
        box = QGroupBox("Starter lists (included)")
        self.starter_table = QTableWidget(0, 3)
        self.starter_table.setHorizontalHeaderLabels(["List", "Entries", "What it is"])
        self.starter_table.verticalHeader().setVisible(False)
        self.starter_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.starter_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.starter_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.starter_table.setMaximumHeight(130)
        self._bundled = wl.bundled_wordlists()
        self.starter_table.setRowCount(len(self._bundled))
        for r, b in enumerate(self._bundled):
            self.starter_table.setItem(r, 0, QTableWidgetItem(b.name))
            self.starter_table.setItem(r, 1, QTableWidgetItem(f"{b.count:,}"))
            self.starter_table.setItem(r, 2, QTableWidgetItem(b.description))

        self.use_btn = QPushButton("Use in Hash Recovery")
        tip(self.use_btn, "Load the selected starter list into the Hash Recovery wordlist box.")
        self.copy_path_btn = QPushButton("Copy path")
        tip(self.copy_path_btn, "Copy the selected list's file path to the clipboard.")
        self.savecopy_btn = QPushButton("Save a copy…")
        tip(self.savecopy_btn, "Save a copy of the selected starter list somewhere you choose.")

        row = QHBoxLayout()
        row.addWidget(self.use_btn)
        row.addWidget(self.copy_path_btn)
        row.addWidget(self.savecopy_btn)
        row.addStretch()

        lay = QVBoxLayout(box)
        if not self._bundled:
            lay.addWidget(QLabel("No starter lists are installed with this build."))
        lay.addWidget(self.starter_table)
        lay.addLayout(row)

        self.use_btn.clicked.connect(self._use_starter)
        self.copy_path_btn.clicked.connect(self._copy_starter_path)
        self.savecopy_btn.clicked.connect(self._save_starter_copy)
        return box

    def _selected_bundled(self):
        r = self.starter_table.currentRow()
        if 0 <= r < len(self._bundled):
            return self._bundled[r]
        return None

    def _use_starter(self):
        b = self._selected_bundled()
        if b and self._on_use:
            self._on_use(str(b.path))

    def _copy_starter_path(self):
        b = self._selected_bundled()
        if b:
            QGuiApplication.clipboard().setText(str(b.path))

    def _save_starter_copy(self):
        b = self._selected_bundled()
        if not b:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save a copy", b.path.name, "Text (*.txt);;All files (*)")
        if not path:
            return
        try:
            wl.write_list(path, b.path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError as exc:
            QMessageBox.warning(self, "Couldn't save", str(exc))

    # ---- merge / clean up ----
    def _merge_group(self) -> QGroupBox:
        box = QGroupBox("Combine / clean up lists")
        self.files_list = QListWidget()
        self.files_list.setMaximumHeight(90)
        self.add_files_btn = QPushButton("Add files…")
        tip(self.add_files_btn, "Choose one or more wordlist files to combine.")
        self.clear_files_btn = QPushButton("Clear")
        tip(self.clear_files_btn, "Remove all chosen files from the list.")
        self.cb_dedupe = QCheckBox("Remove duplicates")
        self.cb_dedupe.setChecked(True)
        tip(self.cb_dedupe, "Keep only the first occurrence of each line.")
        self.cb_sort = QCheckBox("Sort A–Z")
        tip(self.cb_sort, "Sort the merged list alphabetically.")
        self.merge_btn = QPushButton("Merge to file…")
        tip(self.merge_btn, "Combine the chosen files (blank lines dropped) and save the result.")
        self.merge_status = QLabel()
        self.merge_status.setWordWrap(True)

        top = QHBoxLayout()
        top.addWidget(self.add_files_btn)
        top.addWidget(self.clear_files_btn)
        top.addStretch()
        bottom = QHBoxLayout()
        bottom.addWidget(self.cb_dedupe)
        bottom.addWidget(self.cb_sort)
        bottom.addStretch()
        bottom.addWidget(self.merge_btn)

        lay = QVBoxLayout(box)
        lay.addLayout(top)
        lay.addWidget(self.files_list)
        lay.addLayout(bottom)
        lay.addWidget(self.merge_status)

        self.add_files_btn.clicked.connect(self._add_merge_files)
        self.clear_files_btn.clicked.connect(lambda: (self.files_list.clear(), self.merge_status.clear()))
        self.merge_btn.clicked.connect(self._merge)
        return box

    def _add_merge_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Add wordlists", "", "Text (*.txt *.lst);;All files (*)")
        for p in paths:
            self.files_list.addItem(p)

    def _merge(self):
        paths = [self.files_list.item(i).text() for i in range(self.files_list.count())]
        if not paths:
            self.merge_status.setText("Add at least one file first.")
            return
        out, _ = QFileDialog.getSaveFileName(self, "Save merged list", "merged.txt", "Text (*.txt);;All files (*)")
        if not out:
            return
        try:
            lines, total = wl.merge_files(paths, dedupe=self.cb_dedupe.isChecked(), sort=self.cb_sort.isChecked())
            n = wl.write_list(out, lines)
        except (ValueError, OSError) as exc:
            self.merge_status.setText(f"Failed: {exc}")
            return
        removed = total - n
        self.merge_status.setText(
            f"Saved {n:,} entries to {out} (read {total:,}, removed {removed:,} duplicates/blanks).")

    # ---- install the big lists ----
    def _install_group(self) -> QGroupBox:
        box = QGroupBox("Get more wordlists")
        note = QLabel("These download standard public wordlists. Watchtower shows the exact command first and logs "
                      "it — nothing is downloaded silently. Downloaded lists are added to your saved lists, so Hash "
                      "Recovery can pick them without retyping a path.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #757575;")
        self.rockyou_btn = QPushButton("Download rockyou…")
        tip(self.rockyou_btn, "Download the rockyou list from SecLists into your data folder (no password needed). "
                              "Works on any distro — it doesn't rely on a system package.")
        self.seclists_btn = QPushButton("Download SecLists (git)…")
        tip(self.seclists_btn, "Clone the SecLists collection into your data folder with git. No password needed; "
                               "it is large.")
        row = QHBoxLayout()
        row.addWidget(self.rockyou_btn)
        row.addWidget(self.seclists_btn)
        row.addStretch()
        lay = QVBoxLayout(box)
        lay.addWidget(note)
        lay.addLayout(row)
        self.rockyou_btn.clicked.connect(self._install_rockyou)
        self.seclists_btn.clicked.connect(self._install_seclists)
        return box

    def _run_plan(self, title: str, intro: str, plan):
        from watchtower.gui.run_dialog import RunPlanDialog
        RunPlanDialog(self.ctx, title, intro, plan, self).exec()

    def _install_rockyou(self):
        dest = str(data_dir() / "wordlists")
        intro = (f"This downloads the rockyou list from SecLists into {dest} (no password needed) and unpacks it. "
                 "The command is shown below and written to the audit log. It works on any distro — it does not rely "
                 "on a system 'wordlists' package, which Ubuntu doesn't provide.")
        self._run_plan("Download rockyou", intro, wl.rockyou_plan(dest))
        rockyou = Path(dest) / "rockyou.txt"
        if rockyou.is_file():
            wl.add_wordlist(self.ctx.settings, str(rockyou))
            self.ctx.bus.wordlists_changed.emit()
            if self._on_use and QMessageBox.question(
                    self, "Use rockyou?", "rockyou.txt is ready and added to your saved lists.\n\n"
                    "Use it in Hash Recovery now?") == QMessageBox.StandardButton.Yes:
                self._on_use(str(rockyou))

    def _install_seclists(self):
        dest = str(data_dir() / "wordlists" / "SecLists")
        intro = (f"This clones the SecLists collection from GitHub into {dest} using git (no password needed). "
                 "It is several hundred MB. The command is shown below and written to the audit log.")
        self._run_plan("Download SecLists", intro, wl.seclists_plan(dest))


