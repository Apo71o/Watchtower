from __future__ import annotations

from pathlib import Path

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
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from watchtower.core import hash_cracker as hc
from watchtower.core import password_strength as ps
from watchtower.core import pwned_check as pw
from watchtower.core.platform_utils import data_dir
from watchtower.core.runner import format_command
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
        tabs = QTabWidget()
        tabs.addTab(StrengthPanel(ctx), "Strength Analyzer")
        tabs.addTab(BreachPanel(ctx), "Breach Check")
        tabs.addTab(HashRecoveryPanel(ctx), "Hash Recovery")
        lay = QVBoxLayout(self)
        lay.addWidget(tabs)


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
# Hash Recovery (command generator — never runs anything)                     #
# --------------------------------------------------------------------------- #

class HashRecoveryPanel(QWidget):
    """Build — but never run — the exact hashcat/John command to recover a
    password from a hash or file you own (a forgotten ZIP/PDF/Office password,
    an /etc/shadow backup from your own machine, …).

    Consistent with the rest of the app, this is a *command generator*: it shows
    the exact command (the "Copy commands" pattern) for you to run yourself in a
    terminal. Watchtower does not execute the recovery, in keeping with the
    non-negotiable "no attack execution" rule. It is gated on an ownership
    confirmation and records the generated command in the audit log.
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

        self.word_input = QLineEdit()
        wordlists = hc.default_wordlists()
        if wordlists:
            self.word_input.setText(wordlists[0])
        self.word_input.setPlaceholderText("wordlist (dictionary) file, e.g. /usr/share/wordlists/rockyou.txt")
        tip(self.word_input, ("A wordlist of candidate passwords to try (a dictionary attack). Your own file; nothing "
                              "is sent anywhere."))
        self.word_browse = QPushButton("Browse…")
        tip(self.word_browse, "Choose the wordlist file.")

        self.rules_input = QLineEdit()
        self.rules_input.setPlaceholderText("optional: rules file (hashcat -r) or a John rule name")
        tip(self.rules_input, ("Optional transformation rules — a hashcat rules file, or a John rules name. Leave "
                               "blank for a plain dictionary run."))

        self.own_box = QCheckBox("I confirm I own these hashes/files, or am authorized to recover them.")
        tip(self.own_box, ("Required. Watchtower only builds recovery commands for hashes and files you own or are "
                           "authorized to recover. Your confirmation is recorded in the audit log."))

        self.gen_btn = QPushButton("Generate command")
        tip(self.gen_btn, ("Build the exact command for the options above. Watchtower does not run it — you copy and "
                           "run it yourself."))
        self.gen_btn.setEnabled(False)
        self.copy_btn = QPushButton("Copy command")
        tip(self.copy_btn, "Copy the recovery command so you can run it in a terminal.")
        self.copy_btn.setEnabled(False)

        self.output = QPlainTextEdit(readOnly=True)
        self.output.setFont(QFont("monospace"))
        self.output.setPlaceholderText("The generated command appears here. Watchtower never runs it.")

        form = QFormLayout()
        form.addRow("Tool:", self.tool_combo)
        form.addRow("Hash type:", self.type_combo)
        hrow = QHBoxLayout()
        hrow.addWidget(self.hash_input, 1)
        hrow.addWidget(self.hash_browse)
        form.addRow("Hash file:", hrow)
        wrow = QHBoxLayout()
        wrow.addWidget(self.word_input, 1)
        wrow.addWidget(self.word_browse)
        form.addRow("Wordlist:", wrow)
        form.addRow("Rules:", self.rules_input)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.gen_btn)
        btn_row.addWidget(self.copy_btn)
        btn_row.addStretch()

        note = QLabel("Watchtower only builds the command — it never runs a recovery here. Copy it and run it "
                      "yourself in a terminal. Hashes, files and any recovered passwords stay on this machine; only "
                      "the command and the hash-file path are written to the audit log.")
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
        self.own_box.toggled.connect(self._update_enabled)
        self.gen_btn.clicked.connect(self._generate)
        self.copy_btn.clicked.connect(self._copy)

    def _update_enabled(self):
        have_tool = bool(hc.available_tools())
        ok = self.own_box.isChecked() and have_tool
        self.gen_btn.setEnabled(ok)
        restore_tip(self.gen_btn, "" if ok else
                    ("Install hashcat or John the Ripper first." if not have_tool else "Confirm ownership first."))

    def _browse_hash(self):
        path, _ = QFileDialog.getOpenFileName(self, "Hash file")
        if path:
            self.hash_input.setText(path)

    def _browse_word(self):
        path, _ = QFileDialog.getOpenFileName(self, "Wordlist")
        if path:
            self.word_input.setText(path)

    def _extractor_hint(self, htype: hc.HashType) -> str | None:
        """For document hash types, the one-off *2john command to produce the hash file."""
        kind = htype.john_format if htype.john_format in hc.EXTRACTORS else None
        if not kind:
            return None
        found = hc.find_extractor(kind)
        extractor = found or f"{kind}2john"
        return format_command([extractor, "<your-document>"]) + " > hash.txt"

    def _generate(self):
        if not self.own_box.isChecked():
            return
        tool = self.tool_combo.currentData()
        htype = self.type_combo.currentData()
        hash_file = self.hash_input.text().strip()
        wordlist = self.word_input.text().strip()
        rules = self.rules_input.text().strip() or None
        workdir = str(data_dir() / "hash_recovery")
        try:
            Path(workdir).mkdir(parents=True, exist_ok=True)
            job = hc.build(tool, hash_file, htype, wordlist, workdir, rules)
        except hc.CrackError as exc:
            self._job = None
            self.copy_btn.setEnabled(False)
            self.output.setPlainText(f"# Could not build the command:\n# {exc}")
            return

        self._job = job
        crack_cmd = format_command(job.argv)
        show_cmd = format_command(hc.show_argv(job))
        lines: list[str] = []
        extractor = self._extractor_hint(htype)
        if extractor:
            lines += ["# Step 1 — extract the hash from the document (run against the document itself):",
                      extractor, "",
                      "# Step 2 — run the dictionary recovery against that hash file:"]
        else:
            lines.append("# Run the dictionary recovery:")
        lines += [crack_cmd, "", "# Afterwards, list any passwords that were recovered:", show_cmd]
        self.output.setPlainText("\n".join(lines))
        self.copy_btn.setEnabled(True)

        # Audit: records the ownership confirmation and the exact command. Watchtower does NOT run it.
        self.ctx.audit.append(
            Event.CONFIRMATION, command=crack_cmd, target=hash_file or None,
            detail={"purpose": "hash-recovery command generated (not run by Watchtower)",
                    "tool": tool, "hash_type": htype.label})

    def _copy(self):
        if self._job:
            QGuiApplication.clipboard().setText(format_command(self._job.argv))


