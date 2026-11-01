"""Confirm-then-run dialog for a deps.Plan, with live output.

Flow: show the exact commands -> user clicks Run -> each step runs in the
background with its output streamed into the dialog. Steps that need root go
through pkexec (graphical password prompt). If pkexec is missing or can't
authenticate, the step is opened in a terminal window running sudo instead,
so it always works somewhere the user can type their password.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout

from watchtower.core import deps
from watchtower.core.runner import CommandUnavailable, format_command
from watchtower.gui.context import AppContext
from watchtower.gui.ui import tip
from watchtower.gui.worker import run_in_background
from watchtower.storage.audit_log import Event


class _Lines(QObject):
    line = Signal(str)


class RunPlanDialog(QDialog):
    finished_ok = Signal(bool)

    def __init__(self, ctx: AppContext, title: str, intro: str, plan: deps.Plan, parent=None):
        super().__init__(parent)
        self.ctx, self.plan, self.title = ctx, plan, title
        self.setWindowTitle(title)
        self.resize(780, 520)
        intro_lbl = QLabel(intro)
        intro_lbl.setWordWrap(True)
        self.text = QPlainTextEdit(readOnly=True)
        self.text.setFont(QFont("monospace"))
        self.text.setPlainText(plan.describe() or "(nothing to run)")
        if plan.manual:
            self.text.appendPlainText("\n# Not installable automatically, do these by hand:\n"
                                      + "\n".join(f"#   {m}" for m in plan.manual))
        self.status = QLabel("Review the commands above, then click Run.")
        self.status.setWordWrap(True)
        self.copy_btn = QPushButton("Copy commands")
        self.copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(plan.describe()))
        self.run_btn = QPushButton("Run")
        self.run_btn.setDefault(True)
        self.run_btn.setEnabled(bool(plan.steps))
        self.close_btn = QPushButton("Cancel")
        tip(self.copy_btn, "Copy the commands so you can run them yourself in a terminal instead.")
        tip(self.run_btn, "Run the commands shown above. You may be asked for your password.")
        tip(self.close_btn, "Close without running anything (or close the window when finished).")
        self.run_btn.clicked.connect(self._run)
        self.close_btn.clicked.connect(self._close)
        row = QHBoxLayout()
        row.addWidget(self.copy_btn)
        row.addStretch()
        row.addWidget(self.run_btn)
        row.addWidget(self.close_btn)
        lay = QVBoxLayout(self)
        lay.addWidget(intro_lbl)
        lay.addWidget(self.text)
        lay.addWidget(self.status)
        lay.addLayout(row)
        self._lines = _Lines()
        self._lines.line.connect(self.text.appendPlainText)
        self._running = False
        self._ran = False

    def _close(self):
        if self._running:
            return
        if not self._ran:
            self.ctx.audit.append(Event.DECLINED, command=self.plan.describe(), detail={"action": self.title})
        self.accept() if self._ran else self.reject()

    def _run(self):
        self.ctx.audit.append(Event.CONFIRMATION, command=self.plan.describe(), detail={"action": self.title})
        self._running = self._ran = True
        self.run_btn.setEnabled(False)
        self.close_btn.setEnabled(False)
        self.close_btn.setText("Close")
        self.text.clear()
        self.status.setText("Running… output appears below. A password prompt may open.")
        run_in_background(self._execute, on_done=self._done, on_error=self._error)

    # runs on a worker thread
    def _execute(self) -> list[str]:
        emit = self._lines.line.emit
        problems: list[str] = []
        for step in self.plan.steps:
            emit(f"\n### {step.label}")
            argv = step.argv
            if step.elevated:
                wrapped = deps.elevate(argv)
                if wrapped is None:
                    problems.append(self._terminal(step, "no graphical password prompt (pkexec) found"))
                    continue
                argv = wrapped
            emit("$ " + format_command(argv))
            try:
                res = self.ctx.runner.stream(argv, purpose=step.label, on_line=emit)
            except CommandUnavailable as exc:
                problems.append(f"{step.label}: {exc}")
                continue
            if step.elevated and argv[0].endswith("pkexec") and res.exit_code in deps.PKEXEC_AUTH_FAILED:
                problems.append(self._terminal(step, "the password prompt was dismissed or unavailable"))
            elif not res.ok:
                problems.append(f"{step.label}: exited with code {res.exit_code} (see output above)")
        return problems

    def _terminal(self, step: deps.Step, why: str) -> str:
        argv = deps.terminal_argv(step.script or format_command(step.argv))
        if argv is None:
            return (f"{step.label}: {why}, and no terminal emulator was found. "
                    "Click 'Copy commands' and run them in a terminal.")
        self._lines.line.emit(f"({why}: opening a terminal window instead; enter your password there)")
        try:
            self.ctx.runner.spawn(argv, purpose=f"{step.label} (in terminal)")
        except CommandUnavailable as exc:
            return f"{step.label}: could not open a terminal: {exc}"
        return f"{step.label}: continuing in the terminal window. When it finishes, click Re-check."

    def _done(self, problems: list[str]):
        self._running = False
        self.close_btn.setEnabled(True)
        if problems:
            self.status.setText("Finished with notes:\n• " + "\n• ".join(problems))
        else:
            self.status.setText("Finished successfully.")
        self.finished_ok.emit(not problems)

    def _error(self, msg: str):
        self._running = False
        self.close_btn.setEnabled(True)
        self.status.setText("Failed.")
        QMessageBox.warning(self, self.title, msg)
