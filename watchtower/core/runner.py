"""The one place Watchtower runs external programs.

Rules enforced here:
  * argv lists only, never shell=True, so the logged command is exactly what ran.
  * The exact command is written to the audit log BEFORE it starts, and the
    exit code is written as a linked COMMAND_END row afterwards.
  * A missing binary becomes a CommandUnavailable error with a readable
    message, never a raw FileNotFoundError traceback.

Scope enforcement (only touching authorized networks/hosts) is layered on
top of this by the scanning modules from build step 2 onward; this module
deliberately knows nothing about targets beyond recording them.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
from dataclasses import dataclass

from watchtower.core.platform_utils import is_windows
from watchtower.storage.audit_log import AuditLog, Event


def format_command(argv: list[str]) -> str:
    if is_windows():
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


class CommandUnavailable(RuntimeError):
    pass


@dataclass
class CommandResult:
    argv: list[str]
    command: str
    exit_code: int
    stdout: str
    stderr: str
    log_id: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        return self.stdout + (("\n" + self.stderr) if self.stderr else "")


class CommandRunner:
    def __init__(self, audit: AuditLog):
        self.audit = audit
        self._display_hooks: list = []

    def on_command(self, callback) -> None:
        """callback(command_str, purpose) is called just before each run so the
        GUI can show the exact command on screen."""
        self._display_hooks.append(callback)

    def run(
        self,
        argv: list[str],
        *,
        purpose: str,
        target: str | None = None,
        timeout: float | None = 600,
        input_text: str | None = None,
    ) -> CommandResult:
        if not argv:
            raise ValueError("empty argv")
        command = format_command(argv)
        self._announce(command, purpose)
        self._require_binary(argv, command, purpose, target)
        start_id = self.audit.append(Event.COMMAND_START, command=command, target=target,
                                     detail={"purpose": purpose})
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, errors="replace",
                input=input_text, stdin=None if input_text is not None else subprocess.DEVNULL,
                **_popen_flags(),
            )
        except subprocess.TimeoutExpired as exc:
            self.audit.append(Event.COMMAND_END, command=command, target=target,
                              detail={"purpose": purpose, "error": f"timed out after {timeout}s"},
                              exit_code=-1, ref_id=start_id)
            return CommandResult(argv, command, -1, _decode(exc.stdout), _decode(exc.stderr), start_id)
        except OSError as exc:
            self.audit.append(Event.COMMAND_ERROR, command=command, target=target,
                              detail={"purpose": purpose, "error": str(exc)}, ref_id=start_id)
            raise CommandUnavailable(f"Could not run '{argv[0]}': {exc}") from exc

        self.audit.append(Event.COMMAND_END, command=command, target=target,
                          detail={"purpose": purpose}, exit_code=proc.returncode, ref_id=start_id)
        return CommandResult(argv, command, proc.returncode, proc.stdout, proc.stderr, start_id)


    def _announce(self, command: str, purpose: str) -> None:
        for hook in list(self._display_hooks):
            try:
                hook(command, purpose)
            except Exception:
                pass

    def _require_binary(self, argv, command, purpose, target) -> None:
        if shutil.which(argv[0]) is None:
            self.audit.append(Event.COMMAND_ERROR, command=command, target=target,
                              detail={"purpose": purpose, "error": "not installed / not on PATH"})
            raise CommandUnavailable(f"'{argv[0]}' is not installed or not on PATH.")

    def stream(
        self,
        argv: list[str],
        *,
        purpose: str,
        target: str | None = None,
        on_line=None,
        cancel: threading.Event | None = None,
        env: dict | None = None,
    ) -> CommandResult:
        """Like run(), but delivers combined stdout/stderr line by line to
        on_line(str) as it is produced (for long installs and scans). Setting
        `cancel` terminates the process."""
        if not argv:
            raise ValueError("empty argv")
        command = format_command(argv)
        self._announce(command, purpose)
        self._require_binary(argv, command, purpose, target)
        start_id = self.audit.append(Event.COMMAND_START, command=command, target=target,
                                     detail={"purpose": purpose})
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                text=True, errors="replace", bufsize=1, env=env, **_popen_flags(),
            )
        except OSError as exc:
            self.audit.append(Event.COMMAND_ERROR, command=command, target=target,
                              detail={"purpose": purpose, "error": str(exc)}, ref_id=start_id)
            raise CommandUnavailable(f"Could not run '{argv[0]}': {exc}") from exc

        cancelled = False
        if cancel is not None:
            def _watch():
                nonlocal cancelled
                while proc.poll() is None:
                    if cancel.wait(0.3):
                        cancelled = True
                        try:
                            proc.terminate()
                        except OSError:
                            pass
                        return
            threading.Thread(target=_watch, daemon=True).start()

        lines: list[str] = []
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            if on_line:
                on_line(line.rstrip("\n"))
        code = proc.wait()
        detail = {"purpose": purpose}
        if cancelled:
            detail["cancelled"] = True
        self.audit.append(Event.COMMAND_END, command=command, target=target, detail=detail,
                          exit_code=code, ref_id=start_id)
        return CommandResult(argv, command, code, "".join(lines), "", start_id)

    def spawn(self, argv: list[str], *, purpose: str) -> None:
        """Start a detached process (e.g. a terminal window the user interacts
        with). Logged like any other command; its exit code is not tracked."""
        command = format_command(argv)
        self._announce(command, purpose)
        self._require_binary(argv, command, purpose, None)
        self.audit.append(Event.COMMAND_START, command=command,
                          detail={"purpose": purpose, "detached": True})
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=not is_windows())


def _popen_flags() -> dict:
    # Don't flash a console window for every command on Windows.
    if is_windows():
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace")
    return data
