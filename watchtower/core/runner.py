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
        for hook in list(self._display_hooks):
            try:
                hook(command, purpose)
            except Exception:
                pass

        if shutil.which(argv[0]) is None:
            self.audit.append(Event.COMMAND_ERROR, command=command, target=target,
                              detail={"purpose": purpose, "error": "not installed / not on PATH"})
            raise CommandUnavailable(f"'{argv[0]}' is not installed or not on PATH.")

        start_id = self.audit.append(Event.COMMAND_START, command=command, target=target,
                                     detail={"purpose": purpose})
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
                input=input_text, errors="replace",
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


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace")
    return data
