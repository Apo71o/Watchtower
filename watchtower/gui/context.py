"""Shared application state handed to every tab."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal

from watchtower.core.deps import DependencyState
from watchtower.core.platform_utils import PlatformInfo
from watchtower.core.runner import CommandRunner
from watchtower.storage.audit_log import AuditLog, Entry
from watchtower.storage.db import Database
from watchtower.storage.settings import AUTH_ACK, Settings


class Bus(QObject):
    """Cross-thread signals. Core code calls plain callbacks; these re-emit
    them as Qt signals so widgets update on the GUI thread."""
    audit_appended = Signal(object)          # Entry
    command_started = Signal(str, str)       # command, purpose
    authorization_changed = Signal(bool)
    dependencies_changed = Signal()


@dataclass
class AppContext:
    db: Database
    settings: Settings
    audit: AuditLog
    runner: CommandRunner
    deps: DependencyState
    platform: PlatformInfo
    bus: Bus

    @classmethod
    def create(cls, db: Database, platform: PlatformInfo) -> AppContext:
        settings = Settings(db)
        audit = AuditLog(db)
        runner = CommandRunner(audit)
        bus = Bus()
        audit.subscribe(lambda e: bus.audit_appended.emit(e))
        runner.on_command(lambda cmd, purpose: bus.command_started.emit(cmd, purpose))
        return cls(db, settings, audit, runner, DependencyState(), platform, bus)

    @property
    def authorized(self) -> bool:
        return bool(self.settings.get(AUTH_ACK))


__all__ = ["AppContext", "Bus", "Entry"]
