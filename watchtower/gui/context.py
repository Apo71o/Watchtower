"""Shared application state handed to every tab."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal

from watchtower.core.deps import DependencyState
from watchtower.core.platform_utils import PlatformInfo
from watchtower.core.runner import CommandRunner
from watchtower.storage.audit_log import AuditLog, Entry
from watchtower.storage.db import Database
from watchtower.storage.scope import (
    CaptureScheduleStore,
    CaptureStore,
    HostAuditStore,
    Maintenance,
    NetworkStore,
    NvdCache,
    OwnedDomainStore,
    ScanStore,
    ScheduleStore,
    TargetStore,
)
from watchtower.storage.settings import Settings


class Bus(QObject):
    """Cross-thread signals. Core code calls plain callbacks; these re-emit
    them as Qt signals so widgets update on the GUI thread."""
    audit_appended = Signal(object)          # Entry
    command_started = Signal(str, str)       # command, purpose
    targets_changed = Signal()
    interfaces_changed = Signal(object)      # list[WirelessInterface]
    request_scan = Signal(str)               # open Scan a Target with this target filled in
    scan_finished = Signal()                 # new nmap results stored
    networks_changed = Signal()              # Wi-Fi observations or Authorized flags changed
    audit_finished = Signal()                # new Host/Web/Domain Audit results stored
    domains_changed = Signal()               # owned-domain list changed
    captures_changed = Signal()              # a traffic capture finished / was deleted
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
    networks: NetworkStore
    targets: TargetStore
    scans: ScanStore
    audits: HostAuditStore
    schedules: ScheduleStore
    nvd: NvdCache
    maintenance: Maintenance
    domains: OwnedDomainStore
    captures: CaptureStore
    capture_schedules: CaptureScheduleStore

    @classmethod
    def create(cls, db: Database, platform: PlatformInfo) -> AppContext:
        settings = Settings(db)
        audit = AuditLog(db)
        runner = CommandRunner(audit)
        bus = Bus()
        audit.subscribe(lambda e: bus.audit_appended.emit(e))
        runner.on_command(lambda cmd, purpose: bus.command_started.emit(cmd, purpose))
        return cls(db, settings, audit, runner, DependencyState(), platform, bus,
                   NetworkStore(db, audit), TargetStore(db, audit), ScanStore(db), HostAuditStore(db),
                   ScheduleStore(db, audit), NvdCache(db), Maintenance(db), OwnedDomainStore(db, audit),
                   CaptureStore(db), CaptureScheduleStore(db, audit))

    def log_network(self, command: str, purpose: str, target: str | None = None) -> None:
        """Record an outbound request Watchtower makes itself (not via a subprocess):
        audit log NETWORK_REQUEST + Command Console. Safe to call from worker threads."""
        from watchtower.storage.audit_log import Event
        self.audit.append(Event.NETWORK_REQUEST, command=command, target=target, detail={"purpose": purpose})
        self.bus.command_started.emit(command, f"{purpose} (network request)")

    def nvd_enabled(self) -> bool:
        from watchtower.storage.settings import NVD_ENABLED
        return bool(self.settings.get(NVD_ENABLED, False))

    def nvd_lookup(self, cpes: set[str], progress=None) -> tuple[int, int]:
        """Fetch uncached CPEs from NVD (blocking; call from a worker). Every request is logged.
        Returns (CPEs fetched, CVEs found)."""
        import requests

        from watchtower.core import nvd
        from watchtower.storage.audit_log import Event
        from watchtower.storage.settings import NVD_API_KEY

        def on_request(url, params):
            from urllib.parse import urlencode
            full = f"GET {url}?{urlencode(params)}"
            self.audit.append(Event.NETWORK_REQUEST, command=full, detail={"purpose": "NVD CVE lookup"})
            self.bus.command_started.emit(full, "NVD CVE lookup (network request)")

        client = nvd.NvdClient(requests.Session(), self.settings.get(NVD_API_KEY, "") or "", on_request)
        todo = sorted(c for c in cpes if self.nvd.get(c) is None)
        found = 0
        for i, cpe in enumerate(todo, 1):
            if progress:
                progress(f"NVD: {cpe} ({i}/{len(todo)})")
            cves = client.fetch(cpe)
            self.nvd.put(cpe, cves)
            found += len(cves)
        return len(todo), found

    def pwned_online(self, password: str):
        """Check one password against HaveIBeenPwned via k-anonymity. Only the first
        5 hex chars of the SHA-1 are sent; logged as a network request. Blocking."""
        import requests

        from watchtower.core import pwned_check
        from watchtower.storage.audit_log import Event

        def on_request(url):
            self.audit.append(Event.NETWORK_REQUEST, command=f"GET {url}",
                              detail={"purpose": "Pwned Passwords breach check (SHA-1 prefix only)"})
            self.bus.command_started.emit(f"GET {url}", "Pwned Passwords check (k-anonymity: hash prefix only)")

        return pwned_check.check_api(password, requests.Session(), on_request=on_request)


__all__ = ["AppContext", "Bus", "Entry"]
