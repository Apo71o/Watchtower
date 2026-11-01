"""Append-only audit log of every command run and every user confirmation.

The table has database triggers rejecting UPDATE/DELETE, so a finished
command is recorded as a second COMMAND_END row pointing at its COMMAND_START
row rather than by editing the start row.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum

from watchtower.storage.db import Database


class Event(StrEnum):
    COMMAND_START = "command_start"
    COMMAND_END = "command_end"
    COMMAND_ERROR = "command_error"      # could not launch (missing binary, etc.)
    CONFIRMATION = "user_confirmation"   # user explicitly OK'd an action
    DECLINED = "user_declined"
    AUTHORIZATION_ACK = "authorization_ack"
    SCOPE_CHANGE = "scope_change"        # network/host marked (un)authorized
    APP_START = "app_start"
    NETWORK_REQUEST = "network_request"  # outbound HTTP (NVD only, when enabled)
    REMEDIATION = "remediation"          # user applied / launched a fix for a finding


@dataclass
class Entry:
    id: int
    ts: str
    event: str
    command: str | None
    target: str | None
    detail: str | None
    exit_code: int | None
    ref_id: int | None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, db: Database):
        self.db = db
        self._listeners: list = []

    def subscribe(self, callback) -> None:
        """callback(entry: Entry) is called after each append (any thread)."""
        self._listeners.append(callback)

    def append(
        self,
        event: Event,
        *,
        command: str | None = None,
        target: str | None = None,
        detail: str | dict | None = None,
        exit_code: int | None = None,
        ref_id: int | None = None,
    ) -> int:
        if isinstance(detail, dict):
            detail = json.dumps(detail, sort_keys=True)
        ts = _now()
        cur = self.db.execute(
            "INSERT INTO audit_log(ts, event, command, target, detail, exit_code, ref_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, Event(event).value, command, target, detail, exit_code, ref_id),
        )
        entry = Entry(cur.lastrowid, ts, Event(event).value, command, target, detail, exit_code, ref_id)
        for cb in list(self._listeners):
            try:
                cb(entry)
            except Exception:
                pass
        return entry.id

    def entries(self, limit: int | None = None) -> list[Entry]:
        sql = "SELECT * FROM audit_log ORDER BY id DESC"
        params: tuple = ()
        if limit:
            sql += " LIMIT ?"
            params = (limit,)
        return [Entry(**dict(r)) for r in self.db.query(sql, params)]

    def export_json(self) -> str:
        return json.dumps([asdict(e) for e in reversed(self.entries())], indent=2)

    def export_csv(self) -> str:
        buf = io.StringIO()
        fields = list(Entry.__dataclass_fields__)
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for e in reversed(self.entries()):
            writer.writerow(asdict(e))
        return buf.getvalue()
