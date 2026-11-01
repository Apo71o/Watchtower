"""SQLite storage. One database file in the per-user data dir.

Schema changes go in MIGRATIONS as new entries appended to the end — never
edit an existing entry, since installs that already ran it won't re-run it.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from watchtower.core.platform_utils import data_dir

MIGRATIONS: list[str] = [
    # 1: settings + append-only audit log
    """
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,              -- UTC ISO-8601
        event      TEXT NOT NULL,              -- see storage.audit_log.Event
        command    TEXT,                       -- exact argv, shell-quoted
        target     TEXT,                       -- host/BSSID/interface acted on
        detail     TEXT,                       -- free text / JSON
        exit_code  INTEGER,
        ref_id     INTEGER REFERENCES audit_log(id)  -- links *_end to *_start
    );

    -- Append-only: refuse edits and deletes at the database level.
    CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

    CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    """,
]


class Database:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else data_dir() / "watchtower.db"
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            version = self.conn.execute("PRAGMA user_version").fetchone()[0]
            for i, script in enumerate(MIGRATIONS[version:], start=version + 1):
                self.conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {i};\nCOMMIT;")

    @property
    def schema_version(self) -> int:
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, params)

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def close(self) -> None:
        self.conn.close()
