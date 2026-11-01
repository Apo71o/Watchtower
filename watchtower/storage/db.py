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
    # 2: Wi-Fi observations, authorized scope, scan history
    """
    CREATE TABLE networks (
        bssid       TEXT PRIMARY KEY,          -- upper-case MAC
        ssid        TEXT,
        channel     INTEGER,
        freq        INTEGER,                   -- MHz
        signal_dbm  INTEGER,
        signal_pct  INTEGER,
        security    TEXT,                      -- normalized, e.g. "WPA2", "WPA2/WPA3", "WEP", "Open"
        cipher      TEXT,
        auth        TEXT,                      -- PSK / SAE / MGT / OPN
        wps         INTEGER,                   -- 1 seen, 0 not advertised, NULL unknown
        raw_security TEXT,
        source      TEXT,                      -- nmcli / iwlist / airodump-ng
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        authorized  INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE stations (
        mac         TEXT PRIMARY KEY,
        bssid       TEXT,                      -- NULL when not associated
        power       INTEGER,
        packets     INTEGER,
        probes      TEXT,                      -- comma-separated probed SSIDs
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL
    );

    CREATE TABLE targets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        value       TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- IP, CIDR, nmap range, or hostname
        note        TEXT,
        bssid       TEXT,                      -- network it was added from, if any
        added       TEXT NOT NULL
    );

    CREATE TABLE scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        tool        TEXT NOT NULL,             -- "nmap"
        target      TEXT NOT NULL,
        command     TEXT NOT NULL,
        started     TEXT NOT NULL,
        finished    TEXT,
        exit_code   INTEGER,
        raw_output  TEXT                       -- nmap XML
    );
    CREATE INDEX scans_target ON scans(target, started);
    """,
    # 3: Host Audit results (TLS, SNMP)
    """
    CREATE TABLE host_audits (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        kind        TEXT NOT NULL,             -- "tls" | "snmp"
        host        TEXT NOT NULL,
        port        INTEGER,
        tool        TEXT,                      -- testssl.sh / sslyze / snmpget
        command     TEXT,
        started     TEXT NOT NULL,
        finished    TEXT,
        exit_code   INTEGER,
        raw_output  TEXT,                      -- tool JSON / text
        result_json TEXT                       -- normalized issues / attempts
    );
    CREATE INDEX host_audits_host ON host_audits(host, kind, port, id);
    """,
    # 4: history (Wi-Fi snapshots) and scheduled scans
    """
    CREATE TABLE wifi_snapshots (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        source      TEXT NOT NULL              -- "managed" | "airodump-ng"
    );
    CREATE TABLE wifi_observations (
        snapshot_id INTEGER NOT NULL REFERENCES wifi_snapshots(id) ON DELETE CASCADE,
        bssid TEXT NOT NULL, ssid TEXT, channel INTEGER, signal_dbm INTEGER, signal_pct INTEGER,
        security TEXT, auth TEXT, cipher TEXT, wps INTEGER,
        PRIMARY KEY (snapshot_id, bssid)
    );
    CREATE TABLE schedules (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        target           TEXT NOT NULL,
        profile          TEXT NOT NULL,
        scan_type        TEXT,
        extra            TEXT NOT NULL DEFAULT '',
        os_detect        INTEGER NOT NULL DEFAULT 0,
        vuln             INTEGER NOT NULL DEFAULT 0,
        interval_minutes INTEGER NOT NULL,
        enabled          INTEGER NOT NULL DEFAULT 1,
        created          TEXT NOT NULL,
        last_run         TEXT,
        next_run         TEXT NOT NULL,
        last_status      TEXT
    );
    ALTER TABLE scans ADD COLUMN schedule_id INTEGER;
    """,
    # 5: NVD lookup cache (opt-in feature)
    """
    CREATE TABLE nvd_cache (
        cpe      TEXT PRIMARY KEY,             -- CPE 2.3 match string queried
        fetched  TEXT NOT NULL,
        cves     TEXT NOT NULL                 -- JSON list of parsed CVE summaries
    );
    """,
    # 6: domains the user owns (Domain Audit scope). Web/domain audit results go in host_audits with
    #    kind "headers" / "nikto" (host = normalized URL) or "email" / "subdomains" (host = domain).
    """
    CREATE TABLE owned_domains (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE COLLATE NOCASE,
        note   TEXT,
        added  TEXT NOT NULL
    );
    """,
    # 7: Traffic Audit captures (live or imported pcap) and scheduled captures
    """
    CREATE TABLE captures (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        source      TEXT NOT NULL,             -- "interface:eth0" | "file:/path/to/x.pcap"
        pcap_path   TEXT,
        owned       INTEGER NOT NULL DEFAULT 0, -- 1: Watchtower created the file (may delete it)
        command     TEXT,
        started     TEXT NOT NULL,
        finished    TEXT,
        exit_code   INTEGER,
        packets     INTEGER,
        seconds     REAL,
        stats_json  TEXT,
        events_json TEXT,                      -- parsed events only; never secrets
        error       TEXT,
        schedule_id INTEGER
    );
    CREATE INDEX captures_source ON captures(source, id);
    CREATE TABLE capture_schedules (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        interface        TEXT NOT NULL,
        seconds          INTEGER NOT NULL,
        user_filter      TEXT NOT NULL DEFAULT '',
        interval_minutes INTEGER NOT NULL,
        enabled          INTEGER NOT NULL DEFAULT 1,
        created          TEXT NOT NULL,
        last_run         TEXT,
        next_run         TEXT NOT NULL,
        last_status      TEXT
    );
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
