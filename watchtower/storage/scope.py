"""Persistence for seen Wi-Fi networks/stations, the authorized-target list,
and scan history. Every scope change is written to the audit log."""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone

from watchtower.core.targets import in_scope, parse_target
from watchtower.storage.audit_log import AuditLog, Event
from watchtower.storage.db import Database


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class NetworkStore:
    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def record(self, aps, stations=(), source: str = "") -> None:
        """Upsert observations from a scan. `aps` are wifi_scan.AccessPoint,
        `stations` wifi_scan.Station. Never touches the authorized flag."""
        ts = now()
        for ap in aps:
            self.db.execute(
                """INSERT INTO networks(bssid, ssid, channel, freq, signal_dbm, signal_pct, security, cipher,
                                        auth, wps, raw_security, source, first_seen, last_seen)
                   VALUES (:bssid, :ssid, :channel, :freq, :signal_dbm, :signal_pct, :security, :cipher,
                           :auth, :wps, :raw_security, :source, :ts, :ts)
                   ON CONFLICT(bssid) DO UPDATE SET
                     ssid = COALESCE(NULLIF(excluded.ssid, ''), networks.ssid),
                     channel = COALESCE(excluded.channel, networks.channel),
                     freq = CASE WHEN excluded.channel IS NOT NULL THEN excluded.freq ELSE networks.freq END,
                     signal_dbm = excluded.signal_dbm, signal_pct = excluded.signal_pct,
                     security = excluded.security, cipher = COALESCE(excluded.cipher, networks.cipher),
                     auth = COALESCE(excluded.auth, networks.auth),
                     wps = COALESCE(excluded.wps, networks.wps),
                     raw_security = excluded.raw_security, source = excluded.source,
                     last_seen = excluded.last_seen""",
                {**{f.name: getattr(ap, f.name) for f in fields(ap) if f.name != "in_use"},
                 "source": source or ap.source, "ts": ts},
            )
        for st in stations:
            self.db.execute(
                """INSERT INTO stations(mac, bssid, power, packets, probes, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(mac) DO UPDATE SET bssid = excluded.bssid, power = excluded.power,
                     packets = excluded.packets, probes = excluded.probes, last_seen = excluded.last_seen""",
                (st.mac, st.bssid, st.power, st.packets, ",".join(st.probes), ts, ts),
            )

    def all(self) -> list[dict]:
        rows = self.db.query(
            """SELECT n.*, (SELECT COUNT(*) FROM stations s WHERE s.bssid = n.bssid) AS clients
               FROM networks n ORDER BY n.last_seen DESC, n.signal_dbm DESC""")
        return [dict(r) for r in rows]

    def stations_for(self, bssid: str) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM stations WHERE bssid = ? ORDER BY last_seen DESC", (bssid,))]

    def set_authorized(self, bssid: str, authorized: bool) -> None:
        row = self.db.query("SELECT ssid, authorized FROM networks WHERE bssid = ?", (bssid,))
        if not row or bool(row[0]["authorized"]) == authorized:
            return
        self.db.execute("UPDATE networks SET authorized = ? WHERE bssid = ?", (int(authorized), bssid))
        self.audit.append(Event.SCOPE_CHANGE, target=bssid,
                          detail={"network": row[0]["ssid"], "authorized": authorized})

    def is_authorized(self, bssid: str) -> bool:
        row = self.db.query("SELECT authorized FROM networks WHERE bssid = ?", (bssid,))
        return bool(row and row[0]["authorized"])

    def forget_unauthorized(self) -> int:
        cur = self.db.execute("DELETE FROM networks WHERE authorized = 0")
        self.db.execute("DELETE FROM stations WHERE bssid IS NULL OR bssid NOT IN (SELECT bssid FROM networks)")
        return cur.rowcount


class TargetStore:
    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def values(self) -> list[str]:
        return [r["value"] for r in self.db.query("SELECT value FROM targets ORDER BY id")]

    def all(self) -> list[dict]:
        return [dict(r) for r in self.db.query("SELECT * FROM targets ORDER BY id")]

    def add(self, value: str, note: str = "", bssid: str | None = None) -> bool:
        value = parse_target(value).text  # validates
        cur = self.db.execute("INSERT OR IGNORE INTO targets(value, note, bssid, added) VALUES (?, ?, ?, ?)",
                              (value, note, bssid, now()))
        if cur.rowcount:
            self.audit.append(Event.SCOPE_CHANGE, target=value,
                              detail={"authorized_target": "added", "note": note, "network": bssid})
        return bool(cur.rowcount)

    def remove(self, value: str) -> None:
        cur = self.db.execute("DELETE FROM targets WHERE value = ?", (value,))
        if cur.rowcount:
            self.audit.append(Event.SCOPE_CHANGE, target=value, detail={"authorized_target": "removed"})

    def covers(self, target: str) -> bool:
        return in_scope(target, self.values())


class HostAuditStore:
    def __init__(self, db: Database):
        self.db = db

    def start(self, kind: str, host: str, port: int | None, tool: str, command: str) -> int:
        return self.db.execute(
            "INSERT INTO host_audits(kind, host, port, tool, command, started) VALUES (?, ?, ?, ?, ?, ?)",
            (kind, host, port, tool, command, now())).lastrowid

    def finish(self, audit_id: int, exit_code: int, raw_output: str, result_json: str) -> None:
        self.db.execute("UPDATE host_audits SET finished = ?, exit_code = ?, raw_output = ?, result_json = ? "
                        "WHERE id = ?", (now(), exit_code, raw_output, result_json, audit_id))

    def latest(self, host: str | None = None) -> list[dict]:
        """Newest finished audit per (host, kind, port)."""
        sql = ("SELECT * FROM host_audits a WHERE finished IS NOT NULL AND id = (SELECT MAX(id) FROM host_audits b "
               "WHERE b.host = a.host AND b.kind = a.kind AND IFNULL(b.port, -1) = IFNULL(a.port, -1) "
               "AND b.finished IS NOT NULL)")
        params: tuple = ()
        if host:
            sql += " AND host = ?"
            params = (host,)
        return [dict(r) for r in self.db.query(sql + " ORDER BY host, kind, port", params)]


class ScanStore:
    def __init__(self, db: Database):
        self.db = db

    def start(self, tool: str, target: str, command: str) -> int:
        return self.db.execute("INSERT INTO scans(tool, target, command, started) VALUES (?, ?, ?, ?)",
                               (tool, target, command, now())).lastrowid

    def finish(self, scan_id: int, exit_code: int, raw_output: str | None) -> None:
        self.db.execute("UPDATE scans SET finished = ?, exit_code = ?, raw_output = ? WHERE id = ?",
                        (now(), exit_code, raw_output, scan_id))

    def recent(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT id, tool, target, command, started, finished, exit_code FROM scans "
            "ORDER BY id DESC LIMIT ?", (limit,))]

    def with_output(self, limit: int = 200) -> list[dict]:
        """Newest-first scans including their raw output (for findings)."""
        return [dict(r) for r in self.db.query(
            "SELECT * FROM scans WHERE raw_output IS NOT NULL AND raw_output != '' ORDER BY id DESC LIMIT ?",
            (limit,))]

    def get(self, scan_id: int) -> dict | None:
        rows = self.db.query("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return dict(rows[0]) if rows else None
