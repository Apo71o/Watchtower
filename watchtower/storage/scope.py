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

    def record(self, aps, stations=(), source: str = "") -> int:
        """Upsert observations from a scan. `aps` are wifi_scan.AccessPoint,
        `stations` wifi_scan.Station. Never touches the authorized flag. Also
        stores a snapshot for history diffs; returns its id."""
        ts = now()
        kind = "airodump-ng" if source == "airodump-ng" else "managed"
        snap = self.db.execute("INSERT INTO wifi_snapshots(ts, source) VALUES (?, ?)", (ts, kind)).lastrowid
        for ap in aps:
            self.db.execute(
                "INSERT OR REPLACE INTO wifi_observations(snapshot_id, bssid, ssid, channel, signal_dbm, signal_pct, "
                "security, auth, cipher, wps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (snap, ap.bssid, ap.ssid, ap.channel, ap.signal_dbm, ap.signal_pct, ap.security, ap.auth, ap.cipher,
                 ap.wps))
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
        return snap

    def snapshots(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT s.*, (SELECT COUNT(*) FROM wifi_observations o WHERE o.snapshot_id = s.id) AS count "
            "FROM wifi_snapshots s ORDER BY id DESC LIMIT ?", (limit,))]

    def snapshot(self, snap_id: int) -> dict[str, dict]:
        return {r["bssid"]: dict(r) for r in self.db.query(
            "SELECT * FROM wifi_observations WHERE snapshot_id = ?", (snap_id,))}

    def authorized_ssids(self) -> set[str]:
        return {r["ssid"] for r in self.db.query("SELECT ssid FROM networks WHERE authorized = 1 AND ssid != ''")}

    def authorized_bssids(self) -> set[str]:
        return {r["bssid"] for r in self.db.query("SELECT bssid FROM networks WHERE authorized = 1")}

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


class ScheduleStore:
    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def add(self, target: str, profile: str, interval_minutes: int, scan_type: str | None = None, extra: str = "",
            os_detect: bool = False, vuln: bool = False) -> int:
        parse_target(target)
        sid = self.db.execute(
            "INSERT INTO schedules(target, profile, scan_type, extra, os_detect, vuln, interval_minutes, created, "
            "next_run) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (target, profile, scan_type, extra, int(os_detect), int(vuln), int(interval_minutes), now(), now()),
        ).lastrowid
        self.audit.append(Event.SCOPE_CHANGE, target=target,
                          detail={"schedule": "added", "id": sid, "profile": profile,
                                  "every_minutes": interval_minutes})
        return sid

    def all(self) -> list[dict]:
        return [dict(r) for r in self.db.query("SELECT * FROM schedules ORDER BY id")]

    def get(self, sid: int) -> dict | None:
        rows = self.db.query("SELECT * FROM schedules WHERE id = ?", (sid,))
        return dict(rows[0]) if rows else None

    def due(self, at: str | None = None) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM schedules WHERE enabled = 1 AND next_run <= ? ORDER BY next_run", (at or now(),))]

    def set_enabled(self, sid: int, enabled: bool) -> None:
        self.db.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (int(enabled), sid))
        self.audit.append(Event.SCOPE_CHANGE, detail={"schedule": "enabled" if enabled else "paused", "id": sid})

    def remove(self, sid: int) -> None:
        self.db.execute("DELETE FROM schedules WHERE id = ?", (sid,))
        self.audit.append(Event.SCOPE_CHANGE, detail={"schedule": "removed", "id": sid})

    def mark_run(self, sid: int, status: str, run_at: str, next_run: str) -> None:
        self.db.execute("UPDATE schedules SET last_run = ?, next_run = ?, last_status = ? WHERE id = ?",
                        (run_at, next_run, status, sid))

    def run_now(self, sid: int) -> None:
        self.db.execute("UPDATE schedules SET next_run = ? WHERE id = ?", (now(), sid))


class ScanStore:
    def __init__(self, db: Database):
        self.db = db

    def start(self, tool: str, target: str, command: str, schedule_id: int | None = None) -> int:
        return self.db.execute(
            "INSERT INTO scans(tool, target, command, started, schedule_id) VALUES (?, ?, ?, ?, ?)",
            (tool, target, command, now(), schedule_id)).lastrowid

    def for_target(self, target: str, limit: int = 100) -> list[dict]:
        """Finished scans of exactly this target, newest first (with output)."""
        return [dict(r) for r in self.db.query(
            "SELECT * FROM scans WHERE target = ? AND finished IS NOT NULL AND raw_output IS NOT NULL "
            "AND raw_output != '' ORDER BY id DESC LIMIT ?", (target, limit))]

    def targets(self) -> list[dict]:
        """Distinct scan targets with how many finished scans each has."""
        return [dict(r) for r in self.db.query(
            "SELECT target, COUNT(*) AS n, MAX(started) AS last FROM scans WHERE finished IS NOT NULL "
            "AND raw_output IS NOT NULL AND raw_output != '' GROUP BY target ORDER BY last DESC")]

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
