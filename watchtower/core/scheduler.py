"""Recurring re-scans of authorized targets, feeding the history diff.

Schedules run while Watchtower is open (the GUI checks once a minute) and,
if the user opts in, while it's closed via a systemd *user* timer that runs
`watchtower --run-scheduled` (no root involved). Every run re-checks the
target against the authorized-target list, so removing a target stops its
schedule from scanning it.
"""

from __future__ import annotations

import os
import shlex
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchtower.core import deps, nmap_runner, traffic_audit
from watchtower.core.history_diff import Change, diff_scans
from watchtower.core.platform_utils import is_linux
from watchtower.core.runner import CommandRunner, CommandUnavailable, format_command

INTERVALS: dict[str, int] = {
    "Every hour": 60, "Every 6 hours": 360, "Every 12 hours": 720, "Daily": 1440, "Weekly": 10080,
}
TIMER_NAME = "watchtower-schedules"


@dataclass
class RunResult:
    schedule_id: int
    target: str
    status: str                       # "ok" | "skipped: ..." | "failed: ..."
    scan_id: int | None = None
    changes: list[Change] = field(default_factory=list)

    @property
    def alerts(self) -> list[Change]:
        return [c for c in self.changes if c.level == "alert"]


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def next_run_after(run_at: datetime, interval_minutes: int) -> str:
    return _iso(run_at + timedelta(minutes=interval_minutes))


def run_schedule(sched: dict, runner: CommandRunner, targets, scans, schedules,
                 now: datetime | None = None) -> RunResult:
    """Run one due schedule (blocking). `targets`/`scans`/`schedules` are the storage stores."""
    now = now or datetime.now(timezone.utc)
    nxt = next_run_after(now, sched["interval_minutes"])
    res = RunResult(sched["id"], sched["target"], "ok")

    def finish(status: str) -> RunResult:
        res.status = status
        schedules.mark_run(sched["id"], status, _iso(now), nxt)
        return res

    nmap = deps.find_binary("nmap")
    if not nmap:
        return finish("skipped: nmap not installed")
    out_dir = Path(tempfile.mkdtemp(prefix="watchtower-sched-"))
    xml_path = out_dir / "scan.xml"
    try:
        cmd = nmap_runner.build(nmap, sched["target"], sched["profile"], scan_type=sched.get("scan_type"),
                                vuln=bool(sched["vuln"]), os_detect=bool(sched["os_detect"]), extra=sched["extra"],
                                xml_path=str(xml_path), authorized=targets.values())
    except ValueError as exc:   # includes ScopeError: target no longer authorized
        out_dir.rmdir()
        return finish(f"skipped: {exc}")
    if cmd.needs_root:
        out_dir.rmdir()
        return finish("skipped: these options need root; grant nmap capabilities (Dependency Check) or remove "
                      "-O/-sU/-A from the schedule")
    previous = scans.for_target(sched["target"], limit=1)
    scan_id = scans.start("nmap", sched["target"], format_command(cmd.argv), schedule_id=sched["id"])
    try:
        r = runner.run(cmd.argv, purpose=f"scheduled scan #{sched['id']}", target=sched["target"], timeout=6 * 3600)
        xml = xml_path.read_text(encoding="utf-8", errors="replace") if xml_path.exists() else ""
    except CommandUnavailable as exc:
        scans.finish(scan_id, -1, "")
        return finish(f"failed: {exc}")
    finally:
        for f in out_dir.iterdir():
            f.unlink(missing_ok=True)
        out_dir.rmdir()
    scans.finish(scan_id, r.exit_code, xml)
    res.scan_id = scan_id
    if r.exit_code != 0 or not xml:
        return finish(f"failed: nmap exit {r.exit_code}")
    if previous:
        res.changes = diff_scans(nmap_runner.parse_xml(previous[0]["raw_output"]), nmap_runner.parse_xml(xml))
    return finish(f"ok: {len(res.changes)} change(s)" if previous else "ok: first scan (baseline)")


def run_capture_schedule(sched: dict, runner: CommandRunner, captures, capture_schedules,
                         now: datetime | None = None) -> RunResult:
    """Run one due scheduled capture (blocking): record, analyze, compare with the previous capture."""
    now = now or datetime.now(timezone.utc)
    nxt = next_run_after(now, sched["interval_minutes"])
    iface = sched["interface"]
    res = RunResult(sched["id"], f"traffic on {iface}", "ok")

    def finish(status: str) -> RunResult:
        res.status = status
        capture_schedules.mark_run(sched["id"], status, _iso(now), nxt)
        return res

    if not traffic_audit.capture_binary() or not traffic_audit.tshark_binary():
        return finish("skipped: dumpcap/tshark not installed")
    out = traffic_audit.new_capture_path(iface)
    try:
        argv = traffic_audit.capture_argv(iface, out, sched["seconds"], user_filter=sched["user_filter"],
                                          monitor_interfaces=traffic_audit.monitor_interfaces(runner))
    except (ValueError, RuntimeError) as exc:
        return finish(f"skipped: {exc}")
    source = f"interface:{iface}"
    previous = captures.for_source(source, limit=1)
    cid = captures.start(source, out, True, format_command(argv), schedule_id=sched["id"])
    try:
        r = runner.run(argv, purpose=f"scheduled traffic capture #{sched['id']}", target=iface,
                       timeout=sched["seconds"] + 120)
    except CommandUnavailable as exc:
        captures.finish(cid, -1, 0, 0, "{}", "[]", str(exc))
        return finish(f"failed: {exc}")
    if r.exit_code != 0 or not Path(out).exists():
        err = traffic_audit.capture_error(r.stderr, r.exit_code)
        captures.finish(cid, r.exit_code, 0, 0, "{}", "[]", err)
        return finish(f"failed: {err}")
    from watchtower.core import traffic_hosts
    a = traffic_audit.analyze_pcap(runner, out, target=iface,
                                   local_nets=traffic_hosts.interface_networks(runner, iface))
    captures.finish(cid, 0, a.stats.packets, a.stats.seconds, traffic_audit.stats_to_json(a.stats),
                    traffic_audit.events_to_json(a.events), a.error)
    if a.error:
        return finish(f"failed: {a.error}")
    if previous:
        res.changes = traffic_audit.diff_captures(traffic_audit.events_from_json(previous[0]["events_json"]),
                                                  a.events)
    return finish(f"ok: {len(res.changes)} change(s)" if previous else "ok: first capture (baseline)")


def run_due(runner: CommandRunner, targets, scans, schedules, captures=None, capture_schedules=None) -> list[RunResult]:
    out = [run_schedule(s, runner, targets, scans, schedules) for s in schedules.due()]
    if captures is not None and capture_schedules is not None:
        out += [run_capture_schedule(s, runner, captures, capture_schedules) for s in capture_schedules.due()]
    return out


# ---- background timer (systemd --user), Linux only ----

def timer_units(python: str | None = None, home: str | None = None) -> dict[str, str]:
    python = python or sys.executable
    env = f"Environment=WATCHTOWER_HOME={shlex.quote(home)}\n" if home else ""
    return {
        f"{TIMER_NAME}.service": (
            "[Unit]\nDescription=Watchtower scheduled scans\n\n[Service]\nType=oneshot\n"
            f"{env}ExecStart={shlex.quote(python)} -m watchtower --run-scheduled\n"),
        f"{TIMER_NAME}.timer": (
            "[Unit]\nDescription=Run due Watchtower scans every 15 minutes\n\n[Timer]\nOnBootSec=5min\n"
            "OnUnitActiveSec=15min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"),
    }


def user_unit_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def timer_install_argvs() -> list[list[str]]:
    systemctl = deps.find_binary("systemctl") or "systemctl"
    return [[systemctl, "--user", "daemon-reload"], [systemctl, "--user", "enable", "--now", f"{TIMER_NAME}.timer"]]


def timer_remove_argvs() -> list[list[str]]:
    systemctl = deps.find_binary("systemctl") or "systemctl"
    return [[systemctl, "--user", "disable", "--now", f"{TIMER_NAME}.timer"]]


def background_supported() -> bool:
    return is_linux() and bool(deps.find_binary("systemctl"))
