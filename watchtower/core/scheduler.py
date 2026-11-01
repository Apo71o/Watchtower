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

from watchtower.core import deps, nmap_runner
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


def run_due(runner: CommandRunner, targets, scans, schedules) -> list[RunResult]:
    return [run_schedule(s, runner, targets, scans, schedules) for s in schedules.due()]


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
