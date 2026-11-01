"""Entry point: `watchtower` (pipx) or `python -m watchtower`."""

from __future__ import annotations

import argparse
import os
import sys

from watchtower import APP_NAME, __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchtower", description=f"{APP_NAME} security audit GUI")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("--check-deps", action="store_true",
                        help="print the dependency check to the terminal and exit (no GUI)")
    parser.add_argument("--run-scheduled", action="store_true",
                        help="run any due scheduled scans and exit (used by the background timer)")
    args = parser.parse_args(argv)

    from watchtower.core import deps
    from watchtower.core.platform_utils import platform_info
    from watchtower.core.runner import CommandRunner
    from watchtower.storage.audit_log import AuditLog, Event
    from watchtower.storage.db import Database

    info = platform_info()
    db = Database()

    if args.check_deps:
        runner = CommandRunner(AuditLog(db))
        print(info.summary())
        for s in deps.check_all(runner):
            mark = "ok " if s.present else ("-- " if s.tool.optional else "!! ")
            ver = f" {s.version}" if s.version else ""
            hint = "" if s.present else f"   -> {s.install_hint}"
            print(f"{mark}{s.tool.name}{ver}{hint}")
        return 0

    if args.run_scheduled:
        return run_scheduled_headless(db)

    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from watchtower.gui.context import AppContext
    from watchtower.gui.main_window import MainWindow
    from watchtower.gui.theme import apply_theme
    from watchtower.gui.worker import run_in_background, shutdown
    from watchtower.storage.settings import THEME

    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    ctx = AppContext.create(db, info)
    apply_theme(ctx.settings.get(THEME, "system"))
    ctx.audit.append(Event.APP_START, detail={"version": __version__, "platform": info.summary()})

    win = MainWindow(ctx)
    win.show()

    # Populate feature gating in the background; first-run screens after the window shows.
    def _deps_done(statuses):
        ctx.deps.update(statuses)
        ctx.bus.dependencies_changed.emit()

    run_in_background(deps.check_all, ctx.runner, on_done=_deps_done)
    QTimer.singleShot(0, win.first_run)
    code = app.exec()
    # Tear down in a fixed order: child processes, background jobs, the window, then Qt.
    ctx.runner.terminate_all()
    all_done = shutdown()
    win.deleteLater()
    app.processEvents()
    del win
    db.close()
    if not all_done:
        # A job is stuck (e.g. a root process we can't signal). Python's normal teardown would race
        # that thread against Qt's destruction and can segfault; everything is already saved
        # (SQLite autocommit), so leave immediately instead.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    return code


def run_scheduled_headless(db) -> int:
    """Run due schedules without a GUI; desktop-notify on alerts (notify-send, if present)."""
    from watchtower.core import deps, scheduler
    from watchtower.core.runner import CommandRunner
    from watchtower.storage.audit_log import AuditLog, Event
    from watchtower.storage.scope import ScanStore, ScheduleStore, TargetStore

    audit = AuditLog(db)
    audit.append(Event.APP_START, detail={"mode": "scheduled scans (headless)"})
    runner = CommandRunner(audit)
    results = scheduler.run_due(runner, TargetStore(db, audit), ScanStore(db), ScheduleStore(db, audit))
    for r in results:
        print(f"#{r.schedule_id} {r.target}: {r.status}")
        for c in r.changes:
            print(f"   [{c.level}] {c.title} {c.detail}")
    alerts = [(r, c) for r in results for c in r.alerts]
    notify = deps.find_binary("notify-send")
    if alerts and notify:
        body = "\n".join(f"{r.target}: {c.title}" for r, c in alerts[:6])
        runner.run([notify, "-a", "Watchtower", f"Watchtower: {len(alerts)} alert(s)", body],
                   purpose="desktop notification", timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
