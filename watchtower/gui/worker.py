"""Run blocking work (subprocesses) off the GUI thread."""

from __future__ import annotations

import traceback

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)


class _Job(QRunnable):
    def __init__(self, fn, args, kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.signals = _Signals()

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:  # surfaced to the user, not swallowed
            self.signals.failed.emit(f"{exc}\n\n{traceback.format_exc(limit=3)}")
        else:
            self.signals.done.emit(result)


_jobs: set = set()


def run_in_background(fn, *args, on_done=None, on_error=None, **kwargs) -> None:
    job = _Job(fn, args, kwargs)
    _jobs.add(job)  # keep signals alive until delivery
    job.setAutoDelete(False)

    def _finish(cb, value):
        _jobs.discard(job)
        if cb:
            cb(value)

    job.signals.done.connect(lambda r: _finish(on_done, r))
    job.signals.failed.connect(lambda m: _finish(on_error, m))
    QThreadPool.globalInstance().start(job)
