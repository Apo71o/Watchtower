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
            self._emit(self.signals.failed, f"{exc}\n\n{traceback.format_exc(limit=3)}")
        else:
            self._emit(self.signals.done, result)

    @staticmethod
    def _emit(signal, value):
        if _closing:
            return   # app is shutting down: don't touch Qt from this thread
        try:
            signal.emit(value)
        except RuntimeError:
            pass  # the window that asked for this was closed while it ran: nobody to tell


_jobs: set = set()
_closing = False


def shutdown(timeout_ms: int = 4000) -> bool:
    """Called on exit: drop queued jobs and wait briefly for running ones.
    Returns True if every job finished."""
    global _closing
    _closing = True
    pool = QThreadPool.globalInstance()
    pool.clear()
    done = pool.waitForDone(timeout_ms)
    _closing = False   # tests keep running after a shutdown() call
    return done


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
