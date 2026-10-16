"""Long-op job runner — one thread per full read / restore / VM pull.

A job is a callable run off the request thread; it reports progress through a
``report(done, total, message)`` callback and its events fan out on the
:class:`~toshiba_cix.server.events.EventBus` as ``job.progress`` / ``job.done``
/ ``job.error`` so the UI's progress bars update over SSE (architecture.md 4.2,
DESIGN_PLAN 10.3). State is kept so ``GET /api/jobs/{id}`` can be polled when a
client missed the stream.

Pure stdlib (``threading``); the engine work the job does is injected as the
callable, so this module has no SNMP/serial knowledge and is unit-testable with
a trivial function.
"""

from __future__ import annotations

import threading
import time
import uuid


class Job:
    """One tracked unit of work and its live progress."""

    def __init__(self, job_id: str, kind: str):
        self.id = job_id
        self.kind = kind
        self.status = "pending"        # pending | running | done | error
        self.done = 0
        self.total = 0
        self.message = ""
        self.detail = None             # optional granular progress payload
        self.result = None
        self.error = None
        self.started = None
        self.finished = None

    def as_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "status": self.status,
            "done": self.done, "total": self.total, "message": self.message,
            "detail": self.detail,
            "error": self.error, "started": self.started,
            "finished": self.finished,
            # the result is included only once finished and only if JSON-ish
            "result": self.result if self.status == "done" else None,
        }


class JobManager:
    """Submit callables, track them, publish their progress to the bus."""

    def __init__(self, bus=None):
        self._bus = bus
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, fn, *, join_for: float = 0.0) -> Job:
        """Run ``fn(report)`` in a daemon thread; return its :class:`Job` now.

        ``fn`` receives a ``report(done, total, message="", detail=None)``
        callback. Its return value becomes ``job.result``. ``join_for`` lets a
        caller/test wait up to N seconds for completion (0 = return at once).
        """
        job = Job(uuid.uuid4().hex[:12], kind)
        with self._lock:
            self._jobs[job.id] = job

        def report(done, total=None, message="", detail=None):
            job.done = done
            if total is not None:
                job.total = total
            if message:
                job.message = message
            if detail is not None:
                job.detail = detail
            self._publish("job.progress", job)

        def run():
            job.status = "running"
            job.started = time.time()
            self._publish("job.progress", job)
            try:
                job.result = fn(report)
                job.status = "done"
                job.finished = time.time()
                self._publish("job.done", job)
            except Exception as exc:  # noqa: BLE001  — surface, never crash the daemon
                job.status = "error"
                job.error = f"{type(exc).__name__}: {exc}"
                job.finished = time.time()
                self._publish("job.error", job)

        t = threading.Thread(target=run, name=f"job-{job.id}", daemon=True)
        t.start()
        job._thread = t  # type: ignore[attr-defined]
        if join_for:
            t.join(timeout=join_for)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: (j.started or 0), reverse=True)
        return [j.as_dict() for j in jobs]

    def _publish(self, event: str, job: Job) -> None:
        if self._bus is not None:
            self._bus.publish(event, job.as_dict())


__all__ = ["Job", "JobManager"]
