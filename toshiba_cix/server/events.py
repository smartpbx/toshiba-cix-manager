"""The SSE event bus — the one push channel to the UI (``GET /api/events``).

A single daemon serves one local browser, so this is a small in-process
pub/sub: each subscriber gets a bounded :class:`queue.Queue`; :meth:`publish`
fans an event out to every live subscriber without blocking the publisher (a
full queue drops the oldest event rather than stall the engine). The handler
turns a subscription into the ``text/event-stream`` wire format.

Event types (DESIGN_PLAN 10.3, architecture.md 4.2): ``job.progress``,
``job.done``, ``job.error``, ``session.mode``, ``session.identity``,
``vm.link``. The payload is any JSON-serialisable dict.

Pure stdlib, thread-safe, I/O-free — the handler owns the socket.
"""

from __future__ import annotations

import json
import threading
from queue import Empty, Full, Queue

# A heartbeat the handler can send so a proxy / the browser keeps the stream
# open through idle periods; also how it notices a dropped client.
HEARTBEAT = ":keepalive"


class Subscription:
    """One live SSE client's queue. Iterate :meth:`events` to drain it."""

    def __init__(self, bus: "EventBus", maxsize: int = 1000):
        self._bus = bus
        self._q: "Queue[str]" = Queue(maxsize=maxsize)
        self.closed = False

    def put(self, frame: str) -> None:
        try:
            self._q.put_nowait(frame)
        except Full:
            # Never block the publisher: drop the oldest, enqueue the newest.
            try:
                self._q.get_nowait()
            except Empty:
                pass
            try:
                self._q.put_nowait(frame)
            except Full:  # pragma: no cover
                pass

    def get(self, timeout: float):
        """Next frame, or ``None`` on timeout (so the caller can heartbeat)."""
        try:
            return self._q.get(timeout=timeout)
        except Empty:
            return None

    def close(self) -> None:
        self.closed = True
        self._bus.unsubscribe(self)


class EventBus:
    """Fan events out to every live :class:`Subscription`. Thread-safe."""

    def __init__(self):
        self._subs: list[Subscription] = []
        self._lock = threading.Lock()
        self._on_count_change = None

    def on_count_change(self, callback) -> None:
        """Register a ``callback(count)`` fired when subscriber count changes.

        The daemon's auto-exit watcher uses this to start/cancel its timer.
        """
        self._on_count_change = callback

    def subscribe(self) -> Subscription:
        sub = Subscription(self)
        with self._lock:
            self._subs.append(sub)
            count = len(self._subs)
        self._notify(count)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)
            count = len(self._subs)
        self._notify(count)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def publish(self, event: str, data=None) -> None:
        """Enqueue ``event`` (+ optional JSON ``data``) on every subscriber."""
        frame = format_sse(event, data)
        with self._lock:
            subs = list(self._subs)
        for sub in subs:
            sub.put(frame)

    def _notify(self, count: int) -> None:
        cb = self._on_count_change
        if cb:
            try:
                cb(count)
            except Exception:  # noqa: BLE001  — a watcher error must not break pub/sub
                pass


def format_sse(event: str, data=None) -> str:
    """One SSE frame: ``event:`` + ``data:`` + blank-line terminator."""
    payload = json.dumps(data if data is not None else {}, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


__all__ = ["EventBus", "Subscription", "format_sse", "HEARTBEAT"]
