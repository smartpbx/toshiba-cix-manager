"""Per-connected-device session state (the engine's working copy + mode).

A :class:`Session` is what the design's safety model hangs on (DESIGN_PLAN 5.5,
architecture.md 2): the last full read as the **working copy** (``doc``), the
**staged changeset** (``pending`` — nothing hits the wire on edit), the live
device **identity**, the arming **mode** with its idle expiry, and the session's
job ids. P0 lays the structure and the lifecycle hooks (mode changes and
identity updates publish to the SSE bus); the commit/simulate machinery that
fills it is P1/P2.

Pure stdlib and bus-injected; no SNMP here — a session is handed a device
descriptor, never a socket.
"""

from __future__ import annotations

import threading
import time
import uuid

# Arming modes. "armed" permits writes; it expires after an idle window
# (DESIGN_PLAN decision #6: 15 min local default, 10 remote, configurable).
MODE_DISARMED = "disarmed"
MODE_ARMED = "armed"
MODE_SIMULATE = "simulate"
_MODES = (MODE_DISARMED, MODE_ARMED, MODE_SIMULATE)

DEFAULT_ARM_MINUTES = 15
REMOTE_ARM_MINUTES = 10


class Session:
    def __init__(self, session_id: str, *, site=None, device=None,
                 transport=None, bus=None):
        self.id = session_id
        self.site = site
        self.device = device or {}
        self.transport = transport
        self.identity = None
        self.doc = {}                 # working copy: program_key -> rows
        self.freshness = {}           # program_key -> read timestamp
        self.pending = []             # staged ops (a Changeset mirror)
        self.mode = MODE_DISARMED
        self.mode_expires = None
        self.jobs = []
        self.created = time.time()
        self._bus = bus

    # -- identity ----------------------------------------------------------
    def set_identity(self, identity) -> None:
        self.identity = identity
        self._publish("session.identity",
                      {"session": self.id, "identity": identity})

    # -- mode --------------------------------------------------------------
    def set_mode(self, mode: str, *, minutes: int | None = None) -> dict:
        if mode not in _MODES:
            raise ValueError(f"unknown mode {mode!r}")
        self.mode = mode
        if mode == MODE_ARMED:
            window = (REMOTE_ARM_MINUTES if self.transport in ("overlay", "agent")
                      else DEFAULT_ARM_MINUTES) if minutes is None else minutes
            self.mode_expires = time.time() + window * 60
        else:
            self.mode_expires = None
        state = self.mode_state()
        self._publish("session.mode", state)
        return state

    def mode_state(self) -> dict:
        expired = (self.mode == MODE_ARMED and self.mode_expires is not None
                   and time.time() >= self.mode_expires)
        if expired:
            # Lazily fall back to disarmed when the idle window passes.
            self.mode = MODE_DISARMED
            self.mode_expires = None
        return {"session": self.id, "mode": self.mode,
                "expires": self.mode_expires,
                "writable": self.mode == MODE_ARMED}

    def is_armed(self) -> bool:
        return self.mode_state()["mode"] == MODE_ARMED

    def as_dict(self) -> dict:
        return {"id": self.id, "site": self.site, "transport": self.transport,
                "identity": self.identity, "mode": self.mode_state()["mode"],
                "mode_expires": self.mode_expires,
                "pending": len(self.pending),
                "programs_read": sorted(self.doc.keys()), "jobs": list(self.jobs)}

    def _publish(self, event, data):
        if self._bus is not None:
            self._bus.publish(event, data)


class SessionManager:
    def __init__(self, bus=None):
        self._bus = bus
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, *, site=None, device=None, transport=None) -> Session:
        sid = uuid.uuid4().hex[:12]
        s = Session(sid, site=site, device=device, transport=transport,
                    bus=self._bus)
        with self._lock:
            self._sessions[sid] = s
        return s

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list(self) -> list[dict]:
        with self._lock:
            return [s.as_dict() for s in self._sessions.values()]

    def drop(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None


__all__ = ["Session", "SessionManager", "MODE_DISARMED", "MODE_ARMED",
           "MODE_SIMULATE"]
