"""Switchroom's local HTTP server (supersedes the old single-file ``webapp``).

Split into small, testable, pure-stdlib pieces: the loopback token + Origin
guard (:mod:`auth`), a table router (:mod:`router`), the SSE bus
(:mod:`events`), the job runner (:mod:`jobs`), per-device sessions
(:mod:`sessions`), the generated-schema loader (:mod:`schema`), the request
handler (:mod:`http`) and the assembly + launch (:mod:`app`).

``webapp`` keeps the legacy JSON route handlers (and the monkeypatch seam the
offline tests rely on) and wires them, plus these core routes, onto a
:class:`~toshiba_cix.server.app.ServerContext`.
"""

from __future__ import annotations

from .app import (ServerContext, make_server, register_core_routes,
                  run_server)
from .auth import LoopbackAuth, generate_token
from .events import EventBus
from .http import Request, build_handler
from .jobs import Job, JobManager
from .router import Router
from .sessions import Session, SessionManager

__all__ = [
    "ServerContext", "register_core_routes", "make_server", "run_server",
    "build_handler", "Request", "Router", "EventBus", "Job", "JobManager",
    "Session", "SessionManager", "LoopbackAuth", "generate_token",
]
