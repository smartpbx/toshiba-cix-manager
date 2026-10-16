"""The HTTP request handler: auth, routing, JSON/bytes/SSE responses.

``build_handler(ctx)`` returns a :class:`http.server.BaseHTTPRequestHandler`
subclass bound to a :class:`~toshiba_cix.server.app.ServerContext`. It keeps the
old webapp's response semantics (so nothing regresses) and adds:

* the loopback token + Origin/Host gate on every ``/api`` call (``ctx.auth``);
* table-driven dispatch (``ctx.router``) with ``{param}`` capture;
* the ``text/event-stream`` server for ``GET /api/events`` (``ctx.bus``);
* a ``Set-Cookie`` planted on the ``/`` load so the same-origin SPA
  authenticates with nothing added to its requests.

Route functions take ``(ctx, req)`` and use the :class:`Request` facade's
``send_json`` / ``send_bytes`` / ``body`` helpers, so they can live in
``webapp.py`` (preserving the monkeypatch seam the tests rely on) while this
module owns the socket.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .events import HEARTBEAT

log = logging.getLogger("toshiba_cix.server")

_SSE_HEARTBEAT_SECS = 20.0


class Request:
    """Per-request facade handed to a route function."""

    def __init__(self, handler: BaseHTTPRequestHandler, params: dict):
        self.handler = handler
        self.params = params or {}
        parsed = urlparse(handler.path)
        self.path = parsed.path
        self.query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        self._body = _UNSET

    @property
    def headers(self):
        return self.handler.headers

    def body(self) -> dict:
        """Parsed JSON request body ({} if empty). Raises ``ValueError`` on bad JSON."""
        if self._body is _UNSET:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                self._body = {}
            else:
                raw = self.handler.rfile.read(length)
                self._body = json.loads(raw.decode("utf-8")) if raw else {}
        return self._body

    # -- responses ---------------------------------------------------------
    def send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self._start(status, "application/json", len(body))
        self.handler.wfile.write(body)

    def send_text(self, text: str, status: int = 200,
                  content_type: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self._start(status, content_type, len(body))
        self.handler.wfile.write(body)

    def send_bytes(self, body: bytes, content_type: str, status: int = 200,
                   filename: str | None = None, extra_headers=None) -> None:
        self._start(status, content_type, len(body),
                    disposition=(f'attachment; filename="{filename}"'
                                 if filename else None),
                    extra_headers=extra_headers)
        self.handler.wfile.write(body)

    def _start(self, status, content_type, length, disposition=None,
               extra_headers=None):
        h = self.handler
        h.send_response(status)
        h.send_header("Content-Type", content_type)
        h.send_header("Content-Length", str(length))
        if disposition:
            h.send_header("Content-Disposition", disposition)
        for k, v in (extra_headers or {}).items():
            h.send_header(k, v)
        h.end_headers()


_UNSET = object()


def build_handler(ctx):
    """Return a request-handler class bound to ``ctx`` (router/auth/bus/...)."""

    class Handler(BaseHTTPRequestHandler):
        # HTTP/1.0 (the default): a response closes its connection, which keeps
        # the SSE stream simple (no chunked framing) and matches the old
        # handler's semantics so nothing regresses.
        server_version = f"Switchroom/{getattr(ctx, 'version', '0')}"

        def log_message(self, fmt, *args):  # noqa: N802  — quiet; route to logger
            log.debug("%s - %s", self.address_string(), fmt % args)

        # -- method entry points ------------------------------------------
        def do_GET(self):  # noqa: N802
            if not self._guard():
                return
            if urlparse(self.path).path == "/api/events":
                self._serve_sse()
                return
            self._dispatch("GET")

        def do_POST(self):  # noqa: N802
            if self._guard():
                self._dispatch("POST")

        def do_PUT(self):  # noqa: N802
            if self._guard():
                self._dispatch("PUT")

        def do_PATCH(self):  # noqa: N802
            if self._guard():
                self._dispatch("PATCH")

        def do_DELETE(self):  # noqa: N802
            if self._guard():
                self._dispatch("DELETE")

        # -- auth ----------------------------------------------------------
        def _guard(self) -> bool:
            ok, status, message = ctx.auth.check(
                headers=self.headers, path=urlparse(self.path).path)
            if ok:
                return True
            body = json.dumps({"ok": False, "error": message}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False

        # -- dispatch ------------------------------------------------------
        def _dispatch(self, method: str):
            path = urlparse(self.path).path
            match = ctx.router.match(method, path)
            if match is None:
                allowed = ctx.router.methods_for(path)
                if allowed:
                    self._error(405, f"method not allowed (try {','.join(sorted(allowed))})")
                else:
                    self._error(404, "not found")
                return
            handler, params = match
            req = Request(self, params)
            try:
                handler(ctx, req)
            except (ValueError, json.JSONDecodeError) as exc:
                self._safe_json({"ok": False, "error": f"bad request: {exc}"}, 400)
            except BrokenPipeError:  # pragma: no cover — client went away
                pass
            except Exception as exc:  # noqa: BLE001
                log.exception("handler error on %s %s", method, path)
                self._safe_json(
                    {"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 500)

        # -- SSE -----------------------------------------------------------
        def _serve_sse(self):
            sub = ctx.bus.subscribe()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while not sub.closed:
                    frame = sub.get(timeout=_SSE_HEARTBEAT_SECS)
                    payload = frame if frame is not None else (HEARTBEAT + "\n\n")
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                sub.close()

        # -- error helpers -------------------------------------------------
        def _error(self, status, message):
            self._safe_json({"ok": False, "error": message}, status)

        def _safe_json(self, obj, status):
            try:
                body = json.dumps(obj, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, OSError):  # pragma: no cover
                pass

    return Handler


__all__ = ["build_handler", "Request", "ThreadingHTTPServer"]
