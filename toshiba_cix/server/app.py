"""Server assembly: the context, the P0 core routes, and the launch.

``ServerContext`` is the one object the handler closes over — router, auth
guard, SSE bus, job runner, session registry and the on-disk store (AppDirs +
site book + journal). ``register_core_routes`` adds the routes P0 owns
(``/api/schema``, ``/api/sites``, ``/api/jobs``, ``/api/journal`` and the
session/mode trio that drives the SSE channel); the legacy JSON routes are
registered by ``webapp`` so their handler semantics — and the test monkeypatch
seam — are untouched.

``run_server`` binds an OS-chosen loopback port (never a fixed one, so a second
instance can't collide), ``serve`` adds the app-mode browser open and the
auto-exit-after-last-client rule. All stdlib.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import threading
from urllib.parse import urlparse

from .. import __version__
from ..appdirs import AppDirs, store_root
from .auth import LoopbackAuth, generate_token
from .events import EventBus
from .http import ThreadingHTTPServer, build_handler
from .jobs import JobManager
from .router import Router
from .schema import load_ui_schema_text, schema_summary
from .sessions import SessionManager

log = logging.getLogger("toshiba_cix.server")

AUTOEXIT_GRACE_SECS = 20.0


class ServerContext:
    """Everything a request handler needs, assembled once per server."""

    def __init__(self, *, token=None, appdirs: AppDirs | None = None,
                 version: str = __version__):
        self.version = version
        self.router = Router()
        self.auth = LoopbackAuth(token)
        self.bus = EventBus()
        self.jobs = JobManager(self.bus)
        self.sessions = SessionManager(self.bus)
        self.appdirs = appdirs
        self._sitebook = None
        self._journal = None

    # -- lazy store accessors (nothing is created until a route needs it) --
    def sitebook(self):
        from ..sites import SiteBook, sitebook_from_root
        if self.appdirs is None:
            return SiteBook(os.path.join(store_root(), "sites.json"))
        if self._sitebook is None:
            self.appdirs.ensure()
            self._sitebook = sitebook_from_root(self.appdirs)
        return self._sitebook

    def journal(self):
        from ..journal import journal_from_root
        if self._journal is None:
            root = self.appdirs or AppDirs(store_root())
            root.ensure()
            self._journal = journal_from_root(root)
        return self._journal


# --------------------------------------------------------------------------
# P0 core routes
# --------------------------------------------------------------------------
def register_core_routes(ctx: ServerContext) -> None:
    ctx.router.get("/api/schema", _schema)
    ctx.router.get("/api/sites", _sites_list)
    ctx.router.post("/api/sites", _sites_upsert)
    ctx.router.put("/api/sites/{id}", _sites_put)
    ctx.router.delete("/api/sites/{id}", _sites_delete)
    ctx.router.get("/api/jobs", _jobs_list)
    ctx.router.get("/api/jobs/{id}", _jobs_get)
    ctx.router.get("/api/journal", _journal_list)
    ctx.router.post("/api/sessions", _sessions_create)
    ctx.router.get("/api/sessions", _sessions_list)
    ctx.router.post("/api/sessions/{id}/mode", _session_mode)


def _schema(ctx, req):
    # Served as raw text (it is already JSON) so the big file is not re-encoded.
    req.send_text(load_ui_schema_text(), content_type="application/json")


def _sites_list(ctx, req):
    req.send_json({"ok": True, "sites": ctx.sitebook().load()})


def _sites_upsert(ctx, req):
    body = req.body()
    if not isinstance(body, dict) or not (body.get("name") or body.get("id")):
        req.send_json({"ok": False, "error": "a site needs a name or id"}, 400)
        return
    site = ctx.sitebook().upsert(body)
    req.send_json({"ok": True, "site": site})


def _sites_put(ctx, req):
    body = dict(req.body() or {})
    body["id"] = req.params["id"]
    req.send_json({"ok": True, "site": ctx.sitebook().upsert(body)})


def _sites_delete(ctx, req):
    removed = ctx.sitebook().delete(req.params["id"])
    req.send_json({"ok": removed, "deleted": req.params["id"]},
                  200 if removed else 404)


def _jobs_list(ctx, req):
    req.send_json({"ok": True, "jobs": ctx.jobs.list()})


def _jobs_get(ctx, req):
    job = ctx.jobs.get(req.params["id"])
    if job is None:
        req.send_json({"ok": False, "error": "no such job"}, 404)
        return
    req.send_json({"ok": True, "job": job.as_dict()})


def _journal_list(ctx, req):
    limit = int(req.query.get("limit") or 100)
    req.send_json({"ok": True, "commits": ctx.journal().list_commits(limit)})


def _sessions_create(ctx, req):
    body = req.body() or {}
    s = ctx.sessions.create(site=body.get("site"), device=body.get("device"),
                            transport=body.get("transport"))
    req.send_json({"ok": True, "session": s.as_dict()})


def _sessions_list(ctx, req):
    req.send_json({"ok": True, "sessions": ctx.sessions.list()})


def _session_mode(ctx, req):
    s = ctx.sessions.get(req.params["id"])
    if s is None:
        req.send_json({"ok": False, "error": "no such session"}, 404)
        return
    body = req.body() or {}
    mode = body.get("mode")
    try:
        state = s.set_mode(mode, minutes=body.get("minutes"))
    except ValueError as exc:
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return
    req.send_json({"ok": True, "mode": state})


# --------------------------------------------------------------------------
# launch
# --------------------------------------------------------------------------
def pick_free_port(host: str, preferred: int) -> int:
    """``preferred`` if free, else the next free (up to +20); 0 lets the OS pick."""
    if preferred == 0:
        return 0
    for port in range(preferred, preferred + 21):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    return preferred


def make_server(ctx: ServerContext, host: str = "127.0.0.1", port: int = 0):
    """Bind the server (OS-chosen port by default) and return ``(httpd, url)``."""
    httpd = ThreadingHTTPServer((host, pick_free_port(host, port)),
                                build_handler(ctx))
    actual = httpd.server_address[1]
    ctx.host, ctx.port = host, actual
    return httpd, f"http://{host}:{actual}"


def _open_app_window(url: str) -> None:
    """Open the UI chromeless in app mode; fall back to a normal browser tab.

    Tries Edge/Chrome/Chromium/Brave ``--app=`` (a dedicated window with its own
    taskbar entry) before the stdlib ``webbrowser``. Best-effort and silent.
    """
    candidates = {
        "win32": [["cmd", "/c", "start", "msedge", f"--app={url}"],
                  ["cmd", "/c", "start", "chrome", f"--app={url}"]],
        "darwin": [["open", "-na", "Google Chrome", "--args", f"--app={url}"],
                   ["open", "-na", "Microsoft Edge", "--args", f"--app={url}"]],
    }.get(sys.platform, [[b, f"--app={url}"] for b in
                         ("google-chrome", "chromium", "chromium-browser",
                          "brave-browser", "microsoft-edge")])
    for cmd in candidates:
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return
        except (OSError, ValueError):
            continue
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass


def _install_autoexit(httpd, ctx: ServerContext, grace: float) -> None:
    """Shut the daemon down ``grace`` seconds after the last SSE client leaves.

    A new client within the grace window cancels the pending exit, so a browser
    reload does not kill the server. Agent/bridge mode disables this.
    """
    state = {"timer": None}

    def on_count(count: int):
        t = state["timer"]
        if count > 0:
            if t is not None:
                t.cancel()
                state["timer"] = None
            return
        if t is None:
            timer = threading.Timer(grace, _shutdown)
            timer.daemon = True
            state["timer"] = timer
            timer.start()

    def _shutdown():
        if ctx.bus.subscriber_count() == 0:
            log.info("no clients for %ss — exiting", grace)
            threading.Thread(target=httpd.shutdown, daemon=True).start()

    ctx.bus.on_count_change(on_count)


def run_server(ctx: ServerContext, host: str = "127.0.0.1", port: int = 0, *,
               open_browser: bool = True, autoexit: bool = True,
               block: bool = True, on_ready=None):
    """Create, optionally open + auto-exit, and serve. Returns ``(httpd, url)``.

    ``on_ready(url)`` is called once the server is bound and about to serve.
    With ``block=False`` it serves in a daemon thread and returns at once
    (tests / embedders); call ``httpd.shutdown()`` to stop it.
    """
    httpd, base = make_server(ctx, host, port)
    url = base + (f"/#token={ctx.auth.token}" if ctx.auth.enabled else "/")
    if autoexit:
        _install_autoexit(httpd, ctx, AUTOEXIT_GRACE_SECS)
    if open_browser:
        _open_app_window(url)
    if on_ready:
        on_ready(url)
    if not block:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, url
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd, url


__all__ = ["ServerContext", "register_core_routes", "make_server",
           "run_server", "pick_free_port"]
