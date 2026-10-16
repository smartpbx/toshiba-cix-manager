"""Offline tests for the new server plumbing (toshiba_cix.server.*).

Two layers: pure unit tests of the router, auth guard, event bus, job runner
and session modes; and HTTP integration against a real ThreadingHTTPServer
built with auth ENABLED and a temp store, driven with urllib / http.client so
the token + Origin/Host gate, the ``/api/schema`` + ``/api/sites`` +
``/api/jobs`` + session/mode routes and the SSE ``/api/events`` channel are all
exercised with no network and no real user profile touched.

Run:  python3 tests/test_server.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from toshiba_cix import appdirs, webapp  # noqa: E402
from toshiba_cix.server.auth import LoopbackAuth  # noqa: E402
from toshiba_cix.server.events import EventBus, format_sse  # noqa: E402
from toshiba_cix.server.http import ThreadingHTTPServer, build_handler  # noqa: E402
from toshiba_cix.server.jobs import JobManager  # noqa: E402
from toshiba_cix.server.router import Router  # noqa: E402
from toshiba_cix.server.sessions import SessionManager  # noqa: E402

TOKEN = "test-token-abc123"


# ===========================================================================
# unit: router
# ===========================================================================
def test_router_static_and_param():
    r = Router()
    r.get("/api/jobs", lambda: "list")
    r.get("/api/jobs/{id}", lambda: "one")
    assert r.match("GET", "/api/jobs")[0]() == "list"
    h, params = r.match("GET", "/api/jobs/abc")
    assert h() == "one" and params == {"id": "abc"}
    assert r.match("GET", "/api/missing") is None


def test_router_static_beats_param():
    r = Router()
    r.get("/api/sites/{id}", lambda: "param")
    r.get("/api/sites/new", lambda: "static")
    assert r.match("GET", "/api/sites/new")[0]() == "static"
    assert r.match("GET", "/api/sites/123")[0]() == "param"


def test_router_methods_for():
    r = Router()
    r.get("/api/x", lambda: 1)
    r.post("/api/x", lambda: 2)
    assert set(r.methods_for("/api/x")) == {"GET", "POST"}
    assert r.methods_for("/api/none") == []


# ===========================================================================
# unit: auth
# ===========================================================================
def test_auth_disabled_passes_all():
    a = LoopbackAuth(None)
    assert a.enabled is False
    assert a.check(headers=_H({}), path="/api/read")[0] is True


def test_auth_requires_token():
    a = LoopbackAuth(TOKEN)
    assert a.check(headers=_H({}), path="/api/read")[1] == 401
    ok, status, _ = a.check(headers=_H({"X-CIX-Token": TOKEN,
                                        "Host": "127.0.0.1:9"}), path="/api/read")
    assert ok and status == 200
    # static always passes
    assert a.check(headers=_H({}), path="/")[0] is True


def test_auth_blocks_cross_origin_and_bad_host():
    a = LoopbackAuth(TOKEN)
    bad_origin = a.check(headers=_H({"X-CIX-Token": TOKEN, "Host": "127.0.0.1:9",
                                     "Origin": "http://evil.example"}),
                         path="/api/read")
    assert bad_origin[1] == 403
    bad_host = a.check(headers=_H({"X-CIX-Token": TOKEN, "Host": "evil.example"}),
                       path="/api/read")
    assert bad_host[1] == 403


def test_auth_accepts_cookie():
    a = LoopbackAuth(TOKEN)
    ok, status, _ = a.check(
        headers=_H({"Cookie": f"cix_token={TOKEN}; other=1",
                    "Host": "127.0.0.1:9"}), path="/api/schema")
    assert ok and status == 200
    assert a.cookie_header().startswith("cix_token=" + TOKEN)


# ===========================================================================
# unit: event bus
# ===========================================================================
def test_event_bus_fanout_and_count():
    counts = []
    bus = EventBus()
    bus.on_count_change(counts.append)
    s1 = bus.subscribe()
    s2 = bus.subscribe()
    assert bus.subscriber_count() == 2
    bus.publish("job.done", {"id": "x"})
    f1, f2 = s1.get(timeout=1), s2.get(timeout=1)
    assert "job.done" in f1 and "job.done" in f2
    s1.close()
    s2.close()
    assert bus.subscriber_count() == 0
    assert counts[-1] == 0 and max(counts) == 2


def test_format_sse():
    frame = format_sse("session.mode", {"mode": "armed"})
    assert frame.startswith("event: session.mode\n")
    assert '"mode": "armed"' in frame and frame.endswith("\n\n")


# ===========================================================================
# unit: jobs
# ===========================================================================
def test_job_runs_and_reports():
    bus = EventBus()
    sub = bus.subscribe()
    mgr = JobManager(bus)

    def work(report):
        report(1, 2, "half")
        report(2, 2, "done")
        return {"rows": 2}

    job = mgr.submit("read", work, join_for=2.0)
    assert job.status == "done" and job.result == {"rows": 2}
    assert mgr.get(job.id).done == 2
    # a job.done frame reached the bus
    frames = []
    for _ in range(10):
        f = sub.get(timeout=0.2)
        if f:
            frames.append(f)
    assert any("job.done" in f for f in frames)
    sub.close()


def test_job_error_is_captured():
    mgr = JobManager(None)

    def boom(report):
        raise RuntimeError("nope")

    job = mgr.submit("read", boom, join_for=2.0)
    assert job.status == "error" and "nope" in job.error


# ===========================================================================
# unit: sessions
# ===========================================================================
def test_session_mode_and_expiry():
    bus = EventBus()
    sub = bus.subscribe()
    mgr = SessionManager(bus)
    s = mgr.create(site="alpha", transport="direct")
    assert s.is_armed() is False
    s.set_mode("armed", minutes=15)
    assert s.is_armed() is True
    assert any("session.mode" in (sub.get(timeout=0.2) or "") for _ in range(5))
    # expired window falls back to disarmed on next read
    s.mode_expires = time.time() - 1
    assert s.mode_state()["mode"] == "disarmed"
    sub.close()


def test_session_unknown_mode_rejected():
    mgr = SessionManager(None)
    s = mgr.create()
    try:
        s.set_mode("nope")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ===========================================================================
# HTTP integration (auth ENABLED, temp store)
# ===========================================================================
_server = None
_base = None
_tmp = None
_ctx = None


def setup_module(module):
    _start_server()


def teardown_module(module):
    _stop_server()


def _start_server():
    global _server, _base, _tmp, _ctx
    _tmp = tempfile.mkdtemp(prefix="cix-srv-")
    _ctx = webapp.make_context(token=TOKEN, appdirs=appdirs.AppDirs(_tmp))
    _server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(_ctx))
    _base = f"http://127.0.0.1:{_server.server_address[1]}"
    threading.Thread(target=_server.serve_forever, daemon=True).start()


def _stop_server():
    if _server:
        _server.shutdown()
        _server.server_close()


def _req(method, path, body=None, headers=None, token=TOKEN):
    h = dict(headers or {})
    if token:
        h.setdefault("X-CIX-Token", token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(_base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode()), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = {"raw": raw}
        return e.code, parsed, dict(e.headers)


def test_http_requires_token():
    status, body, _ = _req("GET", "/api/schema", token=None)
    assert status == 401 and body["ok"] is False


def test_http_cross_origin_refused():
    status, body, _ = _req("GET", "/api/schema",
                           headers={"Origin": "http://evil.example"})
    assert status == 403


def test_http_static_sets_cookie_without_token():
    # "/" is static: served with no token, and it plants the auth cookie.
    status, _body, headers = _req_raw("GET", "/", token=None)
    assert status == 200
    assert "cix_token=" in headers.get("Set-Cookie", "")


def test_http_schema_route():
    status, body, _ = _req("GET", "/api/schema")
    assert status == 200
    assert body["counts"]["programs"] == 186
    assert "200StationAssign" in body["programs"]


def test_http_sites_crud():
    status, body, _ = _req("POST", "/api/sites", {"name": "Toner Farms"})
    assert status == 200 and body["site"]["id"] == "toner-farms"
    status, body, _ = _req("GET", "/api/sites")
    assert any(s["id"] == "toner-farms" for s in body["sites"])
    status, body, _ = _req("PUT", "/api/sites/toner-farms",
                           {"name": "Toner Farms 2", "pbx": {"host": "10.1.2.3"}})
    assert body["site"]["pbx"]["host"] == "10.1.2.3"
    status, body, _ = _req("DELETE", "/api/sites/toner-farms")
    assert status == 200 and body["deleted"] == "toner-farms"
    status, body, _ = _req("DELETE", "/api/sites/toner-farms")
    assert status == 404


def test_http_jobs_route():
    job = _ctx.jobs.submit("read", lambda report: report(1, 1) or "ok",
                           join_for=2.0)
    status, body, _ = _req("GET", f"/api/jobs/{job.id}")
    assert status == 200 and body["job"]["status"] == "done"
    status, body, _ = _req("GET", "/api/jobs")
    assert any(j["id"] == job.id for j in body["jobs"])
    status, body, _ = _req("GET", "/api/jobs/nope")
    assert status == 404


def test_http_session_mode_and_405():
    status, body, _ = _req("POST", "/api/sessions", {"site": "alpha",
                                                     "transport": "direct"})
    sid = body["session"]["id"]
    status, body, _ = _req("POST", f"/api/sessions/{sid}/mode", {"mode": "armed"})
    assert status == 200 and body["mode"]["mode"] == "armed"
    # wrong method on a known path -> 405, not 404
    status, body, _ = _req("GET", "/api/connect")
    assert status == 405


def test_http_sse_delivers_published_event():
    # A raw socket: recv() returns whatever has arrived, so the streaming
    # (Content-Length-less) event-stream is read without blocking for a count.
    import socket
    s = socket.create_connection(("127.0.0.1", _server.server_address[1]),
                                 timeout=5)
    s.settimeout(5)
    try:
        s.sendall(b"GET /api/events HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                  b"X-CIX-Token: " + TOKEN.encode() + b"\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:            # status line + headers + preamble
            buf += s.recv(1024)
        assert b"200" in buf.split(b"\r\n", 1)[0]
        _ctx.bus.publish("session.identity", {"id": "probe-1"})
        data = b""
        deadline = time.time() + 5
        while b"session.identity" not in data and time.time() < deadline:
            data += s.recv(1024)
        assert b"session.identity" in data
    finally:
        s.close()


def _req_raw(method, path, token=TOKEN):
    """Like _req but returns the raw body text (for non-JSON / static)."""
    h = {}
    if token:
        h["X-CIX-Token"] = token
    req = urllib.request.Request(_base + path, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)


def _H(d):
    """A headers-like object with a case-tolerant .get (mimics http message)."""
    class _Msg:
        def __init__(self, data):
            self._d = data
        def get(self, k, default=None):
            if k in self._d:
                return self._d[k]
            for kk, vv in self._d.items():
                if kk.lower() == k.lower():
                    return vv
            return default
    return _Msg(d)


def _run_all():
    _start_server()
    try:
        fns = [v for k, v in sorted(globals().items())
               if k.startswith("test_") and callable(v)]
        failed = 0
        for fn in fns:
            try:
                fn()
                print(f"PASS {fn.__name__}")
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {fn.__name__}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print(f"ERROR {fn.__name__}: {exc!r}")
        print(f"\n{len(fns) - failed}/{len(fns)} passed")
        return 1 if failed else 0
    finally:
        _stop_server()


if __name__ == "__main__":
    raise SystemExit(_run_all())
