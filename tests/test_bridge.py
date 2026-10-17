"""Offline tests for the manager bridge (Conduit deep-link + Save to cloud).

Two layers:

* **Pure unit** — deep-link parsing, the connection→form mapping, and the two
  Conduit calls (``fetch_connection`` / ``post_backup``) driven through their
  injectable ``_http`` seam, so no socket is opened.
* **HTTP integration** — a real ``ThreadingHTTPServer`` with auth ENABLED and a
  temp store; ``webapp.fetch_connection`` / ``webapp.post_backup`` are swapped
  for fakes (the module-global monkeypatch seam webapp is built around), and a
  fake snapshot store is injected, so the deep-link intake, the consume-once
  pending pickup, the context view and the Save-to-cloud route are exercised
  with no network and no real user profile touched.

Run:  python3 tests/test_bridge.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from toshiba_cix import appdirs, bridge, webapp  # noqa: E402
from toshiba_cix.server.http import ThreadingHTTPServer, build_handler  # noqa: E402

TOKEN = "bridge-test-token"


# ===========================================================================
# unit: deep-link parsing
# ===========================================================================
def test_parse_deeplink_roundtrip():
    from urllib.parse import quote
    base = "https://conduitdocs.app"
    url = (f"switchroom://open?conduit={quote(base, safe='')}"
           "&component=abc-123&token=TKN")
    p = bridge.parse_deeplink(url)
    assert p is not None
    assert p["conduit"] == base
    assert p["component"] == "abc-123"
    assert p["token"] == "TKN"
    assert p["action"] == "open"


def test_parse_deeplink_rejects():
    assert bridge.parse_deeplink("https://evil.example/open?x=1") is None
    assert bridge.parse_deeplink("switchroom://open?component=a&token=b") is None
    assert bridge.parse_deeplink("switchroom://open?conduit=c&token=b") is None
    assert bridge.parse_deeplink("") is None
    assert bridge.parse_deeplink(None) is None


def test_pop_deeplink_arg():
    argv, url = bridge.pop_deeplink_arg(
        ["--port", "8765", "switchroom://open?x=1", "--no-browser"])
    assert url == "switchroom://open?x=1"
    assert argv == ["--port", "8765", "--no-browser"]
    argv, url = bridge.pop_deeplink_arg(["--no-browser"])
    assert url is None and argv == ["--no-browser"]
    argv, url = bridge.pop_deeplink_arg([])
    assert url is None and argv == []


# ===========================================================================
# unit: connection -> form mapping
# ===========================================================================
def test_connection_to_form_defaults():
    f = bridge.connection_to_form({}, system_name="Site A")
    assert f["ip"] == ""
    assert f["community"] == "communityName"
    assert f["port"] == 161
    assert f["reach"] == "direct"
    assert f["site"] == "Site A"


def test_connection_to_form_remote_and_coercions():
    f = bridge.connection_to_form(
        {"host": "172.23.1.1", "via": "rsm", "port": "162", "community": "sec"})
    assert f["ip"] == "172.23.1.1"
    assert f["reach"] == "remote"     # rsm/overlay/remote/agent -> remote
    assert f["port"] == 162           # string coerced to int
    assert f["community"] == "sec"
    # a junk port falls back to 161, not a crash
    assert bridge.connection_to_form({"port": "nope"})["port"] == 161


# ===========================================================================
# unit: Conduit calls (injected _http — no socket)
# ===========================================================================
def test_fetch_connection_ok():
    def http(method, url, token, **kw):
        assert method == "GET"
        assert "/api/manager-bridge/connection?component=abc" in url
        assert token == "tok"
        return 200, {"ok": True, "kind": "toshiba_cix", "system_name": "104670",
                     "component_id": "abc",
                     "connection": {"host": "172.23.1.1", "via": "rsm",
                                    "port": 161, "community": "sec"}}, ""

    res = bridge.fetch_connection("https://conduit.example", "abc", "tok", _http=http)
    assert res["ok"] and res["kind"] == "toshiba_cix"
    assert res["system_name"] == "104670"
    assert res["form"]["ip"] == "172.23.1.1"
    assert res["form"]["reach"] == "remote"
    assert res["form"]["community"] == "sec"
    assert res["form"]["site"] == "104670"


def test_fetch_connection_error_body_surfaces():
    def http(method, url, token, **kw):
        return 401, {"ok": False, "error": "token expired"}, ""

    res = bridge.fetch_connection("https://c", "abc", "tok", _http=http)
    assert res["ok"] is False
    assert res["error"] == "token expired"
    assert res["status"] == 401


def test_fetch_connection_transport_error_wrapped():
    def http(method, url, token, **kw):
        raise OSError("connection refused")

    res = bridge.fetch_connection("https://c", "abc", "tok", _http=http)
    assert res["ok"] is False
    assert "could not reach Conduit" in res["error"]


def test_fetch_connection_bad_base():
    def http(*a, **k):  # must never be called
        raise AssertionError("http called for a bad base URL")

    res = bridge.fetch_connection("ftp://nope", "abc", "tok", _http=http)
    assert res["ok"] is False and "http(s)" in res["error"]


def test_post_backup_ok():
    captured = {}

    def http(method, url, token, *, body=None, **kw):
        captured.update(method=method, url=url, token=token, body=body)
        return 200, {"ok": True, "document_id": 42}, ""

    res = bridge.post_backup("https://c", "abc-123", "tok", filename="f.cixbak",
                             content=b"PK\x03\x04zip", content_type="application/zip",
                             summary="3 programs", _http=http)
    assert res["ok"] and res["document_id"] == 42
    assert captured["method"] == "POST"
    assert "/api/manager-bridge/backup?component=abc-123" in captured["url"]
    assert captured["token"] == "tok"
    assert base64.b64decode(captured["body"]["content_b64"]) == b"PK\x03\x04zip"
    assert captured["body"]["content_type"] == "application/zip"
    assert captured["body"]["summary"] == "3 programs"


def test_post_backup_error_surfaces():
    def http(method, url, token, *, body=None, **kw):
        return 500, {"ok": False, "error": "disk full"}, ""

    res = bridge.post_backup("https://c", "abc", "tok", filename="f",
                             content=b"x", content_type="application/zip", _http=http)
    assert res["ok"] is False and res["error"] == "disk full"


# ===========================================================================
# HTTP integration (auth ENABLED, temp store, fakes for Conduit + snapshots)
# ===========================================================================
_server = None
_base = None
_tmp = None
_ctx = None

# Configurable fakes wired in place of the network-touching module globals.
_FETCH_RESULT = {"value": None}
_POST_CALLS = []


class _FakeStore:
    """Just the snapshot-store surface the Save-to-cloud route uses."""

    def __init__(self):
        self.entries = {}   # site_id -> [entry, ...] (newest first)
        self.exports = {}   # (site_id, sid) -> (filename, bytes)

    def index(self, site_id, **kw):
        return list(self.entries.get(site_id, []))

    def get_entry(self, site_id, sid):
        for e in self.entries.get(site_id, []):
            if e.get("id") == sid:
                return e
        return None

    def export(self, site_id, sid, *, redact_secrets=True, container="cixbak"):
        return self.exports.get((site_id, sid))


def _fake_fetch(conduit, component, token, **kw):
    return _FETCH_RESULT["value"]


def _fake_post(conduit, component, token, *, filename, content, content_type,
               summary=None, **kw):
    _POST_CALLS.append({
        "conduit": conduit, "component": component, "token": token,
        "filename": filename, "content": content, "content_type": content_type,
        "summary": summary,
    })
    return {"ok": True, "document_id": "doc-123"}


def _start_server():
    global _server, _base, _tmp, _ctx
    _tmp = tempfile.mkdtemp(prefix="cix-bridge-")
    _ctx = webapp.make_context(token=TOKEN, appdirs=appdirs.AppDirs(_tmp))
    _ctx._snapshots = _FakeStore()
    # Swap the two network-touching calls (resolved from webapp's globals at
    # call time) for fakes so no socket to Conduit is opened.
    webapp.fetch_connection = _fake_fetch
    webapp.post_backup = _fake_post
    _server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(_ctx))
    _base = f"http://127.0.0.1:{_server.server_address[1]}"
    threading.Thread(target=_server.serve_forever, daemon=True).start()


def _stop_server():
    if _server:
        _server.shutdown()
        _server.server_close()


def _req(method, path, body=None, token=TOKEN):
    h = {}
    if token:
        h["X-CIX-Token"] = token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(_base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw}


def _reset_bridge():
    _ctx._bridge = None
    _ctx._bridge_pending = False


def test_http_deeplink_seed_pending_and_context():
    _reset_bridge()
    _FETCH_RESULT["value"] = {
        "ok": True, "kind": "toshiba_cix", "system_name": "104670 TonerFarms",
        "component_id": "cid", "connection": {},
        "form": {"ip": "172.23.9.9", "community": "sec", "port": 161,
                 "reach": "remote", "site": "104670 TonerFarms"},
    }
    status, body = _req("POST", "/api/deeplink", {
        "conduit": "https://conduitdocs.app", "component": "cid", "token": "tk"})
    assert status == 200 and body["ok"]

    # consume-once: first pending returns the link (with the prefill form)
    status, body = _req("GET", "/api/deeplink/pending")
    dl = body["deeplink"]
    assert dl and dl["active"] and dl["component"] == "cid"
    assert dl["system_name"] == "104670 TonerFarms"
    assert dl["form"]["ip"] == "172.23.9.9" and dl["form"]["reach"] == "remote"
    # and never leaks the token or the Conduit base to the browser
    assert "token" not in dl and "conduit" not in dl

    # second pending is empty (consumed)
    status, body = _req("GET", "/api/deeplink/pending")
    assert body["deeplink"] is None

    # context stays active (for the Save button after a reload), still no secrets
    status, body = _req("GET", "/api/bridge/context")
    ctx = body["context"]
    assert ctx and ctx["active"] and ctx["component"] == "cid"
    assert "form" not in ctx and "token" not in ctx and "conduit" not in ctx


def test_http_deeplink_keeps_fetch_error():
    _reset_bridge()
    _FETCH_RESULT["value"] = {"ok": False, "error": "token expired"}
    status, body = _req("POST", "/api/deeplink", {
        "conduit": "https://conduitdocs.app", "component": "cid2", "token": "tk"})
    assert status == 200 and body["ok"]
    status, body = _req("GET", "/api/deeplink/pending")
    dl = body["deeplink"]
    assert dl and dl["active"] and dl["component"] == "cid2"
    assert dl["error"] == "token expired"
    assert dl.get("form") is None


def test_http_deeplink_requires_all_params():
    _reset_bridge()
    status, body = _req("POST", "/api/deeplink", {"conduit": "https://c"})
    assert status == 400 and body["ok"] is False


def test_http_backup_no_context_409():
    _reset_bridge()
    status, body = _req("POST", "/api/bridge/backup", {"site_id": "s1"})
    assert status == 409 and body["ok"] is False
    assert "Conduit" in body["error"]


def test_http_backup_no_snapshot_409():
    _reset_bridge()
    _FETCH_RESULT["value"] = {"ok": True, "kind": "toshiba_cix", "system_name": "X",
                              "component_id": "cid", "connection": {}, "form": {}}
    webapp.seed_bridge_context(_ctx, "https://conduitdocs.app", "cid", "tk")
    _ctx._snapshots.entries = {}      # nothing to save
    status, body = _req("POST", "/api/bridge/backup", {"site_id": "empty-site"})
    assert status == 409 and body["ok"] is False


def test_http_backup_saves_newest_snapshot():
    _reset_bridge()
    _POST_CALLS.clear()
    _FETCH_RESULT["value"] = {"ok": True, "kind": "toshiba_cix",
                              "system_name": "X", "component_id": "cid",
                              "connection": {}, "form": {}}
    webapp.seed_bridge_context(_ctx, "https://conduitdocs.app", "cid-9", "tok-9")
    site = "104670"
    _ctx._snapshots.entries = {site: [
        {"id": "snap-new", "read_at": "2026-10-17T00:00:00Z",
         "counts": {"programs": 42, "rows": 300}, "swid": "AACS.100"},
        {"id": "snap-old", "read_at": "2026-10-01T00:00:00Z"},
    ]}
    _ctx._snapshots.exports = {(site, "snap-new"): ("104670_snap-new.cixbak",
                                                    b"PK\x03\x04zipbytes")}
    status, body = _req("POST", "/api/bridge/backup", {"site_id": site})
    assert status == 200 and body["ok"], body
    assert body["document_id"] == "doc-123"
    assert body["filename"] == "104670_snap-new.cixbak"
    # the engine sent the newest snapshot's bytes with the held token + component
    assert len(_POST_CALLS) == 1
    call = _POST_CALLS[0]
    assert call["content"] == b"PK\x03\x04zipbytes"
    assert call["content_type"] == "application/zip"
    assert call["component"] == "cid-9" and call["token"] == "tok-9"
    assert call["conduit"] == "https://conduitdocs.app"
    # the summary is counts only — never field values
    assert "42 programs" in call["summary"] and "AACS.100" in call["summary"]


def test_http_backup_explicit_snapshot():
    _reset_bridge()
    _POST_CALLS.clear()
    _FETCH_RESULT["value"] = {"ok": True, "kind": "toshiba_cix", "system_name": "X",
                              "component_id": "cid", "connection": {}, "form": {}}
    webapp.seed_bridge_context(_ctx, "https://conduitdocs.app", "cid", "tok")
    site = "200site"
    _ctx._snapshots.entries = {site: [{"id": "a"}, {"id": "b"}]}
    _ctx._snapshots.exports = {(site, "b"): ("200site_b.cixbak", b"BBB")}
    status, body = _req("POST", "/api/bridge/backup",
                        {"site_id": site, "snapshot": "b"})
    assert status == 200 and body["ok"]
    assert _POST_CALLS[0]["content"] == b"BBB"


# ===========================================================================
# runner (mirrors tests/test_server.py)
# ===========================================================================
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
