"""Offline tests for the web layer.

Starts the real ``ThreadingHTTPServer`` on an ephemeral loopback port and drives
it with ``urllib``, but swaps the SNMP client for an in-memory fake built from
the same captured varbinds the decoder tests use — so the whole HTTP -> read ->
decode -> render -> export pipeline is exercised with no network.

Run:  python3 tests/test_web.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from toshiba_cix import webapp  # noqa: E402
from toshiba_cix.snmp import SnmpV1, Value, VarBind  # noqa: E402
from test_decode import FakeClient, _sample_capture  # noqa: E402
from test_backup import make_backup  # noqa: E402


class WebFakeClient(FakeClient):
    """FakeClient + a .get() so /api/connect and discovery work offline."""

    def __init__(self, ip="192.168.254.253", community="communityName",
                 *, port=161, timeout=3.0, retries=1):
        super().__init__(_sample_capture())
        self.host = ip
        self.community = community
        self.port = port

    def get(self, oids):
        return [VarBind(o, self._data.get(o, Value("missing"))) for o in oids]

    def get_one(self, oid):
        return self._data.get(oid, Value("missing"))

    def set(self, varbinds):
        from toshiba_cix.snmp import Response, _decode_value, _read_tlv
        for oid, tlv in varbinds:
            tag, content, _ = _read_tlv(tlv, 0)
            self._data[oid] = _decode_value(tag, content)
            if oid not in self._sorted:
                self._sorted.append(oid)
                self._sorted.sort(key=lambda o: [int(x) for x in o.split(".")])
        return Response(1, 0, 0, [])


def _fake_factory(ip, community="communityName", *, port=161, timeout=3.0,
                  retries=1):
    return WebFakeClient(ip, community, port=port, timeout=timeout,
                         retries=retries)


# -- server harness ---------------------------------------------------------
_server = None
_base = None


def _start_server():
    global _server, _base
    webapp.SnmpV1 = _fake_factory          # patch the client the handler builds
    _server = ThreadingHTTPServer(("127.0.0.1", 0), webapp.CIXHandler)
    _base = f"http://127.0.0.1:{_server.server_address[1]}"
    threading.Thread(target=_server.serve_forever, daemon=True).start()


def _stop_server():
    if _server:
        _server.shutdown()
        _server.server_close()


def _get(path):
    try:
        with urllib.request.urlopen(_base + path, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _post(path, obj, raw=False):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(_base + path, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            headers = dict(r.headers)
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read()
        headers = dict(e.headers)
        status = e.code
    if raw:
        return status, body, headers
    return status, json.loads(body.decode())


# -- tests ------------------------------------------------------------------
def test_index_serves_html():
    with urllib.request.urlopen(_base + "/", timeout=10) as r:
        body = r.read().decode()
    assert r.status == 200
    assert "Toshiba CIX Manager" in body
    assert "<title>" in body


def test_health():
    status, j = _get("/api/health")
    assert status == 200 and j["ok"] is True
    assert j["writes_enabled"] is True
    assert j["version"]


def test_connect():
    status, j = _post("/api/connect",
                      {"ip": "192.168.254.253", "community": "communityName"})
    assert j["ok"] is True
    assert j["software_id"] == "NA520MT067PNDN2---EM.00"
    assert j["chassis_mac"] == "e8:e0:b7:cc:58:f5"


def test_connect_missing_ip():
    status, j = _post("/api/connect", {"ip": ""})
    assert status == 400 and j["ok"] is False


def test_read_returns_doc_and_report():
    status, j = _post("/api/read", {"ip": "192.168.254.253", "scope": "all"})
    assert j["ok"] is True
    doc = j["doc"]
    dns = {s["dn"] for s in doc["stations"]}
    assert {"200", "221", "241", "401"} <= dns
    assert doc["system"]["software_id"] == "NA520MT067PNDN2---EM.00"
    assert "raw_oid_walk" in doc and doc["raw_oid_walk"]
    assert "Station directory" in j["report"]
    # source OIDs are captured for the (stubbed) write path
    by_dn = {s["dn"]: s for s in doc["stations"]}
    assert by_dn["200"]["source_oids"].get("extension")


def test_save_preview_does_not_write():
    # first read to get a real station object
    _, j = _post("/api/read", {"ip": "192.168.254.253", "scope": "all"})
    st = next(s for s in j["doc"]["stations"] if s["dn"] == "200")
    # extension is the one editable 1200 field present for DN 200 in the sample,
    # so its planned op carries a real target OID derived from the read.
    status, res = _post("/api/save",
                        {"ip": "192.168.254.253", "station": st,
                         "changes": {"extension": "250"}})
    assert res["ok"] is True and res["mode"] == "preview"
    assert "preview" in res["message"].lower()
    op = res["planned_ops"][0]
    assert op["field"] == "extension"
    assert op["new_value"] == "250"
    assert op["old_value"] == "200"
    assert op["target_oid"] and "3.1200.1.1.2." in op["target_oid"]


def test_save_confirm_writes_and_verifies():
    _, j = _post("/api/read", {"ip": "192.168.254.253", "scope": "all"})
    st = next(s for s in j["doc"]["stations"] if s["dn"] == "200")
    status, res = _post("/api/save",
                        {"ip": "192.168.254.253", "community": "communityName",
                         "port": 161, "station": st,
                         "changes": {"extension": "250"}, "confirm": True})
    assert res["ok"] is True and res["mode"] == "write"
    r = res["result"]
    assert r["wrote"] == 1 and r["verified_all"] is True
    assert r["results"][0]["read_back"] == "250"
    assert r["results"][0]["match"] is True


def test_backup_zip():
    _, j = _post("/api/read", {"ip": "192.168.254.253", "scope": "all"})
    status, body, headers = _post("/api/backup", {"doc": j["doc"]}, raw=True)
    assert status == 200
    assert headers.get("Content-Type") == "application/zip"
    assert "attachment" in headers.get("Content-Disposition", "")
    zf = zipfile.ZipFile(io.BytesIO(body))
    names = set(zf.namelist())
    assert {"programming.json", "report.txt", "raw-oid-walk.txt",
            "MANIFEST.txt"} <= names
    # the embedded JSON round-trips and the report mentions a station
    reparsed = json.loads(zf.read("programming.json").decode())
    assert reparsed["system"]["software_id"] == "NA520MT067PNDN2---EM.00"
    assert "NA520MT067PNDN2---EM.00" in zf.read("report.txt").decode()


def test_build_backup_zip_direct():
    # the helper also works without raw_oid_walk present
    doc = {"device": {"ip": "1.2.3.4"}, "system": {"software_id": "X"},
           "stations": [], "stats": {"stations": 0}}
    body = webapp.build_backup_zip(doc)
    zf = zipfile.ZipFile(io.BytesIO(body))
    assert "programming.json" in zf.namelist()
    assert "raw-oid-walk.txt" not in zf.namelist()   # omitted when absent


def test_discover_endpoint_patched():
    canned = {"networks": [{"iface": "eth0", "ip": "192.168.254.10",
                            "prefixlen": 24}],
              "candidates": [{"ip": "192.168.254.253", "mac": "e8e0b7cc58f5",
                              "via": "arp-oui", "verified": True,
                              "software_id": "NA520MT067PNDN2---EM.00"}],
              "verified": []}
    orig = webapp.DISC.discover_cix
    webapp.DISC.discover_cix = lambda *a, **k: dict(canned)
    try:
        status, j = _get("/api/discover")
    finally:
        webapp.DISC.discover_cix = orig
    assert j["ok"] is True
    assert j["candidates"][0]["ip"] == "192.168.254.253"
    assert j["candidates"][0]["verified"] is True


def test_catalog_endpoint():
    status, j = _get("/api/catalog")
    assert status == 200 and j["ok"] is True
    assert j["programs"] == 186 and j["fields"] == 2366 and j["writable"] == 1653
    assert j["catalog_version"].startswith("re-")


def test_catalog_backup_endpoint():
    status, j = _post("/api/catalog-backup",
                      {"ip": "192.168.254.253", "community": "communityName"})
    assert j["ok"] is True
    bk = j["backup"]
    assert bk["format"] == "toshiba-cix-backup"
    assert bk["meta"]["swid"] == "NA520MT067PNDN2---EM.00"
    assert bk["meta"]["catalog_version"].startswith("re-")
    assert "report" in j and "catalog backup" in j["report"]


def test_view_endpoint():
    doc, _ = make_backup()
    status, j = _post("/api/view", {"backup": doc})
    assert j["ok"] is True
    assert "Front Desk" in j["report"]
    assert "200StationAssign" in j["programs"]


def test_view_endpoint_missing_backup():
    status, j = _post("/api/view", {})
    assert status == 400 and j["ok"] is False


def test_diff_endpoint():
    a, _ = make_backup(names=("Front Desk", "Lobby", "Warehouse"))
    b, _ = make_backup(names=("Front Desk", "Reception", "Warehouse"))
    status, j = _post("/api/diff", {"a": a, "b": b})
    assert j["ok"] is True
    assert j["diff"]["summary"]["fields_changed"] >= 1
    assert "Reception" in j["report"]


def test_restore_preview_endpoint():
    doc, _ = make_backup()
    status, j = _post("/api/restore", {"backup": doc, "confirm": False})
    assert j["ok"] is True and j["mode"] == "preview"
    assert j["summary"]["sendable"] >= 3
    # a preview needs no IP and sends nothing
    assert any(op["sendable"] for op in j["planned_ops"])


def test_restore_confirm_endpoint_writes_and_verifies():
    doc, _ = make_backup()
    status, j = _post("/api/restore",
                      {"ip": "192.168.254.253", "community": "communityName",
                       "backup": doc, "confirm": True})
    assert j["ok"] is True and j["mode"] == "write"
    assert j["verified_all"] is True
    assert j["results"] and all(r["match"] for r in j["results"])


def test_update_check_endpoint():
    canned = {"ok": True, "current": "1.1.0", "latest": "1.2.0", "newer": True,
              "asset_url": "https://example.test/a.AppImage",
              "asset_name": "a.AppImage", "replaceable": True,
              "packaging": "appimage", "html_url": "https://example.test",
              "error": None}
    orig = webapp.check_for_update
    webapp.check_for_update = lambda **k: dict(canned)
    try:
        status, j = _get("/api/update")
    finally:
        webapp.check_for_update = orig
    assert status == 200 and j["ok"] is True
    assert j["newer"] is True and j["latest"] == "1.2.0"


def test_update_apply_requires_confirm():
    orig = webapp.plan_update
    webapp.plan_update = lambda *a, **k: {"can_apply": False, "reason": "src"}
    try:
        status, j = _post("/api/update", {})
    finally:
        webapp.plan_update = orig
    assert status == 400 and j["ok"] is False


def test_update_apply_confirm_calls_apply():
    orig = webapp.apply_update
    webapp.apply_update = lambda **k: {"ok": True, "action": "replaced",
                                       "message": "Updated."}
    try:
        status, j = _post("/api/update", {"confirm": True})
    finally:
        webapp.apply_update = orig
    assert j["ok"] is True and j["action"] == "replaced"


def test_404():
    status, j = _get("/api/nope")
    assert status == 404 and j["ok"] is False


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


# pytest fixtures: start/stop the server around the module.
def setup_module(module):  # noqa: D401
    _start_server()


def teardown_module(module):
    _stop_server()


if __name__ == "__main__":
    raise SystemExit(_run_all())
