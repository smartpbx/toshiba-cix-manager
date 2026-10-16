"""Offline tests for the site book and connect-persists-site wiring (v2.1.2).

Two layers:

* pure unit tests of ``toshiba_cix.sites.record_connection`` against a temp
  ``SiteBook`` — a successful connect writes the system, host-matched so a
  reconnect never duplicates, and the tech's chosen name survives;
* HTTP integration against a real ThreadingHTTPServer with a *temp* store and
  the SNMP client swapped for an in-memory fake, so ``POST /api/connect`` is
  shown to upsert the site and ``GET /api/sites`` to list it — no network, no
  real user profile touched.

Run:  python3 tests/test_sites.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from toshiba_cix import appdirs, webapp  # noqa: E402
from toshiba_cix.server.http import ThreadingHTTPServer, build_handler  # noqa: E402
from toshiba_cix.sites import SiteBook, record_connection  # noqa: E402
from toshiba_cix.snmp import Value, VarBind  # noqa: E402
from test_decode import FakeClient, _sample_capture  # noqa: E402


def _book():
    d = tempfile.mkdtemp(prefix="cix-sites-")
    return SiteBook(os.path.join(d, "sites.json")), d


# ===========================================================================
# unit: record_connection
# ===========================================================================
def test_record_creates_site_named_for_software_id():
    book, _ = _book()
    site = record_connection(book, host="10.0.0.5", community="public", port=161,
                             identity={"software_id": "SW-ABC"})
    assert site is not None
    all_sites = book.load()
    assert len(all_sites) == 1
    s = all_sites[0]
    assert s["name"] == "SW-ABC"               # no label -> software id
    assert s["pbx"]["host"] == "10.0.0.5"
    assert s["pbx"]["community"] == "public"
    assert s["pbx"]["identity"]["software_id"] == "SW-ABC"
    assert s["last_connected"]                 # timestamp recorded


def test_record_no_duplicate_on_same_host():
    book, _ = _book()
    record_connection(book, host="10.0.0.5", community="public",
                      identity={"software_id": "SW-ABC"})
    record_connection(book, host="10.0.0.5", community="private",
                      identity={"software_id": "SW-ABC"})
    sites = book.load()
    assert len(sites) == 1                       # host-matched, not duplicated
    assert sites[0]["pbx"]["community"] == "private"   # updated in place


def test_record_second_host_adds_a_site():
    book, _ = _book()
    record_connection(book, host="10.0.0.5")
    record_connection(book, host="10.0.0.6")
    assert {s["pbx"]["host"] for s in book.load()} == {"10.0.0.5", "10.0.0.6"}


def test_record_uses_explicit_label_and_site_id():
    book, _ = _book()
    record_connection(book, host="10.0.0.9", name="Toner Farms", site_id="toner")
    s = book.get("toner")
    assert s is not None and s["name"] == "Toner Farms"
    assert s["pbx"]["host"] == "10.0.0.9"


def test_record_host_match_keeps_existing_name():
    book, _ = _book()
    record_connection(book, host="10.0.0.9", name="Toner Farms", site_id="toner")
    # reconnect to the same host under a different throwaway label
    record_connection(book, host="10.0.0.9", name="192.168 scan", community="c2")
    sites = book.load()
    assert len(sites) == 1
    assert sites[0]["name"] == "Toner Farms"     # the chosen name is preserved
    assert sites[0]["pbx"]["community"] == "c2"  # connection facts refreshed


def test_record_overlay_via_is_recorded():
    book, _ = _book()
    record_connection(book, host="172.30.1.1", via="overlay")
    assert book.load()[0]["pbx"]["via"] == "overlay"


def test_record_requires_a_host():
    book, _ = _book()
    assert record_connection(book, host="") is None
    assert record_connection(book, host=None) is None
    assert book.load() == []


def test_record_disambiguates_id_collision():
    book, _ = _book()
    # a site already filed under the id a bare label would slugify to
    book.upsert({"id": "x", "name": "X one", "pbx": {"host": "10.0.0.1"}})
    record_connection(book, host="10.0.0.2", name="X")   # slug "x" is taken
    sites = book.load()
    assert len(sites) == 2                               # no overwrite
    new = book.get("x-10-0-0-2")
    assert new is not None and new["pbx"]["host"] == "10.0.0.2"


# ===========================================================================
# HTTP integration: /api/sites + connect-persists-site
# ===========================================================================
class _FakeClient(FakeClient):
    """FakeClient + .get() so /api/connect works offline (mirrors test_web)."""

    def __init__(self, ip="192.168.254.253", community="communityName",
                 *, port=161, timeout=3.0, retries=1):
        super().__init__(_sample_capture())
        self.host = ip
        self.community = community
        self.port = port

    def get(self, oids):
        return [VarBind(o, self._data.get(o, Value("missing"))) for o in oids]


def _fake_factory(ip, community="communityName", *, port=161, timeout=3.0,
                  retries=1):
    return _FakeClient(ip, community, port=port, timeout=timeout, retries=retries)


_server = None
_base = None
_tmp = None
_saved_snmp = None


def _start_server():
    global _server, _base, _tmp, _saved_snmp
    _tmp = tempfile.mkdtemp(prefix="cix-sites-srv-")
    _saved_snmp = webapp.SnmpV1
    webapp.SnmpV1 = _fake_factory          # the client the handler builds
    ctx = webapp.make_context(token=None, appdirs=appdirs.AppDirs(_tmp))
    _server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(ctx))
    _base = f"http://127.0.0.1:{_server.server_address[1]}"
    threading.Thread(target=_server.serve_forever, daemon=True).start()


def _stop_server():
    global _server
    if _server:
        _server.shutdown()
        _server.server_close()
    if _saved_snmp is not None:
        webapp.SnmpV1 = _saved_snmp


def _req(method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(_base + path, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_http_sites_round_trip():
    status, body = _req("POST", "/api/sites",
                        {"name": "Round Trip", "pbx": {"host": "1.2.3.4"}})
    assert status == 200 and body["ok"] is True
    status, body = _req("GET", "/api/sites")
    assert status == 200
    match = [s for s in body["sites"] if s["id"] == "round-trip"]
    assert match and match[0]["pbx"]["host"] == "1.2.3.4"


def test_http_connect_upserts_site_without_duplicating():
    ip = "192.168.254.253"
    status, body = _req("POST", "/api/connect",
                        {"ip": ip, "community": "communityName",
                         "site": "Kellys Lumber"})
    assert status == 200 and body["ok"] is True and body["software_id"]

    status, listing = _req("GET", "/api/sites")
    hosts = [s for s in listing["sites"] if s["pbx"].get("host") == ip]
    assert len(hosts) == 1, "connect should persist exactly one saved site"
    saved = hosts[0]
    assert saved["name"] == "Kellys Lumber"
    assert saved["pbx"]["identity"]["software_id"] == body["software_id"]
    assert saved["last_connected"]

    # A second identical connect must not create a duplicate (host-matched).
    _req("POST", "/api/connect", {"ip": ip, "community": "communityName",
                                  "site": "Kellys Lumber"})
    status, listing = _req("GET", "/api/sites")
    hosts = [s for s in listing["sites"] if s["pbx"].get("host") == ip]
    assert len(hosts) == 1, "reconnect must update in place, not duplicate"


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
