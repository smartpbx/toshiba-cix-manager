#!/usr/bin/env python3
"""HTTP integration for the Voice Mail routes (/api/vm/*), offline via FakeLVMU.

A real ThreadingHTTPServer (auth disabled, like the default handler) driven with
urllib: connect to the fake card, read status/boxes/a box/sysparams/pbxdb/
catalog/reports, take a JSON backup, and confirm the save surface is plan-only
(two-phase, no write). Run: python3 -I tests/test_vm_server.py
"""
import json
import os
import sys
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from toshiba_cix import webapp  # noqa: E402
from toshiba_cix.server.http import ThreadingHTTPServer, build_handler  # noqa: E402


def _server():
    ctx = webapp.make_context(token=None)  # auth off for the test
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(ctx))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    return httpd, f"http://127.0.0.1:{port}"


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())


def _post(base, path, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_vm_full_read_flow():
    httpd, base = _server()
    try:
        # before connect, a read route 409s cleanly
        status, body = _post(base, "/api/vm/boxes")  # wrong method -> 405
        assert status == 405
        boxes0 = _get(base, "/api/vm/boxes")
        assert boxes0["ok"] is False  # not connected -> 409 body

        # connect to the offline fake card
        st, conn = _post(base, "/api/vm/connect", {"transport": "fake"})
        assert st == 200 and conn["ok"] and conn["status"]["connected"]
        assert "STRATAGY" in conn["status"]["firmware"].upper()

        status = _get(base, "/api/vm/status")["status"]
        assert status["admin_box"] == "997"
        assert status["writes_enabled"] is False

        boxes = _get(base, "/api/vm/boxes")["boxes"]
        assert len(boxes) >= 10
        assert boxes[0]["box"] == "200"
        # reserved boxes are flagged, never hidden
        assert any(b["reserved"] for b in boxes if b["box"] in ("997", "999"))

        box = _get(base, "/api/vm/boxes/200")
        assert box["mailbox"]["extension"] == "200H"
        assert box["editor"]["writes_enabled"] is False
        # the editor model carries status dots + the confirmed value
        tabs = {t["tab"]: t for t in box["editor"]["tabs"]}
        assert tabs["Header"]
        assert box["editor"]["values"]["extension"] == "200H"

        sp = _get(base, "/api/vm/sysparams")["sysparams"]
        assert any(p["name"] == "pbx_type" for p in sp["params"])
        assert any(f["param"] == "password" for f in sp["findings"])

        pbx = _get(base, "/api/vm/pbxdb?compare=1")["pbxdb"]
        assert pbx["dial_codes"]
        assert pbx["compare"]["available"] is True

        cat = _get(base, "/api/vm/catalog")["editor"]
        assert cat["writes_enabled"] is False

        st, bk = _post(base, "/api/vm/backup/json", {"site": "demo"})
        assert st == 200 and bk["backup"]["meta"]["box_count"] >= 10

        tmpls = _get(base, "/api/vm/reports/templates")["templates"]
        assert any(t["id"] == "audit" for t in tmpls)
        st, rep = _post(base, "/api/vm/reports/run", {"template": "audit"})
        assert st == 200 and rep["report"]["row_count"] >= 10

        # the save surface is PLAN-ONLY: no write, apply refused
        st, plan = _post(base, "/api/vm/boxes/200/save",
                         {"changes": {"security_code": "1234"}})
        assert st == 200
        p = plan["plan"]
        assert p["apply_allowed"] is False
        assert p["writes_enabled"] is False
        assert p["mode"] == "simulate"
        # a confirmed field plans (preview), with the write marked unproven
        assert any(x["field"] == "security_code" for x in p["planned"])
        # a non-confirmed field is refused with a reason, not written
        st, plan2 = _post(base, "/api/vm/boxes/200/save",
                          {"changes": {"do_not_disturb": True}})
        assert any(x["field"] == "do_not_disturb" for x in plan2["plan"]["refused"])

        _post(base, "/api/vm/disconnect")
        assert _get(base, "/api/vm/status")["status"]["connected"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def _run_all():
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


if __name__ == "__main__":
    raise SystemExit(_run_all())
