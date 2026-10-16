"""Route-level tests for the P2 write path (stage / review / Simulate / apply).

Drives the handlers through a real make_context router with a FakeReq, so the
two-phase contract is tested end to end with NO hardware:

* staging and review never open a socket;
* Simulate returns a plan + three-way review + op-log with the client's ``set``
  never called (a LoudClient fails the test if any SET is attempted);
* a live apply is refused (409) until the session is armed, confirmed and the
  typed site name matches — so no code path reaches a live SET by default.

Run:  python3 tests/test_write_routes.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import webapp  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"
PKEY = "200StationAssign"


class LoudClient:
    """A client that FAILS the test if anything tries to read or write it —
    proof that Simulate and the pre-arm gate never touch the network."""

    def get(self, oids):
        raise AssertionError("network GET attempted during a no-network path")

    def set(self, varbinds):
        raise AssertionError("LIVE SET attempted — the gate let a write through")


class FakeReq:
    def __init__(self, body=None, params=None, query=None):
        self._body = body or {}
        self.params = params or {}
        self.query = query or {}
        self.status = None
        self.json = None

    def body(self):
        return self._body

    def send_json(self, obj, status=200):
        self.json = obj
        self.status = status

    def send_text(self, *a, **k):
        self.status = 200


def _view():
    return {
        "catalog_key": PKEY, "program_number": "200",
        "label": "Station Assignments", "menu_path": "Station > Assignments",
        "menu_area": "Station", "row_count": 1,
        "rows": [{"index": "2", "key": "2104", "cells": [
            {"field_name": "name", "col": 19,
             "oid": f"{ROOT}.3.200.1.1.19.1.2",
             "raw_value": "Front Desk", "display_value": "Front Desk",
             "syntax": "OCTET STRING", "access": "rw", "is_secret": False},
        ]}],
    }


def _ctx_session(*, with_client=False):
    ctx = webapp.make_context()           # auth disabled; routes registered
    s = ctx.sessions.create(site="Kellys Lumber", transport="direct")
    s.put_program_view(_view())
    if with_client:
        s.attach_client(LoudClient())
    return ctx, s


def _stage(ctx, s, changes):
    req = FakeReq(body={"program": PKEY, "index": "2", "changes": changes},
                  params={"id": s.id})
    webapp.route_session_pending_stage(ctx, req)
    return req.json


# -- routes registered ------------------------------------------------------
def test_write_routes_registered():
    ctx, s = _ctx_session()
    for method, path in [("POST", f"/api/sessions/{s.id}/pending"),
                         ("GET", f"/api/sessions/{s.id}/pending"),
                         ("DELETE", f"/api/sessions/{s.id}/pending"),
                         ("POST", f"/api/sessions/{s.id}/review"),
                         ("POST", f"/api/sessions/{s.id}/apply"),
                         ("POST", f"/api/sessions/{s.id}/bulk"),
                         ("POST", f"/api/sessions/{s.id}/undo")]:
        assert ctx.router.match(method, path) is not None, (method, path)


# -- stage / pending --------------------------------------------------------
def test_stage_then_pending():
    ctx, s = _ctx_session()
    res = _stage(ctx, s, {"name": "Reception"})
    assert res["ok"] and res["field_count"] == 1
    assert res["groups"][0]["row_key"] == "2104"
    req = FakeReq(params={"id": s.id})
    webapp.route_session_pending_get(ctx, req)
    assert req.json["field_count"] == 1
    assert "validation" in req.json


def test_clear_pending():
    ctx, s = _ctx_session()
    _stage(ctx, s, {"name": "Reception"})
    req = FakeReq(params={"id": s.id}, query={})
    webapp.route_session_pending_clear(ctx, req)
    assert req.json["field_count"] == 0 and s.changeset.is_empty()


# -- review (simulate, no network) ------------------------------------------
def test_review_simulate_no_network():
    ctx, s = _ctx_session(with_client=True)   # LoudClient attached
    _stage(ctx, s, {"name": "Reception"})
    req = FakeReq(body={"simulate": True}, params={"id": s.id})
    webapp.route_session_review(ctx, req)     # must NOT call LoudClient
    rev = req.json["review"]
    assert rev["simulate"] is True and rev["summary"]["will_send"] == 1
    assert rev["rows"][0]["proposed"] == "Reception"


# -- apply simulate = plan + op-log, no SET ---------------------------------
def test_apply_simulate_no_set():
    ctx, s = _ctx_session(with_client=True)
    _stage(ctx, s, {"name": "Reception"})
    req = FakeReq(body={"mode": "simulate"}, params={"id": s.id})
    webapp.route_session_apply(ctx, req)       # LoudClient.set must never fire
    assert req.json["ok"] and req.json["mode"] == "simulate"
    assert req.json["oplog"]["network"] is False
    assert req.json["oplog"]["would_send"] == 1
    assert req.json["oplog"]["commit_value_tlv_hex"] == "020102"
    assert not s.changeset.is_empty()          # simulate is a dry run


def test_apply_empty_tray():
    ctx, s = _ctx_session()
    req = FakeReq(body={"mode": "simulate"}, params={"id": s.id})
    webapp.route_session_apply(ctx, req)
    assert req.json["ok"] is False and req.status == 400


# -- live apply is gated ----------------------------------------------------
def test_apply_live_refused_when_disarmed():
    ctx, s = _ctx_session(with_client=True)    # armed? no.
    _stage(ctx, s, {"name": "Reception"})
    req = FakeReq(body={"mode": "live", "confirm": True}, params={"id": s.id})
    webapp.route_session_apply(ctx, req)       # must 409 BEFORE any SET
    assert req.status == 409 and "armed" in req.json["error"]


def test_apply_live_refused_without_confirm():
    ctx, s = _ctx_session(with_client=True)
    _stage(ctx, s, {"name": "Reception"})
    s.set_mode("armed")
    req = FakeReq(body={"mode": "live", "confirm": False}, params={"id": s.id})
    webapp.route_session_apply(ctx, req)
    assert req.status == 409 and "confirm" in req.json["error"]


# -- bulk stages into the same tray -----------------------------------------
def test_bulk_stages():
    ctx, s = _ctx_session()
    req = FakeReq(body={"op": "set", "program": PKEY, "selection": ["2"],
                        "field": "name", "value": "Reception"},
                  params={"id": s.id})
    webapp.route_session_bulk(ctx, req)
    assert req.json["ok"] and s.changeset.field_count() == 1


# -- undo re-stages the pre-write value -------------------------------------
def test_undo_restages_old_value():
    ctx, s = _ctx_session()
    s.last_applied = [{"program_key": PKEY, "program": "200", "index": "2",
                       "field": "name", "old_value": "Front Desk",
                       "new_value": "Reception", "oid": f"{ROOT}.3.200.1.1.19.1.2"}]
    req = FakeReq(body={}, params={"id": s.id})
    webapp.route_session_undo(ctx, req)
    assert req.json["ok"]
    # the revert is now staged back to the original value
    assert s.changeset.staged[PKEY]["2"]["name"] == "Front Desk"


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
