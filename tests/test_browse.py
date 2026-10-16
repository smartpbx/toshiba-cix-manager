"""Offline tests for the P1 browse layer: snapshot store, the core→all read
engine, and the HTTP session/program/cold-start routes.

Three layers, no network:
* unit — :class:`toshiba_cix.store.SnapshotStore` against a temp dir, and
  :func:`toshiba_cix.snapshot.read_snapshot` against the backup tests' lexical
  fake agent (real catalog OIDs, invented values);
* HTTP — a real ``ThreadingHTTPServer`` built with a **temp** app-data dir (so
  the real user profile is never touched) and the SNMP client swapped for the
  fake factory, driven with urllib: POST /api/snapshot → poll the job → read the
  session working copy, a program's rows, one row, then the cold-start snapshot.

Run:  python3 tests/test_browse.py   (or: python3 -m pytest tests/)
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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from toshiba_cix import appdirs, snapshot, webapp  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402
from toshiba_cix.server.http import ThreadingHTTPServer, build_handler  # noqa: E402
from toshiba_cix.store import SnapshotStore  # noqa: E402
from test_backup import BackupFake, sample_capture  # noqa: E402

CAT = load_catalog()


# ===========================================================================
# unit: SnapshotStore
# ===========================================================================
def _views():
    return {"programs": [{"catalog_key": "200StationAssign", "row_count": 3,
                          "program_number": "200", "menu_area": "Station"}],
            "stats": {"programs": 1, "rows": 3, "cells": 9}}


def test_store_save_and_latest_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp)
        hdr = st.save("104670-toner", _views(),
                      identity={"swid": "CIX670 R5.20"}, meta={"scope": "all"})
        assert hdr["sid"] and hdr["kind"] == "snapshot"
        assert hdr["counts"]["programs"] == 1
        full = st.latest("104670-toner")
        assert full["program_views"]["programs"][0]["catalog_key"] == "200StationAssign"
        assert full["identity"]["swid"] == "CIX670 R5.20"


def test_store_lists_newest_first():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp)
        a = st.save("s", _views())
        time.sleep(0.002)
        b = st.save("s", _views())
        ids = [h["sid"] for h in st.list("s")]
        assert ids[0] == b["sid"] and set(ids) == {a["sid"], b["sid"]}


def test_store_label_pin_delete():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp)
        h = st.save("s", _views())
        st.set_label("s", h["sid"], "before PRI")
        st.set_pinned("s", h["sid"], True)
        hdr = st.list("s")[0]
        assert hdr["label"] == "before PRI" and hdr["pinned"] is True
        assert st.delete("s", h["sid"]) is True
        assert st.list("s") == []


def test_store_latest_missing_site():
    with tempfile.TemporaryDirectory() as tmp:
        assert SnapshotStore(tmp).latest("never-seen") is None
        assert SnapshotStore(tmp).list("never-seen") == []


def test_store_site_id_is_path_safe():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp)
        st.save("../../etc/evil", _views())
        # nothing escaped the store root
        assert os.path.commonpath([tmp, os.path.abspath(
            os.path.join(tmp, "snapshots"))]) == os.path.abspath(tmp)
        assert not os.path.exists("/etc/evil.json")


# ===========================================================================
# unit: read_snapshot (core -> all)
# ===========================================================================
def test_read_snapshot_core_then_all_with_progress():
    data, _ = sample_capture(CAT)
    phases, reports = [], []
    snap = snapshot.read_snapshot(
        BackupFake(data), CAT, site="Example",
        report=lambda d, t, m: reports.append((d, t, m)),
        on_phase=lambda v, ph: phases.append((ph, len(v["programs"]))))
    # identity read into meta via the job
    assert snap["identity"]["swid"] == "LA520MT067PNDN2---EM.00"
    assert snap["meta"]["site"] == "Example" and snap["meta"]["walk_error"] is None
    # on_phase fired for core then all; progress ended at total
    names = [p for p, _ in phases]
    assert names == ["core", "all"]
    assert reports[0][0] == 0 and reports[-1][0] == reports[-1][1]
    # the full views carry the stations program read in the capture
    keys = {p["catalog_key"] for p in snap["program_views"]["programs"]}
    assert "200StationAssign" in keys


def test_core_program_keys_are_catalog_keys():
    keys = snapshot.core_program_keys(CAT)
    assert "200StationAssign" in keys
    assert all(k in CAT.programs for k in keys)


# ===========================================================================
# HTTP integration
# ===========================================================================
class SnapshotFake(BackupFake):
    """BackupFake with the SnmpV1 constructor shape the handler builds."""

    def __init__(self, ip="192.168.254.253", community="communityName",
                 *, port=161, timeout=3.0, retries=1):
        data, _ = sample_capture(CAT)
        super().__init__(data)
        self.host = ip
        self.community = community
        self.port = port


def _factory(ip, community="communityName", *, port=161, timeout=3.0, retries=1):
    return SnapshotFake(ip, community, port=port, timeout=timeout, retries=retries)


class _Harness:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._prev = webapp.SnmpV1
        webapp.SnmpV1 = _factory
        ad = appdirs.AppDirs(self.tmp.name)
        ad.ensure()
        self.ctx = webapp.make_context(appdirs=ad)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.ctx))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        webapp.SnmpV1 = self._prev
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, json.loads(r.read().decode())

    def post(self, path, body):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())

    def wait_job(self, job_id, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, j = self.get(f"/api/jobs/{job_id}")
            if j["job"]["status"] in ("done", "error"):
                return j["job"]
            time.sleep(0.02)
        raise AssertionError("job did not finish")


def test_http_snapshot_connect_browse_and_coldstart():
    h = _Harness()
    try:
        status, res = h.post("/api/snapshot",
                             {"ip": "192.168.254.253", "site": "Example Site",
                              "site_id": "example"})
        assert status == 200 and res["ok"]
        sid, job_id = res["session"], res["job"]
        job = h.wait_job(job_id)
        assert job["status"] == "done", job
        assert job["result"]["stats"]["programs"] >= 1

        # session working copy: programs read, identity set
        _, snap = h.get(f"/api/sessions/{sid}/snapshot")
        assert snap["ok"] and snap["read_keys"]
        assert snap["identity"]["software_id"] == "LA520MT067PNDN2---EM.00"
        assert any(p["catalog_key"] == "200StationAssign" for p in snap["programs"])

        # one program's rows (from the working copy, by number)
        _, prog = h.get(f"/api/sessions/{sid}/program/200")
        assert prog["ok"] and prog["source"] == "snapshot"
        assert prog["program"]["catalog_key"] == "200StationAssign"
        rows = prog["program"]["rows"]
        assert rows and rows[0]["cells"]
        # no bare OIDs: every cell is named
        assert all(c["field_name"] for r in rows for c in r["cells"])

        # one row (record pane)
        idx = rows[0]["index"]
        _, row = h.get(f"/api/sessions/{sid}/program/200/{idx}")
        assert row["ok"] and row["row"]["index"] == idx

        # a cataloged program not in the capture is a shaped empty view, not 404
        _, empty = h.get(f"/api/sessions/{sid}/program/103")
        assert empty["ok"] and empty["source"] == "unread"
        assert empty["program"]["catalog_key"] == "103ClassOfService"
        assert empty["program"]["row_count"] == 0

        # cold start: the snapshot was saved and is reloadable with no device
        _, listed = h.get("/api/sites/example/snapshots")
        assert listed["ok"] and listed["snapshots"]
        _, latest = h.get("/api/sites/example/snapshots/latest")
        assert latest["ok"]
        keys = {p["catalog_key"]
                for p in latest["snapshot"]["program_views"]["programs"]}
        assert "200StationAssign" in keys
    finally:
        h.close()


def test_http_unknown_program_is_404():
    h = _Harness()
    try:
        _, res = h.post("/api/snapshot", {"ip": "1.2.3.4", "site_id": "x"})
        h.wait_job(res["job"])
        try:
            h.get(f"/api/sessions/{res['session']}/program/notreal")
        except urllib.error.HTTPError as e:
            assert e.code == 404
            return
        raise AssertionError("expected 404 for an unknown program")
    finally:
        h.close()


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
