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
# unit: SnapshotStore (now stores the v2 backup doc)
# ===========================================================================
import toshiba_cix.backup as _B  # noqa: E402
from test_backup import sample_capture as _sample_capture  # noqa: E402


def _doc(site="Example", names=("Front Desk", "Lobby", "Warehouse")):
    data, _ = _sample_capture(CAT, names=names)
    return _B.build_backup(list(data.items()), CAT,
                           meta={"site": site, "swid": "CIX670 R5.20"},
                           snapshot={"kind": "snapshot"})


def test_store_put_and_latest_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp, catalog=CAT)
        entry = st.put("104670-toner", _doc(), kind="manual")
        assert entry["id"] and entry["kind"] == "manual"
        assert entry["counts"]["programs"] >= 1 and entry["path"].endswith(".cixbak")
        full = st.latest("104670-toner")
        assert "200StationAssign" in full["programs"]
        assert full["meta"]["swid"] == "CIX670 R5.20"


def test_store_dedupes_identical_reads():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp, catalog=CAT)
        a = st.put("s", _doc(), kind="scheduled")
        b = st.put("s", _doc(), kind="scheduled")   # identical content
        assert b.get("dedupe_of") == a["id"] and b["path"] is None
        # the deduped row still resolves to the original doc for cold start
        assert st.get("s", b["id"])["meta"]["content_hash"] == a["content_hash"]
        # a changed read writes a real file
        c = st.put("s", _doc(names=("Front Desk", "Lobby", "Dock")), kind="scheduled")
        assert c.get("dedupe_of") is None and c["path"]


def test_store_name_pin_and_delete_protection():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp, catalog=CAT)
        e = st.put("s", _doc(), kind="manual")
        st.name("s", e["id"], "before PRI")
        entry = st.get_entry("s", e["id"])
        assert entry["name"] == "before PRI" and entry["kind"] == "named"
        # a named snapshot is protected from deletion
        ok, reason = st.delete("s", e["id"])
        assert ok is False and reason == "named"
        # force removes it
        ok, _ = st.delete("s", e["id"], force=True)
        assert ok and st.index("s") == []


def test_store_cixbak_roundtrip_and_export_redacts():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp, catalog=CAT)
        e = st.put("s", _doc(), kind="manual")
        # the .cixbak unpacks back to the stored doc
        import toshiba_cix.store as S
        path = os.path.join(tmp, "backups", "s", e["path"])
        doc, members = S.unpack_cixbak(path)
        assert "backup.json" in members and "MANIFEST.json" in members
        assert doc["meta"]["content_hash"] == e["content_hash"]
        # export is redacted by default
        fn, data = st.export("s", e["id"])
        assert fn.endswith(".cixbak")
        rdoc, _ = S.unpack_cixbak(data)
        assert rdoc["meta"]["redacted"] is True


def test_store_activity_trail_records_snapshots():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp, catalog=CAT)
        st.put("s", _doc(), kind="manual")
        acts = st.read_activity("s")
        assert acts and acts[0]["event"] == "snapshot"


def test_store_latest_missing_site():
    with tempfile.TemporaryDirectory() as tmp:
        assert SnapshotStore(tmp).latest("never-seen") is None
        assert SnapshotStore(tmp).index("never-seen") == []


def test_store_site_id_is_path_safe():
    with tempfile.TemporaryDirectory() as tmp:
        st = SnapshotStore(tmp, catalog=CAT)
        st.put("../../etc/evil", _doc())
        # nothing escaped the store root
        assert os.path.commonpath([tmp, os.path.abspath(
            os.path.join(tmp, "backups"))]) == os.path.abspath(tmp)
        assert not os.path.exists("/etc/evil.cixbak")


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
    # and the read also produced the v2 backup doc the store persists
    assert snap["backup"]["format_version"] == 2
    assert "200StationAssign" in snap["backup"]["programs"]
    assert snap["backup"]["meta"]["content_hash"].startswith("sha256:")


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

        # value index: the palette finds a station name in the working copy
        _, found = h.get(f"/api/sessions/{sid}/find?q=Front%20Desk")
        assert found["ok"] and found["count"] >= 1
        assert any(g["program"] == "200StationAssign" for g in found["groups"])
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
