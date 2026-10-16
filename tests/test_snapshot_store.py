"""Offline tests for the snapshot store's retention + import paths.

Complements the store round-trip / dedupe / export tests in test_browse.py.
These pin the safety rails the design holds us to (backups.md §13): prune never
removes a pinned, named, newest-full or referenced snapshot; a v1 bare .json
imports and upgrades; the .cixbak container is reproducible. No network.

Run:  python3 tests/test_snapshot_store.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import toshiba_cix.backup as B  # noqa: E402
import toshiba_cix.store as S  # noqa: E402
from test_backup import sample_capture  # noqa: E402
from toshiba_cix.catalog import load_catalog  # noqa: E402

CAT = load_catalog()


def _doc(names=("Front Desk", "Lobby", "Warehouse"), site="Example"):
    data, _ = sample_capture(CAT, names=names)
    return B.build_backup(list(data.items()), CAT,
                          meta={"site": site}, snapshot={"kind": "snapshot"})


def _vary(i):
    # distinct content each call so each put writes a real (non-deduped) file
    return _doc(names=("Front Desk", "Lobby", f"Bay{i}"))


def test_prune_respects_keep_and_protects_special():
    with tempfile.TemporaryDirectory() as tmp:
        st = S.SnapshotStore(tmp, catalog=CAT)
        ids = [st.put("s", _vary(i), kind="auto-post-write")["id"] for i in range(6)]
        # pin the oldest, name the second — both must survive any prune
        st.pin("s", ids[0], True)
        st.name("s", ids[1], "as-built")
        removed = st.prune("s", policy={"auto-post-write": {"keep": 2}})
        kept = {e["id"] for e in st.index("s")}
        assert ids[0] in kept and ids[1] in kept       # pinned / named protected
        assert removed                                  # something was pruned
        # the newest full snapshot is never pruned either
        newest = max(st.index("s"), key=lambda e: e["read_at"])
        assert newest["id"] in kept


def test_prune_keeps_referenced_parent():
    with tempfile.TemporaryDirectory() as tmp:
        st = S.SnapshotStore(tmp, catalog=CAT)
        base = st.put("s", _vary(0), kind="auto-pre-write")["id"]
        # a later snapshot declares base as its parent
        st.put("s", _vary(1), kind="auto-post-write", parent=base)
        for i in range(2, 8):
            st.put("s", _vary(i), kind="auto-pre-write")
        st.prune("s", policy={"auto-pre-write": {"keep": 1},
                              "auto-post-write": {"keep": 1}})
        assert st.get_entry("s", base) is not None     # referenced parent kept


def test_import_v1_json_upgrades_and_keeps():
    with tempfile.TemporaryDirectory() as tmp:
        st = S.SnapshotStore(tmp, catalog=CAT)
        v1 = {"format": "toshiba-cix-backup", "format_version": 1,
              "meta": {"site": "Legacy"},
              "programs": {"104SystemTimer": {"number": "104",
                  "name": "SystemTimer",
                  "rows": [{"index": "0", "key": "_", "fields": {}}]}},
              "unmatched": []}
        entry = st.import_doc("s", v1, kind="imported", name="eManager export")
        assert entry["kind"] == "imported" and entry["name"] == "eManager export"
        doc = st.get("s", entry["id"])
        assert doc["format_version"] == 2
        assert doc["meta"]["content_hash"].startswith("sha256:")


def test_import_cixbak_bytes_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        st = S.SnapshotStore(tmp, catalog=CAT)
        data = S.pack_cixbak(_doc(), catalog=CAT)
        entry = st.import_doc("s", data)
        doc = st.get("s", entry["id"])
        assert "200StationAssign" in doc["programs"]


def test_cixbak_pack_is_reproducible():
    doc = _doc()
    a = S.pack_cixbak(doc, catalog=CAT)
    b = S.pack_cixbak(doc, catalog=CAT)
    assert a == b                                      # byte-identical


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
