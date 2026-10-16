"""Offline tests for the disk-state layer: appdirs, sites, journal.

All three are I/O-injected, so these drive them against a temp directory (and
the journal against an in-memory sqlite) with no touch to the real user
profile. Covers the per-OS root resolution incl. --portable, the sites.json
round-trip / upsert / delete and leg normalisation, and the journal commit/ops
round-trip with the ``index`` -> ``idx`` column mapping.

Run:  python3 tests/test_store.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import appdirs, journal, sites  # noqa: E402


# -- appdirs ----------------------------------------------------------------
def test_default_root_per_os():
    env = {"HOME": "/home/tech", "APPDATA": r"C:\Users\tech\AppData\Roaming",
           "XDG_DATA_HOME": ""}
    assert appdirs.default_root(env=env, platform="linux") == \
        "/home/tech/.local/share/switchroom"
    assert appdirs.default_root(env=env, platform="darwin") == \
        "/home/tech/Library/Application Support/Switchroom"
    win = appdirs.default_root(env=env, platform="win32")
    assert win.endswith("Switchroom") and "Roaming" in win


def test_xdg_data_home_honoured():
    env = {"HOME": "/home/tech", "XDG_DATA_HOME": "/data/xdg"}
    assert appdirs.default_root(env=env, platform="linux") == "/data/xdg/switchroom"


def test_portable_root_beside_executable():
    root = appdirs.portable_root(argv0="/media/usb/app.py")
    assert root == "/media/usb/Switchroom"
    assert appdirs.store_root(portable=True, argv0="/media/usb/app.py") == root


def test_override_wins():
    assert appdirs.store_root(override="/tmp/custom").endswith("custom")


def test_appdirs_layout_and_ensure():
    with tempfile.TemporaryDirectory() as tmp:
        d = appdirs.AppDirs(os.path.join(tmp, "store"))
        assert d.sites_file.endswith("sites.json")
        assert d.journal_db.endswith("journal.sqlite")
        assert d.changes_log.endswith("changes.log")
        assert d.log_file.endswith(os.path.join("logs", "app.log"))
        assert d.pending_file("104670-x").endswith("pending-104670-x.json")
        assert not os.path.exists(d.root)       # constructing is side-effect free
        d.ensure()
        assert os.path.isdir(d.root) and os.path.isdir(d.backups_dir)
        assert os.path.isdir(d.logs_dir)
        sb = d.ensure_site_backups("a/b")        # slug strips the separator
        assert os.path.isdir(sb) and "a-b" in sb


# -- sites ------------------------------------------------------------------
def test_slugify_and_new_site():
    assert sites.slugify_id("104670 Toner Farms — CIX100") == "104670-toner-farms-cix100"
    s = sites.new_site("104670 Toner Farms", pbx={"host": "172.23.4.19",
                                                  "community": "secret"})
    assert s["id"] == "104670-toner-farms"
    assert s["pbx"]["port"] == 161 and s["pbx"]["via"] == "direct"
    assert s["vm"]["transport"] == "serial" and s["vm"]["baud"] == 9600
    assert s["flags"]["persistence_verified"] is None


def test_sitebook_roundtrip_upsert_delete():
    with tempfile.TemporaryDirectory() as tmp:
        book = sites.sitebook_from_root(tmp)
        assert book.load() == []                 # missing file -> empty
        book.upsert(sites.new_site("Alpha"))
        book.upsert(sites.new_site("Bravo"))
        ids = {s["id"] for s in book.load()}
        assert ids == {"alpha", "bravo"}
        # upsert replaces in place, does not duplicate
        book.upsert({"id": "alpha", "name": "Alpha renamed", "pbx": {"host": "10.0.0.1"}})
        a = book.get("alpha")
        assert a["name"] == "Alpha renamed" and a["pbx"]["host"] == "10.0.0.1"
        assert len(book.load()) == 2
        assert book.delete("alpha") is True
        assert book.delete("nope") is False
        assert {s["id"] for s in book.load()} == {"bravo"}


def test_sitebook_file_is_private():
    with tempfile.TemporaryDirectory() as tmp:
        book = sites.sitebook_from_root(tmp)
        book.upsert(sites.new_site("Alpha"))
        assert os.path.exists(book.path)
        if not sys.platform.startswith("win"):
            assert (os.stat(book.path).st_mode & 0o077) == 0


def test_sitebook_ignores_corrupt_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "sites.json")
        with open(path, "w") as fh:
            fh.write("{not json")
        assert sites.SiteBook(path).load() == []


# -- journal ----------------------------------------------------------------
def test_journal_commit_and_ops_roundtrip():
    j = journal.Journal(":memory:")
    cid = j.start_commit(site="alpha", mode="write", transport="overlay",
                         device_identity="CIX100 R5.20B30")
    j.add_ops(cid, [
        {"program": "200", "index": "2104", "field": "stationStationName",
         "oid": "1.3.6.1.4.1.186.1.22.3.200.1.1.18.2104",
         "old": "Front Desk", "new": "Reception", "read_back": "Reception",
         "match": True},
        {"program": "103", "index": "3", "field": "cosAbr",
         "old": 1, "new": 2, "read_back": 2, "match": True},
    ])
    j.finish_commit(cid, ok=True)

    commits = j.list_commits()
    assert len(commits) == 1 and commits[0]["ok"] is True
    assert commits[0]["site"] == "alpha" and commits[0]["finished"]

    full = j.get_commit(cid)
    assert len(full["ops"]) == 2
    op0 = full["ops"][0]
    assert op0["index"] == "2104" and op0["field"] == "stationStationName"
    assert op0["match"] is True and "idx" not in op0
    j.close()


def test_journal_preview_mode_and_changes_log():
    with tempfile.TemporaryDirectory() as tmp:
        j = journal.journal_from_root(tmp)
        cid = j.start_commit(site="bravo", mode="preview")
        j.finish_commit(cid, ok=False)
        c = j.get_commit(cid)
        assert c["mode"] == "preview" and c["ok"] is False
        j.log_line("preview of 3 ops on bravo (nothing sent)")
        with open(os.path.join(tmp, "changes.log")) as fh:
            assert "nothing sent" in fh.read()
        j.close()


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
