"""Offline tests for the self-updater (toshiba_cix.update).

Every GitHub API call and every download is mocked — nothing here touches the
network or the real running binary. The "apply" tests write to a throwaway temp
directory standing in for the AppImage path.

Run:  python3 tests/test_update.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import update  # noqa: E402


# -- patching helpers (no pytest fixtures: the standalone runner calls fn()) --
@contextlib.contextmanager
def _patched(obj, attr, value):
    missing = object()
    old = getattr(obj, attr, missing)
    setattr(obj, attr, value)
    try:
        yield
    finally:
        if old is missing:
            try:
                delattr(obj, attr)
            except AttributeError:
                pass
        else:
            setattr(obj, attr, old)


@contextlib.contextmanager
def _env(key, value):
    missing = object()
    old = os.environ.get(key, missing)
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value
    try:
        yield
    finally:
        if old is missing:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old


_APPIMAGE_PKG = {"kind": "appimage", "path": "/opt/app-x86_64.AppImage",
                 "replaceable": True, "platform": "linux",
                 "asset_suffix": "x86_64.AppImage"}
_WINDOWS_PKG = {"kind": "windows_exe", "path": r"C:\app\Toshiba CIX Manager.exe",
                "replaceable": True, "platform": "windows", "asset_suffix": ".exe"}
_SOURCE_PKG = {"kind": "source", "path": None, "replaceable": False,
               "platform": "linux", "asset_suffix": None}


def _release_json(tag="v1.2.0", assets=None):
    if assets is None:
        assets = [
            {"name": "Toshiba_CIX_Manager-x86_64.AppImage",
             "browser_download_url": "https://example.test/a.AppImage",
             "size": 40_000_000},
            {"name": "Toshiba CIX Manager.exe",
             "browser_download_url": "https://example.test/a.exe",
             "size": 30_000_000},
        ]
    return json.dumps({
        "tag_name": tag, "name": tag,
        "html_url": "https://example.test/releases/" + tag,
        "assets": assets,
    }).encode("utf-8")


class _FakeResp:
    def __init__(self, data, status=200):
        self._buf = io.BytesIO(data)
        self.status = status

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# -- semver -----------------------------------------------------------------
def test_compare_versions_newer_older_equal():
    assert update.compare_versions("1.2.0", "1.1.0") == 1
    assert update.compare_versions("1.1.0", "1.2.0") == -1
    assert update.compare_versions("1.1.0", "1.1.0") == 0
    # v-prefix and uneven lengths are tolerated
    assert update.compare_versions("v2.0", "1.9.9") == 1
    assert update.compare_versions("1.1", "1.1.0") == 0
    # pre-release metadata is ignored down to the numeric core
    assert update.compare_versions("1.2.0-rc1", "1.2.0") == 0


def test_is_newer():
    assert update.is_newer("1.2.0", "1.1.0") is True
    assert update.is_newer("1.1.0", "1.1.0") is False
    assert update.is_newer("1.0.0", "1.1.0") is False


# -- asset selection --------------------------------------------------------
def test_select_asset_linux_picks_appimage():
    assets = [
        {"name": "Toshiba CIX Manager.exe", "browser_download_url": "u-exe"},
        {"name": "Toshiba_CIX_Manager-x86_64.AppImage",
         "browser_download_url": "u-appimage"},
    ]
    chosen = update.select_asset(assets, _APPIMAGE_PKG)
    assert chosen["browser_download_url"] == "u-appimage"


def test_select_asset_windows_picks_exe():
    assets = [
        {"name": "Toshiba_CIX_Manager-x86_64.AppImage",
         "browser_download_url": "u-appimage"},
        {"name": "Toshiba CIX Manager.exe", "browser_download_url": "u-exe"},
    ]
    chosen = update.select_asset(assets, _WINDOWS_PKG)
    assert chosen["browser_download_url"] == "u-exe"


def test_select_asset_source_none():
    assert update.select_asset([{"name": "x.AppImage"}], _SOURCE_PKG) is None


def test_select_asset_no_match():
    assert update.select_asset([{"name": "notes.txt"}], _APPIMAGE_PKG) is None


# -- packaging detection ----------------------------------------------------
def test_detect_packaging_appimage():
    with _patched(update.platform, "system", lambda: "Linux"), \
         _env("APPIMAGE", "/opt/App-x86_64.AppImage"):
        pkg = update.detect_packaging()
    assert pkg["kind"] == "appimage"
    assert pkg["path"] == "/opt/App-x86_64.AppImage"
    assert pkg["replaceable"] is True
    assert pkg["asset_suffix"] == "x86_64.AppImage"


def test_detect_packaging_windows_frozen():
    with _patched(update.platform, "system", lambda: "Windows"), \
         _env("APPIMAGE", None), \
         _patched(update.sys, "frozen", True), \
         _patched(update.sys, "executable", r"C:\app\Toshiba CIX Manager.exe"):
        pkg = update.detect_packaging()
    assert pkg["kind"] == "windows_exe"
    assert pkg["replaceable"] is True
    assert pkg["asset_suffix"] == ".exe"
    assert pkg["path"].endswith(".exe")


def test_detect_packaging_source():
    with _patched(update.platform, "system", lambda: "Linux"), \
         _env("APPIMAGE", None), \
         _patched(update.sys, "frozen", False):
        pkg = update.detect_packaging()
    assert pkg["kind"] == "source"
    assert pkg["replaceable"] is False
    assert pkg["path"] is None
    assert pkg["asset_suffix"] is None


# -- check_for_update -------------------------------------------------------
def test_check_newer_selects_linux_asset():
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)), \
         _patched(update, "_http_get", lambda *a, **k: (200, _release_json("v1.2.0"))):
        info = update.check_for_update(current="1.1.0")
    assert info["ok"] is True
    assert info["newer"] is True
    assert info["latest"] == "1.2.0"
    assert info["latest_tag"] == "v1.2.0"
    assert info["asset_url"].endswith(".AppImage")
    assert info["replaceable"] is True


def test_check_newer_selects_windows_asset():
    with _patched(update, "detect_packaging", lambda: dict(_WINDOWS_PKG)), \
         _patched(update, "_http_get", lambda *a, **k: (200, _release_json("v1.2.0"))):
        info = update.check_for_update(current="1.1.0")
    assert info["ok"] is True and info["newer"] is True
    assert info["asset_url"].endswith(".exe")


def test_check_equal_is_not_newer():
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)), \
         _patched(update, "_http_get", lambda *a, **k: (200, _release_json("v1.1.0"))):
        info = update.check_for_update(current="1.1.0")
    assert info["ok"] is True
    assert info["newer"] is False
    assert info["latest"] == "1.1.0"


def test_check_older_is_not_newer():
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)), \
         _patched(update, "_http_get", lambda *a, **k: (200, _release_json("v1.0.0"))):
        info = update.check_for_update(current="1.1.0")
    assert info["ok"] is True and info["newer"] is False


def test_check_http_error_status_is_safe():
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)), \
         _patched(update, "_http_get", lambda *a, **k: (503, b"nope")):
        info = update.check_for_update(current="1.1.0")
    assert info["ok"] is False
    assert "503" in info["error"]
    assert info["newer"] is False


def test_check_network_error_is_safe():
    def boom(*a, **k):
        raise urllib.error.URLError("no network")

    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)), \
         _patched(update, "_http_get", boom):
        info = update.check_for_update(current="1.1.0")
    assert info["ok"] is False
    assert info["error"]
    assert info["newer"] is False


# -- plan_update ("what would be replaced") ---------------------------------
def test_plan_source_reports_git_pip():
    check = {"ok": True, "current": "1.1.0", "latest": "1.2.0", "newer": True,
             "asset_url": None, "asset_name": None,
             "html_url": "https://example.test"}
    with _patched(update, "detect_packaging", lambda: dict(_SOURCE_PKG)):
        plan = update.plan_update(check)
    assert plan["can_apply"] is False
    assert plan["replaceable"] is False
    assert "git" in plan["reason"] and "pip" in plan["reason"]


def test_plan_appimage_newer_can_apply():
    check = {"ok": True, "current": "1.1.0", "latest": "1.2.0", "newer": True,
             "asset_url": "https://example.test/a.AppImage",
             "asset_name": "a.AppImage", "html_url": "https://example.test"}
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)):
        plan = update.plan_update(check)
    assert plan["can_apply"] is True
    assert plan["target_path"] == _APPIMAGE_PKG["path"]
    assert plan["asset_name"] == "a.AppImage"
    assert _APPIMAGE_PKG["path"] in plan["reason"]


def test_plan_current_is_latest_noop():
    check = {"ok": True, "current": "1.1.0", "latest": "1.1.0", "newer": False,
             "asset_url": "https://example.test/a.AppImage",
             "asset_name": "a.AppImage", "html_url": "https://example.test"}
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)):
        plan = update.plan_update(check)
    assert plan["can_apply"] is False
    assert plan["reason"] == "already up to date"


def test_plan_newer_but_no_asset():
    check = {"ok": True, "current": "1.1.0", "latest": "1.2.0", "newer": True,
             "asset_url": None, "asset_name": None,
             "html_url": "https://example.test"}
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)):
        plan = update.plan_update(check)
    assert plan["can_apply"] is False
    assert "no matching release asset" in plan["reason"]


# -- apply_update -----------------------------------------------------------
def test_apply_requires_confirm():
    try:
        update.apply_update({"ok": True}, confirm=False)
    except update.UpdateError:
        return
    raise AssertionError("apply_update without confirm must raise UpdateError")


def test_apply_appimage_replaces_binary_and_is_executable():
    d = tempfile.mkdtemp()
    try:
        target = os.path.join(d, "Toshiba_CIX_Manager-x86_64.AppImage")
        with open(target, "wb") as fh:
            fh.write(b"OLD-BINARY")
        pkg = {**_APPIMAGE_PKG, "path": target}
        check = {"ok": True, "current": "1.1.0", "latest": "1.2.0",
                 "newer": True, "asset_url": "https://example.test/a.AppImage",
                 "asset_name": "a.AppImage", "html_url": "https://example.test"}

        def fake_dl(url, dest, timeout=120.0):
            data = b"NEW-BINARY-" + b"x" * 2000
            with open(dest, "wb") as fh:
                fh.write(data)
            return len(data)

        with _patched(update, "detect_packaging", lambda: dict(pkg)):
            res = update.apply_update(check, confirm=True, _downloader=fake_dl)

        assert res["ok"] is True
        assert res["action"] == "replaced"
        with open(target, "rb") as fh:
            assert fh.read().startswith(b"NEW-BINARY-")
        assert os.stat(target).st_mode & stat.S_IXUSR
        assert res["relaunch_argv"][0] == target
        # staging file is gone; no temp litter left behind
        assert not os.path.exists(target + ".new")
        assert sorted(os.listdir(d)) == [os.path.basename(target)]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_apply_download_failure_keeps_binary_intact():
    d = tempfile.mkdtemp()
    try:
        target = os.path.join(d, "a-x86_64.AppImage")
        with open(target, "wb") as fh:
            fh.write(b"OLD-BINARY")
        pkg = {**_APPIMAGE_PKG, "path": target}
        check = {"ok": True, "current": "1.1.0", "latest": "1.2.0",
                 "newer": True, "asset_url": "https://example.test/a.AppImage",
                 "asset_name": "a.AppImage", "html_url": "https://example.test"}

        def boom(url, dest, timeout=120.0):
            # simulate a half-written file then a failure
            with open(dest, "wb") as fh:
                fh.write(b"partial")
            raise update.UpdateError("connection reset")

        with _patched(update, "detect_packaging", lambda: dict(pkg)):
            res = update.apply_update(check, confirm=True, _downloader=boom)

        assert res["ok"] is False
        assert res["action"] == "download_failed"
        with open(target, "rb") as fh:
            assert fh.read() == b"OLD-BINARY"          # untouched
        # the temp download was cleaned up
        assert sorted(os.listdir(d)) == [os.path.basename(target)]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_apply_source_is_noop():
    check = {"ok": True, "current": "1.1.0", "latest": "1.2.0", "newer": True,
             "asset_url": None, "asset_name": None,
             "html_url": "https://example.test"}
    with _patched(update, "detect_packaging", lambda: dict(_SOURCE_PKG)):
        res = update.apply_update(check, confirm=True)
    assert res["ok"] is False
    assert res["action"] == "none"


def test_apply_current_is_latest_noop():
    check = {"ok": True, "current": "1.1.0", "latest": "1.1.0", "newer": False,
             "asset_url": "https://example.test/a.AppImage",
             "asset_name": "a.AppImage", "html_url": "https://example.test"}
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)):
        res = update.apply_update(check, confirm=True)
    assert res["ok"] is False
    assert res["action"] == "none"
    assert res["message"] == "already up to date"


# -- _download size / status guards -----------------------------------------
def test_download_rejects_small_body():
    def fake_urlopen(req, timeout=None, context=None):
        return _FakeResp(b"tiny error page", 200)

    d = tempfile.mkdtemp()
    try:
        dest = os.path.join(d, "x")
        with _patched(update.urllib.request, "urlopen", fake_urlopen):
            try:
                update._download("https://example.test", dest, min_bytes=1_000_000)
            except update.UpdateError:
                return
        raise AssertionError("a too-small download must raise UpdateError")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_download_rejects_non_200():
    def fake_urlopen(req, timeout=None, context=None):
        return _FakeResp(b"x" * 2_000_000, 404)

    d = tempfile.mkdtemp()
    try:
        dest = os.path.join(d, "x")
        with _patched(update.urllib.request, "urlopen", fake_urlopen):
            try:
                update._download("https://example.test", dest, min_bytes=1)
            except update.UpdateError:
                return
        raise AssertionError("a non-200 download must raise UpdateError")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_download_ok_returns_size():
    payload = b"N" * 2_000_000

    def fake_urlopen(req, timeout=None, context=None):
        return _FakeResp(payload, 200)

    d = tempfile.mkdtemp()
    try:
        dest = os.path.join(d, "x")
        with _patched(update.urllib.request, "urlopen", fake_urlopen):
            n = update._download("https://example.test", dest, min_bytes=1000)
        assert n == len(payload)
        with open(dest, "rb") as fh:
            assert fh.read() == payload
    finally:
        shutil.rmtree(d, ignore_errors=True)


# -- finalize_pending_update (Windows staged install) -----------------------
def test_finalize_noop_when_not_windows():
    with _patched(update, "detect_packaging", lambda: dict(_APPIMAGE_PKG)):
        res = update.finalize_pending_update()
    assert res["ok"] is False and res["action"] == "none"


def test_finalize_installs_staged_exe():
    d = tempfile.mkdtemp()
    try:
        exe = os.path.join(d, "Toshiba CIX Manager.exe")
        with open(exe, "wb") as fh:
            fh.write(b"RUNNING-OLD")
        with open(exe + ".new", "wb") as fh:
            fh.write(b"STAGED-NEW")
        pkg = {**_WINDOWS_PKG, "path": exe}
        with _patched(update, "detect_packaging", lambda: dict(pkg)):
            res = update.finalize_pending_update()
        assert res["ok"] is True and res["action"] == "finalized"
        with open(exe, "rb") as fh:
            assert fh.read() == b"STAGED-NEW"
        assert not os.path.exists(exe + ".new")
        assert os.path.exists(exe + ".old")          # old moved aside
        assert res["relaunch_argv"][0] == exe
    finally:
        shutil.rmtree(d, ignore_errors=True)


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
