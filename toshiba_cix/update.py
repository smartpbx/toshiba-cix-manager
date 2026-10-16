"""Cross-platform self-updater for the Toshiba CIX Manager (pure stdlib).

The shipped binaries (the Linux ``*-x86_64.AppImage`` and the Windows
``Toshiba CIX Manager.exe``) can check GitHub Releases for a newer version and
replace themselves in place. A plain source / pip checkout is *not* replaced —
it reports "update via git/pip" instead.

Design rules (all enforced below):

* **Check is always safe** — a GET against the GitHub Releases API, every
  network/parse error swallowed into ``{"ok": False, "error": ...}``; it never
  raises and never touches the disk.
* **Apply only on explicit confirm** — :func:`apply_update` raises unless
  ``confirm=True``. It downloads to a sibling temp file, sanity-checks the HTTP
  status and size, and only then atomically swaps it over the running binary, so
  a failed or truncated download always leaves the working binary intact.
* **No new dependencies** — ``urllib`` only.

Public surface::

    from toshiba_cix import update
    info = update.check_for_update()         # {current, latest, newer, asset_url, ...}
    plan = update.plan_update(info)          # what an apply *would* replace
    res  = update.apply_update(info, confirm=True)
    update.relaunch(res["relaunch_argv"])    # os.execv into the new binary

Everything is module-level and I/O-injectable (``apply_update`` takes a
``_downloader``; :func:`check_for_update` goes through :func:`_http_get`) so the
whole thing is unit-testable with no network.
"""

from __future__ import annotations

import json
import os
import platform
import re
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request

from . import __version__

GITHUB_REPO = "smartpbx/toshiba-cix-manager"
LATEST_RELEASE_URL = (
    f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
)
RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases"
USER_AGENT = f"toshiba-cix-manager/{__version__}"

# A shipped binary bundles its own CPython, so it is tens of MB. Anything much
# smaller than this is an HTML error page or a truncated download, not a build.
_MIN_ASSET_BYTES = 500_000
# Hard ceiling so a hostile / runaway response can't fill the disk.
_MAX_ASSET_BYTES = 500_000_000

# Per-platform release-asset suffix. CI publishes exactly these names
# (``Toshiba_CIX_Manager-x86_64.AppImage`` and ``Toshiba CIX Manager.exe``).
_ASSET_SUFFIX = {"linux": "x86_64.AppImage", "windows": ".exe"}


class UpdateError(Exception):
    """Raised only for programming misuse (e.g. apply without confirm).

    Operational failures (network down, no asset, not replaceable) are returned
    as ``{"ok": False, ...}`` dicts, never raised — a failed update must not
    crash the caller.
    """


# --------------------------------------------------------------------------- #
# semver
# --------------------------------------------------------------------------- #
def _parse_version(value: str) -> tuple[int, int, int]:
    """Parse ``"v1.2.3"`` / ``"1.2"`` / ``"1.2.3-rc1"`` to a ``(maj, min, pat)``
    tuple. Pre-release / build metadata is ignored; missing parts are ``0``."""
    text = (value or "").strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    core = re.split(r"[-+]", text, maxsplit=1)[0]
    nums: list[int] = []
    for part in core.split("."):
        m = re.match(r"\d+", part)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])  # type: ignore[return-value]


def compare_versions(a: str, b: str) -> int:
    """Return -1 / 0 / 1 for ``a`` <, ==, > ``b`` (semver, v-prefix tolerant)."""
    pa, pb = _parse_version(a), _parse_version(b)
    return (pa > pb) - (pa < pb)


def is_newer(latest: str, current: str) -> bool:
    """True when ``latest`` is strictly newer than ``current``."""
    return compare_versions(latest, current) > 0


# --------------------------------------------------------------------------- #
# packaging / platform detection
# --------------------------------------------------------------------------- #
def detect_packaging() -> dict:
    """Describe how this process is packaged and whether it can self-replace.

    Returns a dict with:
        kind         : ``"appimage"`` | ``"windows_exe"`` | ``"source"``
        path         : the on-disk file an apply would replace (``None`` for source)
        replaceable  : whether an in-place self-replace is possible
        platform     : ``"linux"`` | ``"windows"`` | other
        asset_suffix : the matching release-asset filename suffix (or ``None``)
    """
    system = platform.system()
    appimage = os.environ.get("APPIMAGE")
    # Linux AppImage: the runtime sets $APPIMAGE to the running .AppImage path.
    if system == "Linux" and appimage:
        return {
            "kind": "appimage", "path": appimage, "replaceable": True,
            "platform": "linux", "asset_suffix": _ASSET_SUFFIX["linux"],
        }
    # Windows frozen exe (PyInstaller): sys.frozen is set, sys.executable is the exe.
    if getattr(sys, "frozen", False) and (system == "Windows" or os.name == "nt"):
        return {
            "kind": "windows_exe", "path": sys.executable, "replaceable": True,
            "platform": "windows", "asset_suffix": _ASSET_SUFFIX["windows"],
        }
    # Everything else (git clone, pip install, a non-AppImage frozen Linux build):
    # report "update via git/pip" and never self-replace.
    return {
        "kind": "source", "path": None, "replaceable": False,
        "platform": system.lower(), "asset_suffix": None,
    }


def select_asset(assets, packaging: dict):
    """Pick the release asset matching ``packaging`` from a GitHub ``assets`` list.

    Returns the asset dict (``{name, browser_download_url, size, ...}``) or
    ``None`` when nothing matches this platform.
    """
    suffix = packaging.get("asset_suffix")
    if not suffix or not assets:
        return None
    for asset in assets:
        if isinstance(asset, dict) and str(asset.get("name", "")).endswith(suffix):
            return asset
    return None


# --------------------------------------------------------------------------- #
# network
# --------------------------------------------------------------------------- #
def _http_get(url: str, *, accept: str | None = None, timeout: float = 15.0):
    """Minimal GET returning ``(status, body_bytes)``. Raises on transport error."""
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        return status, resp.read()


def check_for_update(*, current: str | None = None, timeout: float = 15.0) -> dict:
    """Query GitHub Releases for the latest version. **Never raises.**

    Returns::

        {ok, current, latest, latest_tag, newer, asset_url, asset_name,
         asset_size, packaging, replaceable, html_url, error}

    On any network/parse error ``ok`` is ``False`` and ``error`` carries the
    reason; nothing is downloaded or written.
    """
    current = current or __version__
    packaging = detect_packaging()
    result = {
        "ok": False, "current": current, "latest": None, "latest_tag": None,
        "newer": False, "asset_url": None, "asset_name": None, "asset_size": None,
        "packaging": packaging["kind"], "replaceable": packaging["replaceable"],
        "html_url": RELEASES_PAGE, "error": None,
    }
    try:
        status, raw = _http_get(
            LATEST_RELEASE_URL, accept="application/vnd.github+json",
            timeout=timeout)
        if status != 200:
            result["error"] = f"GitHub returned HTTP {status}"
            return result
        data = json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            ValueError, TimeoutError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    tag = str(data.get("tag_name") or data.get("name") or "").strip()
    norm = tag[1:] if tag[:1] in ("v", "V") else tag
    result["latest_tag"] = tag or None
    result["latest"] = norm or None
    result["html_url"] = data.get("html_url") or RELEASES_PAGE
    result["newer"] = bool(norm) and is_newer(norm, current)
    asset = select_asset(data.get("assets") or [], packaging)
    if asset:
        result["asset_url"] = asset.get("browser_download_url")
        result["asset_name"] = asset.get("name")
        result["asset_size"] = asset.get("size")
    result["ok"] = True
    return result


# --------------------------------------------------------------------------- #
# plan / apply
# --------------------------------------------------------------------------- #
def plan_update(check: dict | None = None, *, current: str | None = None) -> dict:
    """Describe what an :func:`apply_update` *would* do, touching nothing.

    Pass a ``check`` from :func:`check_for_update` to avoid a second network
    call. ``can_apply`` is ``True`` only when a newer version exists, this build
    is replaceable, and a matching asset is published.
    """
    check = check if check is not None else check_for_update(current=current)
    packaging = detect_packaging()
    plan = {
        "current": check.get("current"), "latest": check.get("latest"),
        "newer": check.get("newer"), "packaging": packaging["kind"],
        "replaceable": packaging["replaceable"], "target_path": packaging["path"],
        "asset_url": check.get("asset_url"), "asset_name": check.get("asset_name"),
        "can_apply": False, "reason": None, "html_url": check.get("html_url"),
    }
    if not check.get("ok"):
        plan["reason"] = check.get("error") or "update check failed"
    elif not check.get("newer"):
        plan["reason"] = "already up to date"
    elif not packaging["replaceable"]:
        plan["reason"] = (
            "running from source — update with 'git pull' or "
            "'pip install -U' (in-place self-replace is only for the "
            "AppImage / .exe builds)")
    elif not check.get("asset_url"):
        plan["reason"] = "no matching release asset for this platform"
    else:
        plan["can_apply"] = True
        plan["reason"] = (
            f"will replace {packaging['path']} with {check.get('asset_name')}")
    return plan


def _download(url: str, dest: str, *, timeout: float = 120.0,
              min_bytes: int = _MIN_ASSET_BYTES,
              max_bytes: int = _MAX_ASSET_BYTES) -> int:
    """Stream ``url`` to ``dest``. Returns bytes written.

    Raises :class:`UpdateError` on a non-200 status, an over-size body, or a
    body smaller than ``min_bytes`` (an error page / truncated download).
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/octet-stream"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    written = 0
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        if status != 200:
            raise UpdateError(f"download returned HTTP {status}")
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise UpdateError("download exceeded the maximum size")
                fh.write(chunk)
    if written < min_bytes:
        raise UpdateError(
            f"downloaded file is implausibly small ({written} bytes)")
    return written


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _install_unix(tmp: str, target: str, size: int) -> dict:
    """Make ``tmp`` executable, stage it as ``<target>.new``, then atomically
    swap it over the (open, running) AppImage path."""
    os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    staged = target + ".new"
    os.replace(tmp, staged)      # same directory -> atomic rename
    os.replace(staged, target)   # Linux lets us replace a file that is still open
    return {
        "ok": True, "action": "replaced", "path": target, "size": size,
        "needs_restart": True, "relaunch_argv": [target] + sys.argv[1:],
        "message": (f"Updated {os.path.basename(target)}. "
                    "Relaunch to run the new version."),
    }


def _install_windows(tmp: str, target: str, size: int) -> dict:
    """Stage the download as ``<target>.new``. A running ``.exe`` can't be
    overwritten on Windows, so it is installed on next start by
    :func:`finalize_pending_update`."""
    staged = target + ".new"
    os.replace(tmp, staged)
    return {
        "ok": True, "action": "staged", "path": target, "staged_path": staged,
        "size": size, "needs_restart": True,
        "message": ("Update staged. It installs automatically the next time you "
                    "start the app (Windows can't replace a running .exe)."),
    }


def apply_update(check: dict | None = None, *, confirm: bool = False,
                 current: str | None = None, timeout: float = 120.0,
                 _downloader=None) -> dict:
    """Download the latest release and install it over the running binary.

    **Requires ``confirm=True``** — otherwise raises :class:`UpdateError`.

    The download goes to a sibling temp file; only after a clean, size-checked
    download is it swapped in (atomically on Linux, staged on Windows). Any
    failure leaves the running binary untouched and is returned as
    ``{"ok": False, ...}``.

    ``_downloader`` is injectable for tests: ``fn(url, dest, timeout=...) -> int``.
    """
    if not confirm:
        raise UpdateError("apply_update requires confirm=True (never replace a "
                          "binary without explicit confirmation)")
    check = check if check is not None else check_for_update(current=current)
    plan = plan_update(check)
    if not plan["can_apply"]:
        return {"ok": False, "action": "none", "packaging": plan["packaging"],
                "message": plan["reason"], "html_url": plan.get("html_url")}

    packaging = detect_packaging()
    target = packaging["path"]
    url = check["asset_url"]
    download = _downloader or _download
    target_dir = os.path.dirname(os.path.abspath(target))

    try:
        fd, tmp = tempfile.mkstemp(prefix=".cix-update-", dir=target_dir)
        os.close(fd)
    except OSError as exc:
        return {"ok": False, "action": "none",
                "message": f"cannot write next to {target}: {exc}"}

    try:
        size = download(url, tmp, timeout=timeout)
    except Exception as exc:  # noqa: BLE001  — any failure must be non-fatal
        _safe_unlink(tmp)
        return {"ok": False, "action": "download_failed", "message": str(exc)}

    try:
        if packaging["kind"] == "appimage":
            return _install_unix(tmp, target, size)
        if packaging["kind"] == "windows_exe":
            return _install_windows(tmp, target, size)
        _safe_unlink(tmp)
        return {"ok": False, "action": "none",
                "message": "no installer for this packaging"}
    except Exception as exc:  # noqa: BLE001
        _safe_unlink(tmp)
        return {"ok": False, "action": "install_failed", "message": str(exc)}


def finalize_pending_update() -> dict:
    """Install a staged Windows update at startup (rename-on-next-start).

    No-op on every other platform and when nothing is staged. Fully defensive —
    it must never stop the app from launching. When it swaps a new exe in it
    returns ``relaunch_argv`` so the launcher can ``execv`` into it.
    """
    try:
        packaging = detect_packaging()
        if packaging["kind"] != "windows_exe":
            return {"ok": False, "action": "none"}
        exe = packaging["path"]
        staged = exe + ".new"
        if not os.path.exists(staged):
            return {"ok": False, "action": "none"}
        backup = exe + ".old"
        _safe_unlink(backup)
        # Windows permits renaming a running .exe (but not overwriting it):
        # move the current one aside, then drop the staged one into its place.
        os.replace(exe, backup)
        os.replace(staged, exe)
        return {"ok": True, "action": "finalized", "path": exe,
                "relaunch_argv": [exe] + sys.argv[1:]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "action": "error", "message": str(exc)}


def relaunch(argv=None):  # pragma: no cover  — replaces the process image
    """Replace the current process with a fresh launch of the (updated) binary.

    ``os.execv`` does not return on success.
    """
    argv = argv or [sys.executable] + sys.argv[1:]
    os.execv(argv[0], argv)
