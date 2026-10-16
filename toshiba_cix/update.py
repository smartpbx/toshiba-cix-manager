"""Cross-platform self-updater for the Toshiba CIX Manager (pure stdlib).

The self-contained single-file builds (the Linux ``*-x86_64.AppImage`` and the
Windows ``Toshiba CIX Manager.exe``) check GitHub Releases for a newer version
and **replace themselves in place**. The Tauri "Switchroom" bundles are
package-manager-owned — the ``.deb`` installs a dpkg-managed ``/usr/bin``
binary, the ``.msi`` / NSIS build an MSI-managed one — so those must NOT be
overwritten in place: an apply **downloads the matching installer and hands it
to the system installer** (``xdg-open`` / dpkg·apt for the ``.deb``,
``msiexec`` / ``ShellExecute`` for the ``.msi``). A plain source / pip checkout
is never touched — it reports "update via git/pip" instead.

:func:`detect_packaging` tells these apart (``appimage`` · ``windows_exe`` ·
``deb`` · ``msi`` · ``source``) and :func:`install_method` maps each to
``self_replace`` · ``installer`` · ``none``.

Design rules (all enforced below):

* **Check is always safe** — a GET against the GitHub Releases API, every
  network/parse error swallowed into ``{"ok": False, "error": ...}``; it never
  raises and never touches the disk.
* **Apply only on explicit confirm** — :func:`apply_update` raises unless
  ``confirm=True``. A *self-replace* downloads to a sibling temp file,
  sanity-checks the HTTP status and size, and only then atomically swaps it over
  the running binary, so a failed or truncated download always leaves the
  working binary intact. An *installer* handoff stages the package in a
  user-writable directory (never the package-manager-owned binary dir) and only
  then launches the OS installer.
* **No new dependencies** — ``urllib`` + ``subprocess`` (both stdlib).

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
import subprocess
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

# Per-packaging release-asset matching. CI attaches BOTH the self-contained
# stdlib builds (``Toshiba CIX Manager.exe``, ``Toshiba_CIX_Manager-x86_64.AppImage``)
# AND the Tauri "Switchroom" bundles (``*.deb`` / ``*.AppImage`` on Linux,
# ``*.msi`` + NSIS ``*-setup.exe`` on Windows) to the SAME release, so a single
# suffix is ambiguous — a raw ``.exe`` and an NSIS ``*-setup.exe`` both end in
# ``.exe``. Each kind carries an ordered list of ``(include, exclude)`` name
# matchers (case-insensitive); the first asset whose name contains ``include``
# and not ``exclude`` wins. ``_ASSET_SUFFIX`` is kept for backward-compatible
# callers / tests that still match by a bare suffix.
_ASSET_MATCH = {
    "appimage": [(".appimage", None)],
    "windows_exe": [(".exe", "-setup.exe")],        # the raw PyInstaller exe, not NSIS
    "deb": [(".deb", None)],
    "msi": [(".msi", None), ("-setup.exe", None)],   # prefer MSI, fall back to NSIS
}
_ASSET_SUFFIX = {
    "appimage": "x86_64.AppImage",
    "windows_exe": ".exe",
    "deb": ".deb",
    "msi": ".msi",
}

# How an apply installs each packaging kind:
#   self_replace — swap the running self-contained single file (AppImage / raw .exe)
#   installer    — download the OS package and hand off to the system installer
#                  (dpkg/apt for .deb, msiexec/NSIS for .msi); never overwrite a
#                  package-manager-owned binary in place
#   none         — a git/pip source checkout; update out-of-band
_INSTALL_METHOD = {
    "appimage": "self_replace",
    "windows_exe": "self_replace",
    "deb": "installer",
    "msi": "installer",
    "source": "none",
}


def install_method(kind: str) -> str:
    """The install strategy for a packaging ``kind`` (see ``_INSTALL_METHOD``)."""
    return _INSTALL_METHOD.get(kind, "none")


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
def _tauri_sidecar() -> bool:
    """True when this process is the Switchroom engine spawned by the Tauri shell.

    The desktop shell (``desktop/src-tauri/src/main.rs``) always spawns the
    PyInstaller engine with ``$SWITCHROOM_TOKEN`` set, and the bundler installs
    that engine as ``switchroom-engine`` next to the ``switchroom`` shell binary.
    Either signal means "running inside a Tauri bundle" — which tells a raw
    standalone PyInstaller build (self-replaceable) apart from a
    package-manager-owned Tauri install (installer handoff only)."""
    if os.environ.get("SWITCHROOM_TOKEN"):
        return True
    # Split on both separators so a Windows sidecar path is recognised even when
    # detection happens to run under POSIX os.path (e.g. a Linux CI host).
    base = re.split(r"[\\/]", sys.executable or "")[-1].lower()
    return base in ("switchroom-engine", "switchroom-engine.exe")


def _appimage_match(path: str | None):
    """Prefer the release AppImage whose name shares the running AppImage's
    product token (so a ``Switchroom`` AppImage self-updates to the Switchroom
    asset, not the stdlib one, when both are attached to the same release)."""
    base = os.path.basename(path or "").lower()
    token = re.split(r"[-_. ]", base, maxsplit=1)[0] if base else ""
    if len(token) >= 3:
        return [(token, None), (".appimage", None)]
    return [(".appimage", None)]


def detect_packaging() -> dict:
    """Describe how this process is packaged and how an apply should install.

    Returns a dict with:
        kind           : ``"appimage"`` | ``"windows_exe"`` | ``"deb"`` |
                         ``"msi"`` | ``"source"``
        path           : the on-disk file an apply acts on (``None`` for source)
        replaceable    : ``True`` only for an in-place self-replace (appimage/exe)
        install_method : ``"self_replace"`` | ``"installer"`` | ``"none"``
        platform       : ``"linux"`` | ``"windows"`` | other
        asset_suffix   : backward-compatible release-asset filename suffix
        asset_match    : ordered ``(include, exclude)`` matchers for :func:`select_asset`

    ``$SWITCHROOM_PACKAGING`` (``appimage``|``deb``|``msi``|``exe``|``source``)
    forces the result — an operator escape hatch, and the seam the tests use.
    """
    system = platform.system()
    frozen = bool(getattr(sys, "frozen", False))
    exe = sys.executable or ""
    appimage = os.environ.get("APPIMAGE")
    override = (os.environ.get("SWITCHROOM_PACKAGING") or "").strip().lower()

    def _pkg(kind, path):
        return {
            "kind": kind, "path": path,
            "replaceable": install_method(kind) == "self_replace",
            "install_method": install_method(kind),
            "platform": system.lower(),
            "asset_suffix": _ASSET_SUFFIX.get(kind),
            "asset_match": (_appimage_match(path) if kind == "appimage"
                            else _ASSET_MATCH.get(kind)),
        }

    def _source():
        return {"kind": "source", "path": None, "replaceable": False,
                "install_method": "none", "platform": system.lower(),
                "asset_suffix": None, "asset_match": None}

    if override:
        if override in ("exe", "windows_exe"):
            return _pkg("windows_exe", exe or None)
        if override == "source":
            return _source()
        if override in ("appimage", "deb", "msi"):
            return _pkg(override,
                        (appimage if override == "appimage" else exe) or None)

    # 1. AppImage (raw OR Tauri): a self-contained single file — self-replace it.
    #    The runtime sets $APPIMAGE to the running .AppImage path (inherited by
    #    the Tauri sidecar, which is spawned from the mounted image).
    if system == "Linux" and appimage:
        return _pkg("appimage", appimage)

    # 2. Tauri bundle — the engine runs as the frozen ``switchroom-engine``
    #    sidecar, installed by dpkg (.deb) or MSI/NSIS. NEVER self-replace a
    #    package-manager-owned binary; hand the download to the system installer.
    if frozen and _tauri_sidecar():
        if system == "Windows" or os.name == "nt":
            return _pkg("msi", exe or None)
        if system == "Linux":
            return _pkg("deb", exe or None)
        # other Tauri targets (future macOS .dmg) — installer handoff too
        return _pkg("deb", exe or None)

    # 3. Raw single-file PyInstaller Windows .exe — self-replace (staged).
    if frozen and (system == "Windows" or os.name == "nt"):
        return _pkg("windows_exe", exe or None)

    # 4. Everything else (git clone, pip install): update out-of-band.
    return _source()


def select_asset(assets, packaging: dict):
    """Pick the release asset matching ``packaging`` from a GitHub ``assets`` list.

    Prefers the ordered ``asset_match`` matchers (``(include, exclude)`` name
    substrings, case-insensitive) so a dual-asset release (raw ``.exe`` vs NSIS
    ``*-setup.exe``; ``.msi`` vs ``*-setup.exe``) resolves unambiguously. Falls
    back to a bare ``asset_suffix`` match for callers that only set that. Returns
    the asset dict (``{name, browser_download_url, size, ...}``) or ``None``.
    """
    if not assets:
        return None
    named = [(a, str(a.get("name", ""))) for a in assets if isinstance(a, dict)]
    matchers = packaging.get("asset_match")
    if matchers:
        for inc, exc in matchers:
            inc_l = (inc or "").lower()
            exc_l = exc.lower() if exc else None
            for asset, name in named:
                low = name.lower()
                if inc_l and inc_l in low and (exc_l is None or exc_l not in low):
                    return asset
        return None
    suffix = packaging.get("asset_suffix")
    if not suffix:
        return None
    for asset, name in named:
        if name.endswith(suffix):
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
        "install_method": packaging.get("install_method"),
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
    method = install_method(packaging["kind"])
    plan = {
        "current": check.get("current"), "latest": check.get("latest"),
        "newer": check.get("newer"), "packaging": packaging["kind"],
        "replaceable": packaging["replaceable"], "install_method": method,
        "target_path": packaging["path"],
        "asset_url": check.get("asset_url"), "asset_name": check.get("asset_name"),
        "can_apply": False, "reason": None, "html_url": check.get("html_url"),
    }
    if not check.get("ok"):
        plan["reason"] = check.get("error") or "update check failed"
    elif not check.get("newer"):
        plan["reason"] = "already up to date"
    elif method == "none":
        plan["reason"] = (
            "running from source — update with 'git pull' or "
            "'pip install -U' (the self-updater only drives the packaged "
            "AppImage / .exe / .deb / .msi builds)")
    elif not check.get("asset_url"):
        plan["reason"] = "no matching release asset for this platform"
    elif method == "installer":
        plan["can_apply"] = True
        installer = "dpkg/apt" if packaging["kind"] == "deb" else "msiexec"
        plan["reason"] = (
            f"will download {check.get('asset_name')} and hand off to the "
            f"system installer ({installer}) — the running binary is "
            "package-manager-owned and is never overwritten in place")
    else:  # self_replace
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


# --------------------------------------------------------------------------- #
# installer hand-off (package-manager-owned builds: .deb / .msi / NSIS)
# --------------------------------------------------------------------------- #
def _user_download_dir() -> str:
    """A writable directory to stage an OS installer package in.

    NEVER the directory of the running binary — that is package-manager-owned
    (e.g. ``/usr/bin``) and usually unwritable. Prefers ``$SWITCHROOM_DOWNLOAD_DIR``,
    then ``~/Downloads``, then the system temp dir."""
    override = os.environ.get("SWITCHROOM_DOWNLOAD_DIR")
    if override:
        return override
    home = os.path.expanduser("~")
    if home and home != "~":
        downloads = os.path.join(home, "Downloads")
        if os.path.isdir(downloads):
            return downloads
    return tempfile.gettempdir()


def _launch_installer(path: str) -> bool:
    """Best-effort, non-blocking hand-off to the OS installer.

    Returns whether a launch was dispatched. Never raises and never blocks — a
    failed hand-off still leaves the downloaded file for the user to run."""
    try:
        system = platform.system()
        if system == "Windows" or os.name == "nt":
            if path.lower().endswith(".msi"):
                subprocess.Popen(
                    ["msiexec", "/i", path],
                    close_fds=True,
                    creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
            else:  # NSIS *-setup.exe
                os.startfile(path)  # type: ignore[attr-defined]  # Windows-only
            return True
        if system == "Darwin":
            subprocess.Popen(["open", path], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return True
        # Linux: xdg-open routes a .deb to the GUI installer (GNOME Software /
        # GDebi / Discover). Detached so closing the app does not kill it.
        subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except Exception:  # noqa: BLE001  — hand-off is best-effort
        return False


def _install_deb(path: str, size: int, *, launcher=None) -> dict:
    """Hand a downloaded ``.deb`` to the system installer. The running binary is
    dpkg-owned, so it is NEVER overwritten in place."""
    launched = (launcher or _launch_installer)(path)
    if launched:
        message = (f"Downloaded the update to {path} and opened the system "
                   "installer — follow its prompts (it will ask for your "
                   "password), then reopen Switchroom.")
    else:
        message = (f"Downloaded the update to {path}. Install it with your "
                   f"package manager (e.g. 'sudo apt install \"{path}\"') or "
                   "double-click it in Files, then reopen Switchroom.")
    return {"ok": True, "action": "downloaded", "packaging": "deb",
            "path": path, "size": size, "needs_restart": True,
            "launched": bool(launched), "message": message}


def _install_msi(path: str, size: int, *, launcher=None) -> dict:
    """Hand a downloaded Windows installer (``.msi`` / NSIS ``.exe``) to the OS.
    An MSI/NSIS install is installer-managed, so it is never swapped in place."""
    launched = (launcher or _launch_installer)(path)
    if launched:
        message = (f"Downloaded the update to {path} and launched the installer "
                   "— follow its prompts, then reopen Switchroom.")
    else:
        message = (f"Downloaded the update to {path}. Run it to install, then "
                   "reopen Switchroom.")
    return {"ok": True, "action": "downloaded", "packaging": "msi",
            "path": path, "size": size, "needs_restart": True,
            "launched": bool(launched), "message": message}


def apply_update(check: dict | None = None, *, confirm: bool = False,
                 current: str | None = None, timeout: float = 120.0,
                 _downloader=None, _launcher=None) -> dict:
    """Download the latest release and install it per this build's packaging.

    **Requires ``confirm=True``** — otherwise raises :class:`UpdateError`.

    * **self-replace** (AppImage / raw ``.exe``): the download goes to a sibling
      temp file and, only after a clean size-checked download, is swapped in
      (atomically on Linux, staged on Windows). Any failure leaves the running
      binary untouched.
    * **installer** (Tauri ``.deb`` / ``.msi`` / NSIS): the package is staged in
      a user-writable directory (``~/Downloads`` / temp — never the
      package-manager-owned binary dir) and handed to the system installer; the
      running binary is never overwritten in place.

    Every failure is returned as ``{"ok": False, ...}``.

    ``_downloader`` is injectable for tests (``fn(url, dest, timeout=...) -> int``);
    ``_launcher`` is the injectable installer hand-off (``fn(path) -> bool``).
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
    kind = packaging["kind"]
    method = install_method(kind)
    url = check["asset_url"]
    asset_name = (check.get("asset_name")
                  or os.path.basename(url.split("?", 1)[0])
                  or "switchroom-update")
    download = _downloader or _download

    # -- self-replace: AppImage / raw PyInstaller .exe ----------------------- #
    if method == "self_replace":
        target = packaging["path"]
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
            if kind == "appimage":
                return _install_unix(tmp, target, size)
            return _install_windows(tmp, target, size)
        except Exception as exc:  # noqa: BLE001
            _safe_unlink(tmp)
            return {"ok": False, "action": "install_failed", "message": str(exc)}

    # -- installer hand-off: Tauri .deb / .msi / NSIS ------------------------ #
    if method == "installer":
        dest_dir = _user_download_dir()
        try:
            os.makedirs(dest_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".switchroom-update-", dir=dest_dir)
            os.close(fd)
        except OSError as exc:
            return {"ok": False, "action": "none",
                    "message": f"cannot stage the installer in {dest_dir}: {exc}"}
        try:
            size = download(url, tmp, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            _safe_unlink(tmp)
            return {"ok": False, "action": "download_failed", "message": str(exc)}
        dest = os.path.join(dest_dir, asset_name)
        try:
            _safe_unlink(dest)
            os.replace(tmp, dest)
        except OSError as exc:
            _safe_unlink(tmp)
            return {"ok": False, "action": "install_failed", "message": str(exc)}
        try:
            if kind == "deb":
                return _install_deb(dest, size, launcher=_launcher)
            return _install_msi(dest, size, launcher=_launcher)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "action": "install_failed", "message": str(exc)}

    return {"ok": False, "action": "none",
            "message": "no installer for this packaging"}


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
