"""Per-OS store root for Switchroom — one name, ``<store root>``, everywhere.

Three design docs named three different store paths; this module is the single
place that resolves them (DESIGN_PLAN 2.1, decision #8). It is pure stdlib — no
``platformdirs`` — and fully I/O-injected: ``store_root`` takes ``env`` /
``platform`` / ``argv0`` so a test pins a temp directory without touching the
real user profile.

| OS | Default ``<store root>`` |
|----|--------------------------|
| Windows | ``%APPDATA%\\Switchroom`` |
| macOS   | ``~/Library/Application Support/Switchroom`` |
| Linux   | ``$XDG_DATA_HOME/switchroom`` or ``~/.local/share/switchroom`` |

``--portable`` (``portable=True``) puts the store **beside the executable** so
the whole tool runs from a USB stick. Under the root live ``sites.json``,
``pending-<site>.json``, ``journal.sqlite`` + ``changes.log``, ``settings.json``,
``backups/<site>/...`` and ``logs/app.log`` (architecture.md 4.3).
"""

from __future__ import annotations

import os
import sys

APP_NAME = "Switchroom"            # product name (DESIGN_PLAN decision #7)
APP_DIR_POSIX = "switchroom"       # lowercase for the XDG path


def _home_dir(env: dict) -> str:
    return env.get("HOME") or env.get("USERPROFILE") or os.path.expanduser("~")


def default_root(*, env=None, platform=None) -> str:
    """The per-OS default store root (not created). Pure; inputs injectable."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    if platform.startswith("win"):
        base = env.get("APPDATA") or os.path.join(_home_dir(env), "AppData", "Roaming")
        return os.path.join(base, APP_NAME)
    if platform == "darwin":
        return os.path.join(_home_dir(env), "Library", "Application Support", APP_NAME)
    base = env.get("XDG_DATA_HOME") or os.path.join(_home_dir(env), ".local", "share")
    return os.path.join(base, APP_DIR_POSIX)


def portable_root(*, argv0=None) -> str:
    """The store beside the running executable / script (``--portable``)."""
    exe = argv0
    if exe is None:
        exe = sys.executable if getattr(sys, "frozen", False) else (sys.argv[0] or ".")
    base = os.path.dirname(os.path.abspath(exe))
    return os.path.join(base, APP_NAME)


def store_root(*, portable=False, override=None, env=None, platform=None,
               argv0=None) -> str:
    """Resolve the store root: explicit override > portable > per-OS default."""
    if override:
        return os.path.abspath(os.path.expanduser(override))
    if portable:
        return portable_root(argv0=argv0)
    return default_root(env=env, platform=platform)


class AppDirs:
    """Resolved store root with the standard file/dir layout and ``ensure()``.

    Paths are computed lazily and nothing is written until :meth:`ensure`
    (or a path-returning helper with ``create=True``) is called, so
    constructing an :class:`AppDirs` for a test is side-effect free.
    """

    def __init__(self, root: str):
        self.root = os.path.abspath(os.path.expanduser(root))

    # -- top-level files ---------------------------------------------------
    @property
    def sites_file(self) -> str:
        return os.path.join(self.root, "sites.json")

    @property
    def journal_db(self) -> str:
        return os.path.join(self.root, "journal.sqlite")

    @property
    def changes_log(self) -> str:
        return os.path.join(self.root, "changes.log")

    @property
    def settings_file(self) -> str:
        return os.path.join(self.root, "settings.json")

    def pending_file(self, site_id: str) -> str:
        return os.path.join(self.root, f"pending-{_safe_component(site_id)}.json")

    # -- sub-directories ---------------------------------------------------
    @property
    def backups_dir(self) -> str:
        return os.path.join(self.root, "backups")

    def site_backups_dir(self, site_id: str) -> str:
        return os.path.join(self.backups_dir, _safe_component(site_id))

    @property
    def logs_dir(self) -> str:
        return os.path.join(self.root, "logs")

    @property
    def log_file(self) -> str:
        return os.path.join(self.logs_dir, "app.log")

    # -- creation ----------------------------------------------------------
    def ensure(self) -> "AppDirs":
        """Create the root, ``backups/`` and ``logs/`` (mode 0700). Idempotent."""
        for d in (self.root, self.backups_dir, self.logs_dir):
            os.makedirs(d, exist_ok=True)
            _chmod_private_dir(d)
        return self

    def ensure_site_backups(self, site_id: str) -> str:
        d = self.site_backups_dir(site_id)
        os.makedirs(d, exist_ok=True)
        return d

    def __repr__(self) -> str:  # pragma: no cover
        return f"AppDirs({self.root!r})"


def from_args(*, portable=False, override=None, env=None, platform=None,
              argv0=None) -> AppDirs:
    """Convenience: resolve the root and wrap it in :class:`AppDirs`."""
    return AppDirs(store_root(portable=portable, override=override, env=env,
                              platform=platform, argv0=argv0))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _safe_component(name: str) -> str:
    """A filename-safe slug for a site id used in a path component."""
    keep = "-_."
    s = "".join(c if (c.isalnum() or c in keep) else "-" for c in str(name))
    return s.strip("-") or "site"


def _chmod_private_dir(path: str) -> None:
    """Best-effort 0700 on POSIX; a no-op where chmod is meaningless (Windows)."""
    try:
        if not sys.platform.startswith("win"):
            os.chmod(path, 0o700)
    except OSError:  # pragma: no cover
        pass


__all__ = [
    "APP_NAME", "APP_DIR_POSIX", "AppDirs",
    "default_root", "portable_root", "store_root", "from_args",
]
