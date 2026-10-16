# PyInstaller spec — builds a self-contained Windows "Toshiba CIX Manager.exe".
#
#   python packaging/build_windows.py        (preferred — generates the icon first)
#   # or directly:
#   pyinstaller --noconfirm --clean packaging/toshiba_cix_manager.spec
#
# One-file, console build: the console window shows the URL as a fallback and
# lets the tech Ctrl-C to stop. The browser is opened automatically on launch.
# webui.html is bundled as data and found at runtime via sys._MEIPASS.

import os

# SPECPATH is injected by PyInstaller = the directory holding this spec.
ROOT = os.path.dirname(SPECPATH)                       # noqa: F821  repo root
ICON = os.path.join(SPECPATH, "icon.ico")

a = Analysis(
    [os.path.join(ROOT, "app.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "toshiba_cix", "webui.html"), "toshiba_cix"),
        # vendored eManager catalog + enum labels + menu map —
        # found at runtime via sys._MEIPASS
        (os.path.join(ROOT, "toshiba_cix", "data", "emanager_catalog.json"),
         os.path.join("toshiba_cix", "data")),
        (os.path.join(ROOT, "toshiba_cix", "data", "enum_labels.json"),
         os.path.join("toshiba_cix", "data")),
        (os.path.join(ROOT, "toshiba_cix", "data", "program_menus.json"),
         os.path.join("toshiba_cix", "data")),
        # generated UI schema served at /api/schema (found via sys._MEIPASS)
        (os.path.join(ROOT, "toshiba_cix", "data", "ui_schema.json"),
         os.path.join("toshiba_cix", "data")),
    ],
    hiddenimports=[
        "toshiba_cix", "toshiba_cix.launcher", "toshiba_cix.webapp",
        "toshiba_cix.discover", "toshiba_cix.write", "toshiba_cix.scan",
        "toshiba_cix.decode", "toshiba_cix.report", "toshiba_cix.snmp",
        "toshiba_cix.catalog", "toshiba_cix.backup", "toshiba_cix.enrich",
        "toshiba_cix.diff", "toshiba_cix.restore", "toshiba_cix.manage_cli",
        "toshiba_cix.update", "toshiba_cix.appdirs", "toshiba_cix.sites",
        "toshiba_cix.journal", "toshiba_cix.server", "toshiba_cix.server.app",
        "toshiba_cix.server.auth", "toshiba_cix.server.events",
        "toshiba_cix.server.http", "toshiba_cix.server.jobs",
        "toshiba_cix.server.router", "toshiba_cix.server.schema",
        "toshiba_cix.server.sessions",
        # certifi ships a CA bundle so the self-updater can verify TLS to
        # api.github.com even though this frozen CPython's default verify paths
        # point at the build machine. PyInstaller's bundled hook-certifi.py
        # collects certifi's cacert.pem as data when certifi is importable.
        "certifi",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest"],
    noarchive=False,
)

pyz = PYZ(a.pure)                                       # noqa: F821

exe = EXE(                                              # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Toshiba CIX Manager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon=ICON if os.path.exists(ICON) else None,
)
