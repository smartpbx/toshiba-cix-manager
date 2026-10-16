# PyInstaller spec — builds the Tauri desktop **sidecar** binary.
#
#   python packaging/build_sidecar.py        (preferred — names it for the
#                                              Rust target triple Tauri expects)
#   # or directly:
#   pyinstaller --noconfirm --clean packaging/switchroom_sidecar.spec
#
# One-file, windowed (console=False) build: Tauri spawns it with pipes, reads
# its stdout for the @@SWITCHROOM_ENDPOINT@@ line, and kills it on exit — so no
# console window should flash on Windows. The same data (webui.html, catalog,
# enum labels, menu map, UI schema) is bundled and found at runtime via
# sys._MEIPASS, exactly like the standalone .exe build.
#
# The entry is packaging/sidecar_entry.py, which runs the engine headless with
# no browser and no auto-exit (the desktop window owns the lifecycle).

import os

ROOT = os.path.dirname(SPECPATH)                       # noqa: F821  repo root
ICON = os.path.join(SPECPATH, "icon.ico")

a = Analysis(
    [os.path.join(SPECPATH, "sidecar_entry.py")],
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
    name="switchroom-engine",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=ICON if os.path.exists(ICON) else None,
)
