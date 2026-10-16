#!/usr/bin/env python3
"""Amalgamate the toshiba_cix package into standalone, stdlib-only files.

Produces two single-file artifacts so either can be dropped on a bare machine
(scp, base64-over-ssh, a USB stick) and run with nothing but ``python3``:

* ``toshiba_cix_standalone.py`` — the **reader CLI** (snmp/decode/scan/report/
  cli). This is the lean file for a Raspberry Pi RSM / the Conduit worker:
      python3 toshiba_cix_standalone.py <ip> --scope core

* ``toshiba_cix_manager.py`` — the **full web app** (adds write/discover/webapp
  + the embedded UI). This is the file a tech runs on a laptop:
      python3 toshiba_cix_manager.py                 # serve the web UI
      python3 toshiba_cix_manager.py read <ip> ...   # same CLI reader, bundled

The package remains the source of truth; both files are generated. Edit the
package, then re-run this script.
"""

from __future__ import annotations

import base64
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "toshiba_cix")

# Lines to drop: intra-package imports and per-module __future__ imports.
_INTRA = re.compile(
    r"^\s*(from\s+\.[\w.]*\s+import\b|from\s+\.\s+import\b|import\s+\.|"
    r"from\s+__future__\s+import\b).*$"
)


def _version() -> str:
    with open(os.path.join(PKG, "__init__.py"), encoding="utf-8") as fh:
        m = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read())
    return m.group(1) if m else "0.0.0"


def _strip(src: str) -> str:
    out: list[str] = []
    skip_next_indented = False
    for line in src.splitlines():
        if skip_next_indented:
            # Drop the body line of a stripped `if __name__` guard.
            if line.strip() == "" or line[:1] in (" ", "\t"):
                if line.strip():
                    skip_next_indented = False
                continue
            skip_next_indented = False
        if _INTRA.match(line):
            continue
        if line.strip().startswith('if __name__ == "__main__"'):
            skip_next_indented = True
            continue
        out.append(line)
    return "\n".join(out).rstrip()


def _embedded_html() -> str:
    with open(os.path.join(PKG, "webui.html"), "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")
    return (f'EMBEDDED_WEBUI_HTML = base64.b64decode("{b64}").decode("utf-8")'
            "  # bundled UI")


def _embedded_data(filename: str, global_name: str, note: str) -> str:
    with open(os.path.join(PKG, "data", filename), "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")
    return (f'{global_name} = base64.b64decode("{b64}").decode("utf-8")'
            f"  # {note}")


def _embedded_catalog() -> str:
    return _embedded_data("emanager_catalog.json", "EMBEDDED_CATALOG_JSON",
                          "bundled eManager catalog")


def _embedded_volatile_fields() -> str:
    return _embedded_data("volatile_fields.json", "EMBEDDED_VOLATILE_FIELDS_JSON",
                          "curated volatile-field list (diff hiding)")


def _embedded_references() -> str:
    return _embedded_data("references.json", "EMBEDDED_REFERENCES_JSON",
                          "field -> referenced entity kind (where-used)")


def _embedded_lint_rules() -> str:
    return _embedded_data("lint_rules.json", "EMBEDDED_LINT_RULES_JSON",
                          "config-linter rules (Problems panel)")


def _embedded_enum_labels() -> str:
    return _embedded_data("enum_labels.json", "EMBEDDED_ENUM_LABELS_JSON",
                          "bundled enum value labels")


def _embedded_program_menus() -> str:
    return _embedded_data("program_menus.json", "EMBEDDED_PROGRAM_MENUS_JSON",
                          "bundled eManager menu-area map")


def _embedded_ui_schema() -> str:
    return _embedded_data("ui_schema.json", "EMBEDDED_UI_SCHEMA_JSON",
                          "bundled generated UI schema")


# Flatten-namespace aliases for the voicemail modules: each ``vm_X.py`` is
# referenced as ``vm_X.func`` by its siblings, so after the amalgam strips the
# intra-package imports we bind ``vm_X`` back to the single flattened module.
def _vm_aliases():
    names = ["vm_data", "vm_serial", "vm_records", "vm_link", "vm_sysparams",
             "vm_pbxdb", "vm_catalog", "vm_reports", "vm_backup", "vm_session"]
    return {f"{n}.py": [f"{n} = sys.modules[__name__]  # flatten alias"]
            for n in names}


def build(order, out_name, *, title, with_web, tail):
    """Amalgamate ``order`` (module filenames) into ``out_name``."""
    version = _version()
    # Aliases injected after a named module so flattened references resolve.
    aliases = {
        "decode.py": ["D = sys.modules[__name__]  # 'decode as D' alias"],
        "report.py": ["render_report = render  # 'render as render_report' alias"],
    }
    if with_web:
        aliases["discover.py"] = ["DISC = sys.modules[__name__]  # 'discover as DISC' alias"]
        # Preserve the reader CLI main() before webapp.py redefines `main`.
        aliases["cli.py"] = ["reader_cli_main = main  # reader CLI entry (webapp redefines main)"]
        # Embed the vendored eManager catalog + enum labels + menu map so the
        # single-file build is self-contained (catalog.py reads these globals
        # first, before any bundled-file lookup).
        aliases["catalog.py"] = [_embedded_catalog(), _embedded_enum_labels(),
                                 _embedded_program_menus(),
                                 _embedded_volatile_fields(),
                                 _embedded_references(),
                                 _embedded_lint_rules()]
        # The generated UI schema rides with the schema module (same embed →
        # _MEIPASS → packaged-data resolution as the catalog).
        aliases["server/schema.py"] = [_embedded_ui_schema()]
        aliases["webapp.py"] = [_embedded_html()]
        # Voicemail modules: flatten aliases + embed their vendored data so the
        # single-file build reads the catalog/help/PBX-defaults offline.
        aliases.update(_vm_aliases())
        aliases["vm_data.py"] = aliases["vm_data.py"] + [
            _embedded_data("stratagy_vm_catalog.json",
                           "EMBEDDED_VM_CATALOG_JSON", "bundled VM field catalog"),
            _embedded_data("stratagy_sysparams_help.json",
                           "EMBEDDED_VM_SYSPARAMS_HELP_JSON",
                           "bundled Stratagy sysparam help"),
            _embedded_data("stratagy_pbx_defaults.json",
                           "EMBEDDED_VM_PBX_DEFAULTS_JSON",
                           "bundled Stratagy PBX dial-code/integration defaults"),
        ]

    parts = [
        "#!/usr/bin/env python3",
        f'"""{title}',
        "",
        "Generated from the toshiba_cix package by build_standalone.py.",
        "Pure stdlib; runs unchanged on a bare Python 3 (Pi / laptop).",
        "Edit the package, not this file.",
        '"""',
        "from __future__ import annotations",
        "import argparse, json, logging, socket, sys",
        "from dataclasses import dataclass, field",
        "from datetime import datetime, timezone",
        "from typing import Iterable",
        f'__version__ = "{version}"',
    ]
    if with_web:
        parts.append("import base64")
    parts.append("")
    for name in order:
        with open(os.path.join(PKG, name), encoding="utf-8") as fh:
            parts.append(f"# ===== {name} " + "=" * (60 - len(name)))
            parts.append(_strip(fh.read()))
            for alias in aliases.get(name, []):
                parts.append(alias)
            parts.append("")
    parts.append(tail)
    out = os.path.join(HERE, out_name)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts) + "\n")
    print(f"wrote {out}")


def main() -> None:
    # Reader CLI (lean — for the Pi / Conduit worker).
    build(
        ["snmp.py", "decode.py", "scan.py", "report.py", "cli.py"],
        "toshiba_cix_standalone.py",
        title="Toshiba Strata CIX SNMP reader — standalone (generated).",
        with_web=False,
        tail='if __name__ == "__main__":\n    raise SystemExit(main())',
    )
    # Full web app (for a tech laptop); also carries the reader as `read`.
    web_tail = (
        'if __name__ == "__main__":\n'
        "    _argv = sys.argv[1:]\n"
        '    if _argv and _argv[0] == "read":\n'
        "        raise SystemExit(reader_cli_main(_argv[1:]))\n"
        '    if _argv and _argv[0] in ("serve", "web"):\n'
        "        _argv = _argv[1:]\n"
        "    raise SystemExit(main(_argv))  # webapp.main — serves the UI"
    )
    build(
        ["snmp.py", "decode.py", "scan.py", "catalog.py", "write.py",
         "backup.py", "enrich.py", "diff.py", "diff_view.py", "restore.py",
         "discover.py", "report.py", "cli.py", "update.py",
         # generic single-program read + snapshot engine (depend on backup /
         # enrich / catalog above), the snapshot store and the value index.
         "programs.py", "snapshot.py", "store.py", "index.py",
         # P2 write path (pure): field/row validation, the three-way review,
         # bulk-edit planners, and the staged changeset. Listed after programs/
         # write/snmp because they reference those as flattened globals.
         "validate.py", "review.py", "bulk.py", "changeset.py",
         # P4 polish (pure): hover/row history, templates, the config linter and
         # the wizard planners (depend on programs / write / index above).
         "history.py", "template.py", "lint.py", "wizards.py",
         # voicemail leg (DESIGN_PLAN §8): byte pipe -> framing/link -> decoders
         # -> sysparams/pbxdb/catalog -> reports/backup -> the exclusive session.
         # Listed before webapp.py, which registers their routes.
         "vm_data.py", "vm_serial.py", "vm_records.py", "vm_link.py",
         "vm_sysparams.py", "vm_pbxdb.py", "vm_catalog.py", "vm_reports.py",
         "vm_backup.py", "vm_session.py",
         # disk-state layer, then the server package (dependency order: a
         # module is listed after everything it references, because the
         # amalgam flattens them into one namespace and strips the imports).
         "appdirs.py", "sites.py", "journal.py",
         "server/events.py", "server/auth.py", "server/router.py",
         "server/jobs.py", "server/sessions.py", "server/schema.py",
         "server/http.py", "server/app.py", "webapp.py"],
        "toshiba_cix_manager.py",
        title="Toshiba CIX Manager — standalone web app (generated).",
        with_web=True,
        tail=web_tail,
    )


if __name__ == "__main__":
    main()
