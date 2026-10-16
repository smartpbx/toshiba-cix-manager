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


def _embedded_catalog() -> str:
    with open(os.path.join(PKG, "data", "emanager_catalog.json"), "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")
    return (f'EMBEDDED_CATALOG_JSON = base64.b64decode("{b64}").decode("utf-8")'
            "  # bundled eManager catalog")


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
        # Embed the vendored eManager catalog so the single-file build is
        # self-contained (catalog.load_catalog_text() reads this global first).
        aliases["catalog.py"] = [_embedded_catalog()]
        aliases["webapp.py"] = [_embedded_html()]

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
         "backup.py", "diff.py", "restore.py", "discover.py",
         "report.py", "cli.py", "update.py", "webapp.py"],
        "toshiba_cix_manager.py",
        title="Toshiba CIX Manager — standalone web app (generated).",
        with_web=True,
        tail=web_tail,
    )


if __name__ == "__main__":
    main()
