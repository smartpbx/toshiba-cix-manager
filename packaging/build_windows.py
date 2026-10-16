#!/usr/bin/env python3
"""Build the self-contained Windows ``Toshiba CIX Manager.exe`` with PyInstaller.

PyInstaller is a **build-time-only** dependency — the produced .exe bundles its
own Python, so the target machine needs nothing installed. Install it in a build
venv first::

    python -m venv .buildvenv
    .buildvenv\\Scripts\\activate        (Windows)
    pip install pyinstaller
    python packaging/build_windows.py

The output lands in ``dist/Toshiba CIX Manager.exe`` (git-ignored). This is what
the GitHub Actions release workflow runs on a Windows runner.
"""

from __future__ import annotations

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = os.path.join(HERE, "toshiba_cix_manager.spec")


def main() -> int:
    # Generate the .ico (pure stdlib — no Pillow needed).
    subprocess.check_call([sys.executable, os.path.join(HERE, "make_icon.py")])

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed in this environment.\n"
              "  pip install pyinstaller\n"
              "then re-run. (It is a build-time dep only; the .exe is "
              "self-contained.)", file=sys.stderr)
        return 2

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
           "--distpath", os.path.join(ROOT, "dist"),
           "--workpath", os.path.join(ROOT, "build"),
           SPEC]
    print("running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)
    out = os.path.join(ROOT, "dist", "Toshiba CIX Manager.exe")
    print(f"\nBuilt: {out}" if os.path.exists(out)
          else "\nBuild finished (check dist/).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
