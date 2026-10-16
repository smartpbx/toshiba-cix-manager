#!/usr/bin/env python3
"""Build the Tauri desktop **sidecar** binary and stage it for ``tauri build``.

The Switchroom desktop app (``desktop/``) bundles the Python engine as a Tauri
*sidecar* (an ``externalBin``). Tauri resolves a sidecar named
``binaries/switchroom-engine`` to the file
``binaries/switchroom-engine-<rust-target-triple>`` (plus ``.exe`` on Windows),
so this script:

1. runs PyInstaller on ``switchroom_sidecar.spec`` → a one-file binary, then
2. copies it to ``desktop/src-tauri/binaries/switchroom-engine-<triple>``.

The target triple is ``rustc``'s host triple by default; pass ``--target`` to
cross-name it (e.g. in CI). PyInstaller is build-time only — install it in a
throwaway venv first::

    python -m venv .buildvenv && . .buildvenv/bin/activate
    pip install pyinstaller
    python packaging/build_sidecar.py

Then, from ``desktop/``::

    npm install && npm run tauri build

PyInstaller cannot cross-compile, so the sidecar must be built on each target
OS (a Linux sidecar on Linux, a Windows sidecar on Windows) — see
``desktop/README.md``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = os.path.join(HERE, "switchroom_sidecar.spec")
BIN_DIR = os.path.join(ROOT, "desktop", "src-tauri", "binaries")


def _rustc_host_triple() -> str:
    out = subprocess.check_output(["rustc", "-Vv"], text=True)
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("could not read host triple from `rustc -Vv`")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default=None,
                    help="Rust target triple to name the sidecar for "
                         "(default: rustc host triple)")
    args = ap.parse_args()

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed in this environment.\n"
              "  pip install pyinstaller\n"
              "then re-run. (It is a build-time dep only; the engine stays "
              "pure stdlib.)", file=sys.stderr)
        return 2

    triple = args.target or _rustc_host_triple()
    is_windows = "windows" in triple or sys.platform == "win32"
    src_name = "switchroom-engine.exe" if is_windows else "switchroom-engine"
    dst_name = (f"switchroom-engine-{triple}.exe" if is_windows
                else f"switchroom-engine-{triple}")

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
           "--distpath", os.path.join(ROOT, "dist"),
           "--workpath", os.path.join(ROOT, "build"),
           SPEC]
    print("running:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)

    src = os.path.join(ROOT, "dist", src_name)
    if not os.path.exists(src):
        print(f"expected PyInstaller output not found: {src}", file=sys.stderr)
        return 1

    os.makedirs(BIN_DIR, exist_ok=True)
    dst = os.path.join(BIN_DIR, dst_name)
    shutil.copy2(src, dst)
    if not is_windows:
        os.chmod(dst, 0o755)
    print(f"\nStaged sidecar: {dst}")
    print("Now build the desktop app:  cd desktop && npm install && "
          "npm run tauri build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
