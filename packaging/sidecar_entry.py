#!/usr/bin/env python3
"""PyInstaller entry point for the Tauri desktop **sidecar**.

The Switchroom desktop app (``desktop/``) is a native OS-WebView window
(Tauri v2) with no bundled Chromium. The Python engine still does all the work;
it just runs as a *sidecar* process that Tauri spawns, supervises and kills:

* serve the same loopback HTTP API as ``--serve`` (``/api/health``,
  ``/api/catalog`` … and the committed single-file UI at ``/``),
* on an **OS-chosen** free port (``127.0.0.1:0`` — no fixed-port collision),
* with the loopback token Tauri mints and passes in ``$SWITCHROOM_TOKEN``,
* **without** opening any system browser (Tauri owns the window),
* **without** auto-exit (Tauri owns the lifecycle),
* printing one ``@@SWITCHROOM_ENDPOINT@@ {json}`` line so the Rust side learns
  the final ``url``/``token``/``port`` and points the WebView at it.

This file is the PyInstaller entry (``packaging/switchroom_sidecar.spec``); the
produced binary is bundled by Tauri as an ``externalBin``. PyInstaller is a
**build-time-only** dependency — the engine itself stays pure stdlib, so the
same package still runs on a bare Pi via the amalgam.
"""

from __future__ import annotations

import os
import sys
import threading

# Running from a source checkout (dev): make ``toshiba_cix`` importable. In a
# frozen PyInstaller bundle this is a harmless no-op — the package is embedded.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _die_with_parent() -> None:
    """Exit if our parent (Tauri) goes away.

    Tauri pipes our stdin. While the desktop app lives, the write end stays
    open and this read blocks forever on a daemon thread. If Tauri is killed
    abruptly (so its explicit ``child.kill()`` never runs), the pipe closes,
    the read returns EOF, and we shut ourselves down — no orphaned engine
    left holding a loopback port. Belt-and-suspenders to Tauri's own
    kill-on-exit; costs nothing when the parent is healthy.
    """
    try:
        sys.stdin.buffer.read()
    except Exception:  # noqa: BLE001 — any stdin failure means "shut down"
        pass
    os._exit(0)


def main() -> int:
    from toshiba_cix.webapp import serve

    threading.Thread(target=_die_with_parent, daemon=True).start()
    # port=0 -> an OS-chosen ephemeral port (DESIGN_PLAN §2.2: never a fixed
    # one, so a second instance can't collide). The real port is reported back
    # on the @@SWITCHROOM_ENDPOINT@@ line.
    serve(port=0, open_browser=False, autoexit=False, emit_endpoint=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
