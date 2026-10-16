"""Cross-platform launcher for the Toshiba CIX Manager.

One launch path for every packaging: ``python3 app.py``, the Linux
``toshiba-cix-manager`` script / ``.desktop`` entry, the double-click Windows
``.exe`` and the AppImage all end up here. It:

* picks a **free port** (the preferred one, or the next free),
* starts the local web server,
* **opens the default browser** to ``http://127.0.0.1:<port>``,
* **prints the URL** to the console as a fallback, and
* shuts down cleanly on Ctrl-C / window close.

Everything is stdlib. The server itself lives in :mod:`toshiba_cix.webapp`;
this module only wraps it with the launch ergonomics a non-technical tech needs.
"""

from __future__ import annotations

import argparse
import logging
import threading
from http.server import ThreadingHTTPServer

from . import __version__
from .webapp import CIXHandler, serve


def start_server(host: str = "127.0.0.1", port: int = 0):
    """Start the server in a background thread (used by tests / embedders).

    ``port=0`` binds an OS-chosen free port. Returns ``(httpd, url, thread)``;
    call ``httpd.shutdown()`` to stop it.
    """
    httpd = ThreadingHTTPServer((host, port), CIXHandler)
    url = f"http://{host}:{httpd.server_address[1]}"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, url, thread


def launch(host: str = "127.0.0.1", port: int = 8765,
           open_browser: bool = True, portable: bool = False) -> None:
    """Foreground launch — the double-click / desktop entry point.

    Delegates to :func:`toshiba_cix.webapp.serve`, which finds a free port,
    opens the browser, prints the URL and blocks until Ctrl-C.
    """
    serve(host, port, open_browser=open_browser, portable=portable)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="toshiba-cix-manager",
        description="Toshiba CIX Manager — read/manage a Strata CIX over SNMP "
                    "from a local web app. Opens your browser automatically.",
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1 — local only)")
    p.add_argument("--port", type=int, default=8765,
                   help="preferred port (default 8765; next free if busy)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not auto-open the browser")
    p.add_argument("--portable", action="store_true",
                   help="keep the store beside the executable (USB stick)")
    p.add_argument("--version", action="version",
                   version=f"Toshiba CIX Manager {__version__}")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    launch(args.host, args.port, open_browser=not args.no_browser,
           portable=args.portable)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
