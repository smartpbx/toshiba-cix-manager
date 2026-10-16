"""Smoke test: the launcher starts the server and serves /api/health.

Binds an ephemeral port (0), so it never collides with a running instance.
Fully offline.

Run:  python3 tests/test_launcher.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import launcher  # noqa: E402


def test_start_server_serves_health():
    httpd, url, thread = launcher.start_server(host="127.0.0.1", port=0)
    try:
        assert url.startswith("http://127.0.0.1:")
        with urllib.request.urlopen(url + "/api/health", timeout=10) as r:
            body = json.loads(r.read().decode())
        assert r.status == 200
        assert body["ok"] is True
        assert body["version"]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {exc!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
