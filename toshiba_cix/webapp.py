"""Local web app for the Toshiba CIX Manager (pure stdlib, no pip installs).

A tech runs ``python3 app.py`` (or the single-file build) on any laptop, opens
``http://localhost:<port>`` and reads/views the CIX over SNMP — working offline,
whether plugged straight into the PBX LAN (direct) or reaching it over an RSM
(remote). It is just SNMP to an IP either way; nothing here depends on the
internet, Conduit or ZeroTier.

Served endpoints (all JSON unless noted):
    GET  /                 the single-page UI (``webui.html``)
    GET  /api/health       {ok, version}
    GET  /api/discover     local-LAN auto-discovery of CIX processors
    POST /api/connect      {ip, community, port} -> test GET of the software id
    POST /api/read         {ip, community, port, scope} -> full structured doc
    POST /api/backup       {doc} -> a .zip (programming.json + report + oid walk)
    POST /api/save         {ip, station, changes} -> write PREVIEW (never sends)

The server binds to loopback by default so only the local browser can reach it.
All SNMP is read-only (GET/GETNEXT); ``/api/save`` goes through
:mod:`toshiba_cix.write`, which is stubbed and cannot emit a SET.
"""

from __future__ import annotations

import io
import json
import logging
import os
import socket
import sys
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from . import discover as DISC
# Non-aliased so the single-file build (which flattens the package into one
# module and strips intra-package imports) resolves these as globals.
from .backup import backup, render_backup_text
from .catalog import load_catalog
from .diff import diff_backups, render_diff_text
from .report import render as render_report
from .restore import restore
from .scan import CIXReader
from .snmp import SnmpError, SnmpV1
from .write import WRITES_ENABLED, CIXWriter, WriteError

log = logging.getLogger("toshiba_cix.webapp")

_HTML_CACHE: str | None = None


def load_html() -> str:
    """Return the UI HTML, wherever this is running from.

    Order: the base64-embedded copy (the ``toshiba_cix_manager.py`` standalone)
    → a PyInstaller bundle (``sys._MEIPASS``) → the sibling ``webui.html`` (from
    the package / a dev checkout). This lets the same server code back the
    single-file build, the double-click ``.exe`` and ``python3 app.py``.
    """
    global _HTML_CACHE
    if _HTML_CACHE is not None:
        return _HTML_CACHE
    embedded = globals().get("EMBEDDED_WEBUI_HTML")
    if embedded:
        _HTML_CACHE = embedded
        return _HTML_CACHE
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)   # set when frozen by PyInstaller
    if meipass:
        candidates.append(os.path.join(meipass, "toshiba_cix", "webui.html"))
        candidates.append(os.path.join(meipass, "webui.html"))
    candidates.append(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui.html"))
    for path in candidates:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                _HTML_CACHE = fh.read()
            return _HTML_CACHE
    raise FileNotFoundError("webui.html not found (looked in: "
                            + ", ".join(candidates) + ")")


def _reader(params: dict, *, keep_raw_walk: bool) -> CIXReader:
    ip = (params.get("ip") or "").strip()
    if not ip:
        raise ValueError("missing CIX IP address")
    community = (params.get("community") or "communityName").strip() or "communityName"
    port = int(params.get("port") or 161)
    timeout = float(params.get("timeout") or 3.0)
    retries = int(params.get("retries") or 1)
    scope = params.get("scope") or "core"
    strategy = "serial" if params.get("serial") else "bulk"
    width = int(params.get("width") or 10)
    client = SnmpV1(ip, community, port=port, timeout=timeout, retries=retries)
    return CIXReader(client, scope=scope, strategy=strategy, width=width,
                     keep_raw_walk=keep_raw_walk)


class CIXHandler(BaseHTTPRequestHandler):
    server_version = f"ToshibaCIXManager/{__version__}"

    # Quiet the default noisy logging; route through our logger instead.
    def log_message(self, fmt, *args):  # noqa: N802
        log.debug("%s - %s", self.address_string(), fmt % args)

    # -- helpers ----------------------------------------------------------
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body, content_type, status=200, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    # -- routing ----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            html = load_html().encode("utf-8")
            self._send_bytes(html, "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._send_json({"ok": True, "version": __version__,
                             "writes_enabled": WRITES_ENABLED})
            return
        if path == "/api/discover":
            self._handle_discover()
            return
        if path == "/api/catalog":
            self._handle_catalog()
            return
        self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        try:
            params = self._read_body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": f"bad request body: {exc}"},
                            status=400)
            return
        if path == "/api/connect":
            self._handle_connect(params)
        elif path == "/api/read":
            self._handle_read(params)
        elif path == "/api/backup":
            self._handle_backup(params)
        elif path == "/api/save":
            self._handle_save(params)
        elif path == "/api/catalog-backup":
            self._handle_catalog_backup(params)
        elif path == "/api/view":
            self._handle_view(params)
        elif path == "/api/diff":
            self._handle_diff(params)
        elif path == "/api/restore":
            self._handle_restore(params)
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    # -- handlers ---------------------------------------------------------
    def _handle_connect(self, params):
        try:
            reader = _reader(params, keep_raw_walk=False)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        client = reader.client
        try:
            vbs = client.get([DISC.SOFTWARE_ID_OID, DISC.CHASSIS_MAC_OID])
        except SnmpError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        from . import decode as D
        by_oid = {vb.oid: vb.value for vb in vbs}
        sw = by_oid.get(DISC.SOFTWARE_ID_OID)
        if sw is None or sw.is_missing or sw.kind != "octet" or not sw.raw:
            self._send_json({"ok": False,
                             "error": "no CIX software-id reply (wrong community, "
                                      "not a CIX, or UDP 161 blocked)"})
            return
        out = {"ok": True, "software_id": D.decode_value(sw)}
        mac = by_oid.get(DISC.CHASSIS_MAC_OID)
        if mac is not None and mac.kind == "octet" and mac.raw:
            out["chassis_mac"] = D.decode_value(mac, as_mac=True)
        self._send_json(out)

    def _handle_read(self, params):
        try:
            reader = _reader(params, keep_raw_walk=True)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        try:
            doc = reader.read()
        except SnmpError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("read failed")
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        if not doc.get("stations") and not doc["system"].get("software_id") \
                and doc["device"]["oids_read"] == 0:
            self._send_json({"ok": False,
                             "error": "no data returned — wrong community, not a "
                                      "CIX, or UDP 161 blocked"})
            return
        self._send_json({"ok": True, "doc": doc, "report": render_report(doc)})

    def _handle_backup(self, params):
        doc = params.get("doc")
        if not isinstance(doc, dict):
            self._send_json({"ok": False, "error": "missing doc"}, status=400)
            return
        try:
            body = build_backup_zip(doc)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        ip = (doc.get("device") or {}).get("ip") or "cix"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        fname = f"toshiba-cix-{str(ip).replace('/', '_')}-{ts}-backup.zip"
        self._send_bytes(body, "application/zip", filename=fname)

    def _handle_discover(self):
        try:
            result = DISC.discover_cix()
            result["ok"] = True
            self._send_json(result)
        except Exception as exc:  # noqa: BLE001
            log.exception("discover failed")
            self._send_json({"ok": False, "error": str(exc),
                             "candidates": []})

    def _handle_save(self, params):
        """Plan a station edit, and either PREVIEW it (default) or, with an
        explicit ``confirm: true``, send the live batched SET and GET-verify.

        The preview path never touches the network. The write path is gated by
        ``WRITES_ENABLED`` and ``confirm``; it always reads the values back and
        returns requested-vs-read-back so a write is never silent.
        """
        station = params.get("station") or {}
        changes = params.get("changes") or {}
        confirm = bool(params.get("confirm"))
        writer = CIXWriter()
        try:
            ops = writer.plan_station_update(station, changes)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return

        if not confirm:
            self._send_json({
                "ok": True,
                "mode": "preview",
                "writes_enabled": WRITES_ENABLED,
                "message": ("Preview only — nothing was sent. Use "
                            "“Confirm & write” to apply these SETs."),
                "planned_ops": [op.as_dict() for op in ops],
            })
            return

        # Live write path.
        try:
            reader = _reader(params, keep_raw_walk=False)   # builds the client
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        writer = CIXWriter(reader.client)
        try:
            result = writer.commit(ops, confirm=True, verify=True)
        except (WriteError, SnmpError) as exc:
            self._send_json({"ok": False, "mode": "write",
                             "error": str(exc),
                             "planned_ops": [op.as_dict() for op in ops]})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("write failed")
            self._send_json({"ok": False, "mode": "write",
                             "error": f"{type(exc).__name__}: {exc}"})
            return
        self._send_json({
            "ok": result["ok"],
            "mode": "write",
            "writes_enabled": WRITES_ENABLED,
            "message": ("Write sent and verified." if result["ok"]
                        else "Write sent but read-back did not match — check the "
                             "results below."),
            "result": result,
            "planned_ops": [op.as_dict() for op in ops],
        })


    # -- catalog-driven backup / view / diff / restore --------------------
    def _handle_catalog(self):
        """Report the vendored catalog's identity (version + counts)."""
        try:
            cat = load_catalog()
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        out = {"ok": True, "writes_enabled": WRITES_ENABLED}
        out.update(cat.summary())
        self._send_json(out)

    def _handle_catalog_backup(self, params):
        """Read a live CIX into a catalog backup (read-only). Returns the
        backup doc + a text rendering; the UI saves the JSON locally."""
        try:
            reader = _reader(params, keep_raw_walk=False)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        programs = params.get("programs") or None
        site = params.get("site")
        try:
            cat = load_catalog()
            doc = backup(reader.client, cat, site=site, programs=programs,
                            width=reader.width)
        except SnmpError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("catalog backup failed")
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        if doc["meta"].get("oids_read", 0) == 0:
            self._send_json({"ok": False,
                             "error": "no data returned — wrong community, not a "
                                      "CIX, or UDP 161 blocked"})
            return
        self._send_json({"ok": True, "backup": doc,
                         "report": render_backup_text(doc, catalog=cat)})

    def _handle_view(self, params):
        doc = params.get("backup")
        if not isinstance(doc, dict):
            self._send_json({"ok": False, "error": "missing backup"}, status=400)
            return
        try:
            cat = load_catalog()
            report = render_backup_text(doc, catalog=cat,
                                        program=params.get("program"),
                                        max_rows=params.get("max_rows"))
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        self._send_json({"ok": True, "report": report,
                         "meta": doc.get("meta", {}),
                         "programs": sorted(doc.get("programs", {}).keys())})

    def _handle_diff(self, params):
        a, b = params.get("a"), params.get("b")
        if not isinstance(a, dict) or not isinstance(b, dict):
            self._send_json({"ok": False, "error": "need two backups (a, b)"},
                            status=400)
            return
        try:
            cat = load_catalog()
            d = diff_backups(a, b, catalog=cat,
                             ignore_readonly=not params.get("all"))
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return
        self._send_json({"ok": True, "diff": d, "report": render_diff_text(d)})

    def _handle_restore(self, params):
        """Plan a restore and either PREVIEW it (default) or, with an explicit
        ``confirm: true``, send the batched catalog-driven SETs and GET-verify.

        Gated by WRITES_ENABLED + confirm (reusing CIXWriter). Read-only fields
        are never sent; applies to RAM (reboot persistence unproven)."""
        doc = params.get("backup")
        if not isinstance(doc, dict):
            self._send_json({"ok": False, "error": "missing backup"}, status=400)
            return
        confirm = bool(params.get("confirm"))
        programs = params.get("programs") or None
        from_diff = params.get("from_diff") or None
        try:
            cat = load_catalog()
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        client = None
        if confirm:
            try:
                reader = _reader(params, keep_raw_walk=False)
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            client = reader.client
        try:
            result = restore(client, doc, cat, confirm=confirm,
                                programs=programs, from_diff=from_diff)
        except (WriteError, SnmpError) as exc:
            self._send_json({"ok": False, "mode": "write", "error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            log.exception("restore failed")
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        self._send_json(result)


def build_backup_zip(doc: dict) -> bytes:
    """Pack a read into a .zip: programming.json + report.txt + raw OID walk."""
    buf = io.BytesIO()
    ip = (doc.get("device") or {}).get("ip") or "cix"
    read_at = (doc.get("device") or {}).get("read_at") or ""
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("programming.json", json.dumps(doc, indent=2, default=str))
        zf.writestr("report.txt", render_report(doc))
        walk = doc.get("raw_oid_walk")
        if walk:
            lines = [f"{e.get('oid')} = {e.get('value')}" for e in walk]
            zf.writestr("raw-oid-walk.txt", "\n".join(lines) + "\n")
        manifest = (
            "Toshiba Strata CIX backup\n"
            f"Device   : {ip}\n"
            f"Read at  : {read_at}\n"
            f"Software : {(doc.get('system') or {}).get('software_id', '?')}\n"
            f"Stations : {(doc.get('stats') or {}).get('stations', '?')}\n"
            f"OIDs     : {(doc.get('device') or {}).get('oids_read', '?')}\n"
            "\nFiles:\n"
            "  programming.json  structured programming (re-openable in this tool)\n"
            "  report.txt        human-readable report\n"
            + ("  raw-oid-walk.txt  every OID read, verbatim\n" if walk else "")
        )
        zf.writestr("MANIFEST.txt", manifest)
    return buf.getvalue()


def _pick_port(host: str, preferred: int) -> int:
    """Return ``preferred`` if free, else the next free port (up to +20)."""
    for port in range(preferred, preferred + 21):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    return preferred


def serve(host: str = "127.0.0.1", port: int = 8765, *,
          open_browser: bool = True) -> None:
    port = _pick_port(host, port)
    httpd = ThreadingHTTPServer((host, port), CIXHandler)
    url = f"http://{host}:{port}"
    print(f"Toshiba CIX Manager {__version__}")
    print(f"  Open: {url}")
    print("  Read-only SNMP. Writes are stubbed (not enabled). Ctrl-C to stop.")
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.server_close()


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="toshiba-cix-manager",
        description="Local web app to read/view a Toshiba Strata CIX over SNMP "
                    "(read-only). Serves a UI on localhost.",
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1 — local only)")
    p.add_argument("--port", type=int, default=8765,
                   help="port (default 8765; next free port if busy)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not auto-open the browser")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    serve(args.host, args.port, open_browser=not args.no_browser)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
