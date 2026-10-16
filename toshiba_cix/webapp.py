"""Legacy JSON routes + launch for the Toshiba CIX Manager / Switchroom.

The HTTP *plumbing* now lives in :mod:`toshiba_cix.server` (router, loopback
token + Origin/Host guard, OS-chosen port, sessions, jobs, SSE ``/api/events``,
static UI). This module keeps the **route handlers** that read/view/diff/
restore a CIX over SNMP and wires them, plus the P0 core routes, onto a
:class:`~toshiba_cix.server.app.ServerContext`.

They stay here (as module-level ``route_*`` functions, not methods) for two
reasons: their behaviour must not regress, and the offline tests drive them by
monkeypatching module globals (``SnmpV1``, ``DISC``, ``check_for_update`` …) —
which only works because every handler resolves those names from *this*
module's namespace at call time.

Served endpoints are unchanged:
    GET  /               the single-page UI (``webui.html``)
    GET  /api/health     {ok, version, writes_enabled, schema}
    GET  /api/discover · /api/catalog · /api/update
    POST /api/connect · /api/read · /api/backup · /api/save
    POST /api/catalog-backup · /api/view · /api/diff · /api/restore · /api/update
plus the P0 additions: GET /api/schema, /api/sites, /api/jobs, /api/journal,
the session/mode trio and SSE /api/events (see :mod:`toshiba_cix.server`).

All SNMP reads are read-only (GET/GETNEXT); writes go through
:mod:`toshiba_cix.write` with explicit confirmation and GET-verify.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
import zipfile
from datetime import datetime, timezone

from . import __version__
from . import discover as DISC
from .appdirs import from_args
# Non-aliased so the single-file build (which flattens the package into one
# module and strips intra-package imports) resolves these as globals, and so a
# test can monkeypatch them on this module.
from .backup import backup, render_backup_text
from .catalog import load_catalog
from .diff import diff_backups, render_diff_text
from .enrich import program_views_from_backup
from .programs import empty_program_view, get_row, list_rows
from .report import render as render_report
from .restore import restore
from .scan import CIXReader
from .server.app import ServerContext, register_core_routes, run_server
from .server.auth import generate_token
from .server.http import build_handler
from .server.schema import schema_summary
from .sites import slugify_id
from .snapshot import read_snapshot
from .snmp import SnmpError, SnmpV1
from .update import apply_update, check_for_update, finalize_pending_update, plan_update
from .write import WRITES_ENABLED, CIXWriter, WriteError

log = logging.getLogger("toshiba_cix.webapp")

_HTML_CACHE: str | None = None


def load_html() -> str:
    """Return the UI HTML, wherever this is running from.

    Order: the base64-embedded copy (the ``toshiba_cix_manager.py`` standalone)
    → a PyInstaller bundle (``sys._MEIPASS``) → the sibling ``webui.html`` (from
    the package / a dev checkout).
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


# --------------------------------------------------------------------------
# static UI
# --------------------------------------------------------------------------
def route_index(ctx, req):
    html = load_html().encode("utf-8")
    extra = {}
    cookie = ctx.auth.cookie_header()
    if cookie:
        extra["Set-Cookie"] = cookie
    req.send_bytes(html, "text/html; charset=utf-8", extra_headers=extra)


# --------------------------------------------------------------------------
# simple GETs
# --------------------------------------------------------------------------
def route_health(ctx, req):
    req.send_json({"ok": True, "version": __version__,
                   "writes_enabled": WRITES_ENABLED,
                   "schema": schema_summary()})


def route_discover(ctx, req):
    try:
        result = DISC.discover_cix()
        result["ok"] = True
        req.send_json(result)
    except Exception as exc:  # noqa: BLE001
        log.exception("discover failed")
        req.send_json({"ok": False, "error": str(exc), "candidates": []})


def route_catalog(ctx, req):
    try:
        cat = load_catalog()
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": str(exc)}, 500)
        return
    out = {"ok": True, "writes_enabled": WRITES_ENABLED}
    out.update(cat.summary())
    req.send_json(out)


def route_update_check(ctx, req):
    try:
        req.send_json(check_for_update())
    except Exception as exc:  # noqa: BLE001  — check must never 500
        req.send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


# --------------------------------------------------------------------------
# connect / read / backup
# --------------------------------------------------------------------------
def route_connect(ctx, req):
    try:
        reader = _reader(req.body(), keep_raw_walk=False)
    except ValueError as exc:
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return
    client = reader.client
    try:
        vbs = client.get([DISC.SOFTWARE_ID_OID, DISC.CHASSIS_MAC_OID])
    except SnmpError as exc:
        req.send_json({"ok": False, "error": str(exc)})
        return
    from . import decode as D
    by_oid = {vb.oid: vb.value for vb in vbs}
    sw = by_oid.get(DISC.SOFTWARE_ID_OID)
    if sw is None or sw.is_missing or sw.kind != "octet" or not sw.raw:
        req.send_json({"ok": False,
                       "error": "no CIX software-id reply (wrong community, "
                                "not a CIX, or UDP 161 blocked)"})
        return
    out = {"ok": True, "software_id": D.decode_value(sw)}
    mac = by_oid.get(DISC.CHASSIS_MAC_OID)
    if mac is not None and mac.kind == "octet" and mac.raw:
        out["chassis_mac"] = D.decode_value(mac, as_mac=True)
    req.send_json(out)


def route_read(ctx, req):
    try:
        reader = _reader(req.body(), keep_raw_walk=True)
    except ValueError as exc:
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return
    try:
        doc = reader.read()
    except SnmpError as exc:
        req.send_json({"ok": False, "error": str(exc)})
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("read failed")
        req.send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return
    if not doc.get("stations") and not doc["system"].get("software_id") \
            and doc["device"]["oids_read"] == 0:
        req.send_json({"ok": False,
                       "error": "no data returned — wrong community, not a "
                                "CIX, or UDP 161 blocked"})
        return
    req.send_json({"ok": True, "doc": doc, "report": render_report(doc)})


def route_backup_zip(ctx, req):
    doc = req.body().get("doc")
    if not isinstance(doc, dict):
        req.send_json({"ok": False, "error": "missing doc"}, 400)
        return
    try:
        body = build_backup_zip(doc)
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": str(exc)}, 500)
        return
    ip = (doc.get("device") or {}).get("ip") or "cix"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"toshiba-cix-{str(ip).replace('/', '_')}-{ts}-backup.zip"
    req.send_bytes(body, "application/zip", filename=fname)


def route_save(ctx, req):
    """Plan a station edit and PREVIEW it, or with ``confirm: true`` write + verify.

    Preview never touches the network. The write path is gated by
    ``WRITES_ENABLED`` and ``confirm`` and always GET-verifies the read-back.
    """
    params = req.body()
    station = params.get("station") or {}
    changes = params.get("changes") or {}
    confirm = bool(params.get("confirm"))
    writer = CIXWriter()
    try:
        ops = writer.plan_station_update(station, changes)
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return

    if not confirm:
        req.send_json({
            "ok": True, "mode": "preview", "writes_enabled": WRITES_ENABLED,
            "message": ("Preview only — nothing was sent. Use "
                        "“Confirm & write” to apply these SETs."),
            "planned_ops": [op.as_dict() for op in ops],
        })
        return

    try:
        reader = _reader(params, keep_raw_walk=False)   # builds the client
    except ValueError as exc:
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return
    writer = CIXWriter(reader.client)
    try:
        result = writer.commit(ops, confirm=True, verify=True)
    except (WriteError, SnmpError) as exc:
        req.send_json({"ok": False, "mode": "write", "error": str(exc),
                       "planned_ops": [op.as_dict() for op in ops]})
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("write failed")
        req.send_json({"ok": False, "mode": "write",
                       "error": f"{type(exc).__name__}: {exc}"})
        return
    req.send_json({
        "ok": result["ok"], "mode": "write", "writes_enabled": WRITES_ENABLED,
        "message": ("Write sent and verified." if result["ok"]
                    else "Write sent but read-back did not match — check the "
                         "results below."),
        "result": result, "planned_ops": [op.as_dict() for op in ops],
    })


# --------------------------------------------------------------------------
# catalog-driven backup / view / diff / restore
# --------------------------------------------------------------------------
def route_catalog_backup(ctx, req):
    try:
        reader = _reader(req.body(), keep_raw_walk=False)
    except ValueError as exc:
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return
    params = req.body()
    programs = params.get("programs") or None
    site = params.get("site")
    try:
        cat = load_catalog()
        doc = backup(reader.client, cat, site=site, programs=programs,
                     width=reader.width)
    except SnmpError as exc:
        req.send_json({"ok": False, "error": str(exc)})
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("catalog backup failed")
        req.send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return
    if doc["meta"].get("oids_read", 0) == 0:
        req.send_json({"ok": False,
                       "error": "no data returned — wrong community, not a "
                                "CIX, or UDP 161 blocked"})
        return
    req.send_json({"ok": True, "backup": doc,
                   "report": render_backup_text(doc, catalog=cat),
                   "program_views": program_views_from_backup(doc, cat)})


def route_view(ctx, req):
    params = req.body()
    doc = params.get("backup")
    if not isinstance(doc, dict):
        req.send_json({"ok": False, "error": "missing backup"}, 400)
        return
    try:
        cat = load_catalog()
        report = render_backup_text(doc, catalog=cat,
                                    program=params.get("program"),
                                    max_rows=params.get("max_rows"))
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": str(exc)}, 500)
        return
    req.send_json({"ok": True, "report": report, "meta": doc.get("meta", {}),
                   "programs": sorted(doc.get("programs", {}).keys()),
                   "program_views": program_views_from_backup(doc, cat)})


def route_diff(ctx, req):
    params = req.body()
    a, b = params.get("a"), params.get("b")
    if not isinstance(a, dict) or not isinstance(b, dict):
        req.send_json({"ok": False, "error": "need two backups (a, b)"}, 400)
        return
    try:
        cat = load_catalog()
        d = diff_backups(a, b, catalog=cat, ignore_readonly=not params.get("all"))
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": str(exc)}, 500)
        return
    req.send_json({"ok": True, "diff": d, "report": render_diff_text(d)})


def route_restore(ctx, req):
    """Plan a restore and PREVIEW it, or with ``confirm: true`` write + verify.

    Gated by WRITES_ENABLED + confirm (reusing CIXWriter). Read-only fields are
    never sent; applies to RAM (reboot persistence unproven)."""
    params = req.body()
    doc = params.get("backup")
    if not isinstance(doc, dict):
        req.send_json({"ok": False, "error": "missing backup"}, 400)
        return
    confirm = bool(params.get("confirm"))
    programs = params.get("programs") or None
    from_diff = params.get("from_diff") or None
    try:
        cat = load_catalog()
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": str(exc)}, 500)
        return

    client = None
    if confirm:
        try:
            reader = _reader(params, keep_raw_walk=False)
        except ValueError as exc:
            req.send_json({"ok": False, "error": str(exc)}, 400)
            return
        client = reader.client
    try:
        result = restore(client, doc, cat, confirm=confirm, programs=programs,
                         from_diff=from_diff)
    except (WriteError, SnmpError) as exc:
        req.send_json({"ok": False, "mode": "write", "error": str(exc)})
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("restore failed")
        req.send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return
    req.send_json(result)


def route_update_apply(ctx, req):
    """POST /api/update — download + install the latest release. Requires an
    explicit ``{"confirm": true}``; a plain POST only reports the plan."""
    if not bool(req.body().get("confirm")):
        req.send_json({"ok": False, "error": "apply requires an explicit confirm",
                       "plan": plan_update()}, 400)
        return
    try:
        result = apply_update(confirm=True)
    except Exception as exc:  # noqa: BLE001
        log.exception("update apply failed")
        req.send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return
    req.send_json(result)


# --------------------------------------------------------------------------
# P1 browse: session working copy + snapshot-on-connect + per-program reads
# --------------------------------------------------------------------------
def route_snapshot_start(ctx, req):
    """POST /api/snapshot — connect a CIX and start the core→all snapshot job.

    Creates a session, attaches the live (read-only) SNMP client, and submits a
    background job that reads core programs first (stations/trunks open fast)
    then the rest, populating the session working copy as each phase lands and
    saving the finished snapshot for cold start. Returns the session + job ids;
    progress streams on SSE ``/api/events`` (``job.progress`` / ``session.*``).
    """
    params = req.body()
    try:
        reader = _reader(params, keep_raw_walk=False)
    except ValueError as exc:
        req.send_json({"ok": False, "error": str(exc)}, 400)
        return
    try:
        cat = load_catalog()
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": f"catalog unavailable: {exc}"}, 500)
        return

    client = reader.client
    site = params.get("site")
    site_id = params.get("site_id") or slugify_id(site or getattr(client, "host", "cix"))
    transport = "overlay" if params.get("reach") == "remote" else "direct"
    session = ctx.sessions.create(site=site,
                                  device={"ip": getattr(client, "host", None)},
                                  transport=transport)
    session.attach_client(client)

    def job(report):
        def on_phase(views, phase):
            session.ingest_views(views)
            ctx.bus.publish("session.programs",
                            {"session": session.id, "phase": phase,
                             "read": len(session.doc)})

        snap = read_snapshot(client, cat, report=report, on_phase=on_phase,
                             site=site, width=reader.width)
        ident = snap["identity"]
        session.set_identity({"software_id": ident.get("swid"),
                              "chassis_mac": ident.get("chassis_mac")})
        session.snapshot_meta = snap["meta"]
        header = None
        try:
            header = ctx.snapshots().save(site_id, snap["program_views"],
                                          identity=ident, meta=snap["meta"],
                                          kind="snapshot")
        except Exception as exc:  # noqa: BLE001 — a save failure must not fail the read
            log.warning("snapshot save failed: %s", exc)
        return {"session": session.id, "site_id": site_id, "saved": header,
                "identity": ident, "meta": snap["meta"],
                "stats": snap["program_views"].get("stats")}

    j = ctx.jobs.submit("snapshot", job)
    session.jobs.append(j.id)
    req.send_json({"ok": True, "session": session.id, "site_id": site_id,
                   "job": j.id})


def _session_or_404(ctx, req):
    s = ctx.sessions.get(req.params["id"])
    if s is None:
        req.send_json({"ok": False, "error": "no such session"}, 404)
    return s


def route_session_get(ctx, req):
    s = _session_or_404(ctx, req)
    if s is not None:
        req.send_json({"ok": True, "session": s.as_dict()})


def route_session_snapshot(ctx, req):
    """GET /api/sessions/{id}/snapshot — the working-copy program index.

    A light view the nav uses to grey unread programs and show row counts: the
    identity, the snapshot meta, and one line per program that returned data.
    """
    s = _session_or_404(ctx, req)
    if s is None:
        return
    programs = [{"catalog_key": pv.get("catalog_key"),
                 "program_number": pv.get("program_number"),
                 "menu_area": pv.get("menu_area"),
                 "row_count": pv.get("row_count", 0)}
                for pv in s.doc.values()]
    req.send_json({"ok": True, "identity": s.identity,
                   "meta": s.snapshot_meta, "read_keys": s.read_keys(),
                   "programs": programs})


def _resolve_prog_or_404(ctx, req, cat):
    prog = cat.program(req.params["key"])
    if prog is None:
        req.send_json({"ok": False,
                       "error": "unknown program %r" % req.params["key"]}, 404)
    return prog


def route_session_program(ctx, req):
    """GET /api/sessions/{id}/program/{key} — one program's rows.

    From the working copy by default; ``?refresh=1`` does a live scoped read of
    just this program (read-only) and updates the working copy. An unread
    program returns its shaped empty view so the page says "no rows", never 404.
    """
    s = _session_or_404(ctx, req)
    if s is None:
        return
    try:
        cat = load_catalog()
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": f"catalog unavailable: {exc}"}, 500)
        return
    prog = _resolve_prog_or_404(ctx, req, cat)
    if prog is None:
        return
    if req.query.get("refresh") and s.client is not None:
        try:
            view, error = list_rows(s.client, cat, prog, width=10)
        except Exception as exc:  # noqa: BLE001 — SnmpError or transport
            req.send_json({"ok": False, "error": str(exc)})
            return
        s.put_program_view(view)
        req.send_json({"ok": True, "program": view, "source": "live",
                       "error": error})
        return
    view = s.program_view(prog.key)
    if view is None:
        req.send_json({"ok": True, "program": empty_program_view(cat, prog.key),
                       "source": "unread"})
        return
    req.send_json({"ok": True, "program": view, "source": "snapshot"})


def route_session_program_row(ctx, req):
    """GET /api/sessions/{id}/program/{key}/{index} — one row (record pane).

    From the working copy by default; ``?refresh=1`` does a targeted live GET of
    just that instance (the record pane's ⟳ re-read)."""
    s = _session_or_404(ctx, req)
    if s is None:
        return
    try:
        cat = load_catalog()
    except Exception as exc:  # noqa: BLE001
        req.send_json({"ok": False, "error": f"catalog unavailable: {exc}"}, 500)
        return
    prog = _resolve_prog_or_404(ctx, req, cat)
    if prog is None:
        return
    index = req.params["index"]
    if req.query.get("refresh") and s.client is not None:
        try:
            row, error = get_row(s.client, cat, prog, index)
        except Exception as exc:  # noqa: BLE001 — SnmpError or transport
            req.send_json({"ok": False, "error": str(exc)})
            return
        req.send_json({"ok": row is not None, "row": row, "source": "live",
                       "error": error})
        return
    view = s.program_view(prog.key)
    row = None
    if view is not None:
        row = next((r for r in view["rows"] if r["index"] == index), None)
    req.send_json({"ok": row is not None, "row": row, "source": "snapshot"})


# --------------------------------------------------------------------------
# cold start: snapshots on disk (browse with the device off)
# --------------------------------------------------------------------------
def route_site_snapshots(ctx, req):
    """GET /api/sites/{id}/snapshots — saved-snapshot headers, newest first."""
    req.send_json({"ok": True,
                   "snapshots": ctx.snapshots().list(req.params["id"])})


def route_site_snapshot_latest(ctx, req):
    """GET /api/sites/{id}/snapshots/latest — the full last snapshot (cold start)."""
    snap = ctx.snapshots().latest(req.params["id"])
    req.send_json({"ok": snap is not None, "snapshot": snap})


def route_site_snapshot_get(ctx, req):
    """GET /api/sites/{id}/snapshots/{sid} — one full saved snapshot."""
    snap = ctx.snapshots().get(req.params["id"], req.params["sid"])
    req.send_json({"ok": snap is not None, "snapshot": snap},
                  200 if snap is not None else 404)


# --------------------------------------------------------------------------
# wiring
# --------------------------------------------------------------------------
def register_browse_routes(ctx: ServerContext) -> None:
    """P1 browse routes: snapshot-on-connect, session working copy, cold start."""
    r = ctx.router
    r.post("/api/snapshot", route_snapshot_start)
    r.get("/api/sessions/{id}", route_session_get)
    r.get("/api/sessions/{id}/snapshot", route_session_snapshot)
    r.get("/api/sessions/{id}/program/{key}", route_session_program)
    r.get("/api/sessions/{id}/program/{key}/{index}", route_session_program_row)
    r.get("/api/sites/{id}/snapshots", route_site_snapshots)
    r.get("/api/sites/{id}/snapshots/latest", route_site_snapshot_latest)
    r.get("/api/sites/{id}/snapshots/{sid}", route_site_snapshot_get)


def register_legacy_routes(ctx: ServerContext) -> None:
    """Register the static UI + legacy JSON routes (kept semantics) onto ``ctx``."""
    r = ctx.router
    r.get("/", route_index)
    r.get("/index.html", route_index)
    r.get("/api/health", route_health)
    r.get("/api/discover", route_discover)
    r.get("/api/catalog", route_catalog)
    r.get("/api/update", route_update_check)
    r.post("/api/connect", route_connect)
    r.post("/api/read", route_read)
    r.post("/api/backup", route_backup_zip)
    r.post("/api/save", route_save)
    r.post("/api/catalog-backup", route_catalog_backup)
    r.post("/api/view", route_view)
    r.post("/api/diff", route_diff)
    r.post("/api/restore", route_restore)
    r.post("/api/update", route_update_apply)


def make_context(*, token=None, appdirs=None) -> ServerContext:
    """A context with the core P0 routes + the browse + legacy routes registered."""
    ctx = ServerContext(token=token, appdirs=appdirs)
    register_core_routes(ctx)
    register_browse_routes(ctx)
    register_legacy_routes(ctx)
    return ctx


# The default handler: auth DISABLED (token=None) so the offline test harness
# and ``launcher.start_server`` keep working unchanged.
CIXHandler = build_handler(make_context())


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


def _background_update_check() -> None:
    """Non-blocking, best-effort 'is there a newer release?' notice."""
    try:
        info = check_for_update()
    except Exception:  # noqa: BLE001
        return
    if info.get("ok") and info.get("newer"):
        print(f"  Update available: v{info.get('latest')} "
              f"(you have {info.get('current')}) — {info.get('html_url')}")
        if info.get("replaceable"):
            print("  Use 'Check for updates' in the web UI to install it.")


def serve(host: str = "127.0.0.1", port: int = 8765, *,
          open_browser: bool = True, portable: bool = False) -> None:
    """Launch the full app: finalize any staged update, then serve with the
    loopback token + Origin guard on, an OS-chosen port and app-mode browser.

    ``portable=True`` keeps the store (sites.json, journal, backups) beside the
    executable for a USB stick instead of the per-OS app-data dir.
    """
    import threading

    pending = finalize_pending_update()
    if pending.get("ok") and pending.get("relaunch_argv"):
        from .update import relaunch
        relaunch(pending["relaunch_argv"])   # does not return on success

    ctx = make_context(token=generate_token(), appdirs=from_args(portable=portable))
    print(f"Toshiba CIX Manager {__version__}")
    print("  Read-only SNMP. Writes gated behind explicit confirm. Ctrl-C to stop.")
    threading.Thread(target=_background_update_check, daemon=True).start()
    try:
        run_server(ctx, host, port, open_browser=open_browser, autoexit=True,
                   block=True, on_ready=lambda url: print(f"  Open: {url}"))
    except KeyboardInterrupt:
        print("\nStopping.")


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="toshiba-cix-manager",
        description="Local web app to read/view a Toshiba Strata CIX over SNMP "
                    "(read-only). Serves a UI on localhost.")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1 — local only)")
    p.add_argument("--port", type=int, default=8765,
                   help="preferred port (default 8765; next free port if busy)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not auto-open the browser")
    p.add_argument("--portable", action="store_true",
                   help="keep the store beside the executable (USB stick)")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    serve(args.host, args.port, open_browser=not args.no_browser,
          portable=args.portable)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
