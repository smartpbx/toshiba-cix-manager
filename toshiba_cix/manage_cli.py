"""Command-line entry point for the catalog-driven backup / view / diff / restore.

    python3 manage.py backup  <ip> [--community C] [--out b.json] [--text b.txt]
                               [--programs 200,205] [--site "Label"]
    python3 manage.py view    <backup.json> [--program 200]
    python3 manage.py diff    <a.json> <b.json> [--all] [--json out.json]
    python3 manage.py restore <backup.json> <ip> [--confirm] [--programs 200]
                               [--from-diff d.json] [--community C]

``backup`` is read-only. ``restore`` **previews by default** (sends nothing);
``--confirm`` applies the writable fields to the live CIX (RAM — persistence
across reboot is unproven) and GET-verifies each one. Pure stdlib.
"""

from __future__ import annotations

import argparse
import json
import sys

from .backup import backup as do_backup
from .backup import render_backup_text
from .catalog import load_catalog
from .diff import diff_backups, render_diff_text
from .restore import plan_summary, restore
from .snmp import SnmpError, SnmpV1
from .write import WRITES_ENABLED, WriteError


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _parse_programs(value: str | None):
    if not value:
        return None
    return [p.strip() for p in value.split(",") if p.strip()]


def _client(args) -> SnmpV1:
    return SnmpV1(args.ip, args.community, port=args.port,
                  timeout=args.timeout, retries=args.retries)


def _add_snmp_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--community", default="communityName")
    p.add_argument("--port", type=int, default=161)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--width", type=int, default=10)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="manage.py",
        description="Toshiba Strata CIX catalog-driven backup / view / diff / "
                    "restore (enterprise MIB 1.3.6.1.4.1.186.1.22).")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backup", help="read a live CIX into a backup JSON")
    b.add_argument("ip")
    _add_snmp_opts(b)
    b.add_argument("--site", default=None, help="site label stored in meta")
    b.add_argument("--programs", default=None,
                   help="comma-separated program numbers/keys to limit to")
    b.add_argument("--out", default=None, help="write backup JSON to PATH")
    b.add_argument("--text", default=None, help="write a text rendering to PATH")
    b.add_argument("--quiet", action="store_true")

    v = sub.add_parser("view", help="render a backup JSON")
    v.add_argument("backup")
    v.add_argument("--program", default=None, help="limit to one program")
    v.add_argument("--max-rows", type=int, default=None)

    d = sub.add_parser("diff", help="diff two backup JSONs (a=old, b=new)")
    d.add_argument("a")
    d.add_argument("b")
    d.add_argument("--all", action="store_true",
                   help="include read-only field changes (noisy)")
    d.add_argument("--json", dest="json_out", default=None,
                   help="write the structured diff to PATH")

    r = sub.add_parser("restore", help="write a backup back to a CIX (GATED)")
    r.add_argument("backup")
    r.add_argument("ip")
    _add_snmp_opts(r)
    r.add_argument("--programs", default=None,
                   help="comma-separated programs to restore (default: all)")
    r.add_argument("--from-diff", dest="from_diff", default=None,
                   help="restore only the fields a diff JSON reports changed")
    r.add_argument("--confirm", action="store_true",
                   help="actually SEND the writes (default is preview only)")
    r.add_argument("--batch-size", type=int, default=20)
    return p


def _cmd_backup(args) -> int:
    cat = load_catalog()
    client = _client(args)
    try:
        doc = do_backup(client, cat, site=args.site,
                        programs=_parse_programs(args.programs),
                        width=args.width)
    except SnmpError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if doc["meta"].get("oids_read", 0) == 0:
        print(f"ERROR: no data from {args.ip} — wrong community, not a CIX, or "
              "UDP 161 blocked.", file=sys.stderr)
        return 3
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=str)
        print(f"wrote backup -> {args.out}", file=sys.stderr)
    if args.text:
        with open(args.text, "w", encoding="utf-8") as fh:
            fh.write(render_backup_text(doc, catalog=cat))
        print(f"wrote text   -> {args.text}", file=sys.stderr)
    if not args.quiet:
        if args.out:
            m = doc["meta"]
            print(f"{m['programs_count']} programs, {m['rows_count']} rows, "
                  f"{m['oids_read']} OIDs  (catalog {m['catalog_version']})")
        else:
            print(render_backup_text(doc, catalog=cat))
    return 0


def _cmd_view(args) -> int:
    cat = load_catalog()
    doc = _load_json(args.backup)
    print(render_backup_text(doc, catalog=cat, program=args.program,
                             max_rows=args.max_rows))
    return 0


def _cmd_diff(args) -> int:
    cat = load_catalog()
    a, b = _load_json(args.a), _load_json(args.b)
    d = diff_backups(a, b, catalog=cat, ignore_readonly=not args.all)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2, default=str)
        print(f"wrote diff -> {args.json_out}", file=sys.stderr)
    print(render_diff_text(d))
    return 0


def _cmd_restore(args) -> int:
    cat = load_catalog()
    doc = _load_json(args.backup)
    from_diff = _load_json(args.from_diff) if args.from_diff else None
    client = _client(args) if args.confirm else None
    try:
        result = restore(client, doc, cat, confirm=args.confirm,
                         programs=_parse_programs(args.programs),
                         from_diff=from_diff, batch_size=args.batch_size)
    except (WriteError, SnmpError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    s = result["summary"]
    print(f"plan: {s['sendable']} sendable, {s['skipped']} skipped "
          f"({s['read_only']} read-only), "
          f"{s['unproven_wire_type']} unproven wire-type",
          file=sys.stderr)
    if result["mode"] == "preview":
        print(result["message"])
        print(f"(writes_enabled={WRITES_ENABLED}; re-run with --confirm to apply)")
        for op in result["planned_ops"]:
            if op["sendable"]:
                print(f"  SET {op['target_oid']} = {op['new_value']!r}"
                      f"  [{op['ber_type']}] {op['field_name']}")
        return 0
    print(result["message"])
    for r in result.get("results", []):
        flag = "ok" if r["match"] else "MISMATCH"
        print(f"  [{flag}] {r['field']} = {r['read_back']!r} "
              f"(requested {r['requested']!r})")
    return 0 if result["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {
        "backup": _cmd_backup, "view": _cmd_view,
        "diff": _cmd_diff, "restore": _cmd_restore,
    }[args.cmd](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
