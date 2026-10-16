"""Command-line entry point for the Toshiba CIX reader.

    reader.py <ip> [--community communityName] [--json out.json]
                   [--report out.txt] [--timeout 3] [--redact-secrets]
                   [--quiet]

Writes JSON and/or a text report to files when asked; otherwise prints the
text report to stdout. Read-only and idempotent.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .report import render as render_report
from .scan import CIXReader
from .snmp import SnmpError, SnmpV1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reader.py",
        description="Read & decode a Toshiba Strata CIX over SNMPv1 "
                    "(read-only). Enterprise MIB 1.3.6.1.4.1.186.1.22.",
    )
    p.add_argument("ip", help="CIX processor IP (conventionally x.x.x.253)")
    p.add_argument("--community", default="communityName",
                   help="SNMP v1 community (default: Toshiba factory default)")
    p.add_argument("--port", type=int, default=161)
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-request timeout in seconds (default 3, as eManager)")
    p.add_argument("--retries", type=int, default=1,
                   help="extra attempts per request on UDP timeout")
    p.add_argument("--json", dest="json_out", metavar="PATH",
                   help="write the structured JSON document to PATH")
    p.add_argument("--report", dest="report_out", metavar="PATH",
                   help="write the text report to PATH")
    p.add_argument("--redact-secrets", action="store_true",
                   help="mask FTP passwords in the text report")
    p.add_argument("--quiet", action="store_true",
                   help="do not print the report to stdout")
    p.add_argument("--max-oids", type=int, default=200000,
                   help="safety cap on OIDs walked (default 200000)")
    p.add_argument("--scope", choices=("all", "core"), default="all",
                   help="'all' reads the entire MIB (complete backup, slow on "
                        "a big system); 'core' reads only the documented "
                        "programs (stations, system, network) — much faster")
    p.add_argument("--serial", action="store_true",
                   help="use the simple single-varbind walk instead of the "
                        "fast batched walk (slower, maximally robust)")
    p.add_argument("--width", type=int, default=10,
                   help="max cursors per GETNEXT PDU in batched mode "
                        "(default 10; auto-shrinks if the agent says tooBig)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    client = SnmpV1(
        args.ip, args.community,
        port=args.port, timeout=args.timeout, retries=args.retries,
    )
    reader = CIXReader(
        client,
        max_oids=args.max_oids,
        strategy="serial" if args.serial else "bulk",
        width=args.width,
        scope=args.scope,
    )
    try:
        doc = reader.read()
    except SnmpError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not doc["stations"] and not doc["system"].get("software_id") \
            and doc["device"]["oids_read"] == 0:
        print(
            f"ERROR: no data returned from {args.ip} — wrong community "
            f"({args.community!r}), not a CIX, or UDP 161 blocked.",
            file=sys.stderr,
        )
        return 3

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=_json_default)
        print(f"wrote JSON  -> {args.json_out}", file=sys.stderr)

    text = render_report(doc, redact_secrets=args.redact_secrets)
    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote report-> {args.report_out}", file=sys.stderr)

    if not args.quiet:
        print(text)
    return 0


def _json_default(obj):
    # RowIndex / tuples etc. should never reach here (doc is plain), but be safe.
    try:
        return list(obj)
    except TypeError:
        return str(obj)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
