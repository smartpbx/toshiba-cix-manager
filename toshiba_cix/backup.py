"""Catalog-driven full backup of a Toshiba Strata CIX.

A backup walks every program table the catalog knows (read-only GETNEXT) plus
the system-identity scalars, decodes each value by its field's syntax, and
writes the app's **own openable format** — a single JSON that the viewer, the
diff and the restore planner all read back.

Three layers, I/O isolated so the whole build is unit-tested offline:

* :func:`collect` — the only network step: GETNEXT-walk the catalog's field
  OIDs (reusing :meth:`SnmpV1.bulk_walk`) and return ``[(oid, Value)]``.
* :func:`build_backup` — **pure**: attribute each OID to its catalog field,
  group into program → rows → named fields, decode by syntax. Tested against
  fixtures, no device.
* :func:`backup` — orchestration: read the identity scalars for ``meta`` then
  ``collect`` + ``build_backup``.

Backup file schema (``format == "toshiba-cix-backup"``)::

    {
      "format": "toshiba-cix-backup",
      "format_version": 1,
      "meta": {
        "swid": "<software id>", "chassis_mac": "...", "site": "<label|null>",
        "read_at": "<iso8601>", "catalog_version": "re-xxxxxxxxxxxx",
        "source_ip": "...", "tool_version": "...", "scope": "all"|[programs],
        "oids_read": N, "programs_count": N, "rows_count": N, "walk_error": null
      },
      "programs": {
        "<catalog key>": {               # keyed by catalog key — program
          "number": "200",               #   numbers are null/duplicated, the
          "name": "StationAssign",       #   key is the only unique id
          "group_oid": "...",
          "rows": [
            {"index": "1.3.50.48.48",    # exact instance tail (restores the OID)
             "key": "200",               # human row key (the DN, when present)
             "fields": {"stationStationName": "Front Desk", ...}}
          ]
        }
      },
      "unmatched": [{"oid": "...", "value": ...}]   # anything outside the catalog
    }

Programs are keyed by the **catalog key** (e.g. ``"200StationAssign"``), not the
program number: 31 programs have a null number and numbers repeat, so the key
is the only stable identifier. Each entry still carries ``number`` and ``name``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone

from . import __version__
from .catalog import Catalog, load_catalog
from .decode import ENTERPRISE_ROOT, decode_value, parse_row_index
from .snmp import SnmpError, Value

FORMAT = "toshiba-cix-backup"
# v2 (backups.md §1): adds meta.snapshot{id,kind,name,…}, content_hash,
# program_hashes, identity_programs, sensitive_fields, redacted, and an optional
# voicemail section. v1 files stay openable — a v2 reader treats missing keys as
# defaults (see :func:`load_document`).
FORMAT_VERSION = 2

# The sibling format-family members (templates, change sets, exported diffs) all
# load through :func:`load_document`, dispatching on ``format``.
FORMAT_TEMPLATE = "toshiba-cix-template"
FORMAT_CHANGESET = "toshiba-cix-changeset"
FORMAT_DIFF = "toshiba-cix-diff"

SOFTWARE_ID_OID = f"{ENTERPRISE_ROOT}.7.2.1.0"
CHASSIS_MAC_OID = f"{ENTERPRISE_ROOT}.7.9.1.0"

# The marker a redacted secret carries in an exported file (backups.md §1.3). It
# is *never* a value that can be written back: :mod:`restore` refuses it.
REDACTED_KEY = "__redacted__"

# Programs whose rows make a *system* unique (its IP plan, LAN, SNMP community,
# chassis MAC). The tool writes the present subset into ``meta.identity_programs``
# so the cross-system restore (backups.md §6.3) and cross-site diff (§4.4) can
# exclude them even when an older file is opened by a newer tool. Keyed by
# catalog key; resolved against the live catalog so a key the catalog lacks is
# simply dropped.
IDENTITY_PROGRAM_KEYS = (
    "150SystemIPData", "151BIPUConfiuration", "801LAN",
    "communityName", "macAddress",
)

# Field names whose value is a secret (system/lock/remote/admin passwords, SNMP
# community strings, FTP credentials). The exporter redacts these by default and
# every diff renderer masks them (backups.md §1.3). A conservative name match —
# the catalog's own field names are descriptive.
_SENSITIVE_RE = re.compile(r"(passw|pwd|secret|communityname|communityid)",
                           re.IGNORECASE)


# --------------------------------------------------------------------------
# root planning (pure)
# --------------------------------------------------------------------------
def walk_roots(catalog: Catalog, programs=None) -> list[str]:
    """The minimal set of GETNEXT roots that covers the selected programs.

    Collects the chosen programs' field (column) OIDs, then drops any OID that
    is a descendant of another kept OID — walking the ancestor already sweeps
    the descendant's instances — so the live read makes as few passes as it can.
    """
    if programs:
        progs = catalog.programs_for(programs)
    else:
        progs = list(catalog.programs.values())
    oids = sorted({f["oid"] for p in progs for f in p.fields if f.get("oid")},
                  key=lambda o: [int(x) for x in o.split(".")])
    roots: list[str] = []
    for oid in oids:
        if any(oid == r or oid.startswith(r + ".") for r in roots):
            continue
        roots.append(oid)
    return roots


# --------------------------------------------------------------------------
# collection (I/O)
# --------------------------------------------------------------------------
def collect(client, catalog: Catalog, *, programs=None,
            width: int = 10, max_total: int = 500000
            ) -> tuple[list[tuple[str, Value]], str | None]:
    """GETNEXT-walk the catalog's field subtrees. Returns ``(pairs, error)``.

    Read-only: emits only GETNEXT. Reuses the device-hardened
    :meth:`SnmpV1.bulk_walk` (adaptive batch size, tooBig recovery). A transport
    failure degrades to whatever was collected plus an ``error`` string rather
    than losing the partial read.
    """
    roots = walk_roots(catalog, programs)
    error: str | None = None
    pairs: list[tuple[str, Value]] = []
    try:
        pairs = client.bulk_walk(roots, width=width, max_total=max_total)
    except SnmpError as exc:
        error = str(exc)
    # de-dup (bulk_walk can revisit an overlap)
    seen: set[str] = set()
    out: list[tuple[str, Value]] = []
    for oid, val in pairs:
        if oid not in seen:
            seen.add(oid)
            out.append((oid, val))
    return out, error


def read_identity(client) -> dict:
    """Read the two identity scalars for ``meta`` (software id, chassis MAC)."""
    out: dict = {"swid": None, "chassis_mac": None}
    try:
        vbs = client.get([SOFTWARE_ID_OID, CHASSIS_MAC_OID])
    except SnmpError:
        return out
    by_oid = {vb.oid: vb.value for vb in vbs}
    sw = by_oid.get(SOFTWARE_ID_OID)
    if sw is not None and not sw.is_missing and sw.kind == "octet" and sw.raw:
        out["swid"] = decode_value(sw)
    mac = by_oid.get(CHASSIS_MAC_OID)
    if mac is not None and not mac.is_missing and mac.kind == "octet" and mac.raw:
        out["chassis_mac"] = decode_value(mac, as_mac=True)
    return out


# --------------------------------------------------------------------------
# v2: canonical form, content hashing, identity / secrets, redaction (pure)
# --------------------------------------------------------------------------
def canonical_json(obj) -> str:
    """Canonical JSON for hashing / `git diff`: sorted keys, no whitespace.

    Rows and programs are already emitted in a deterministic order by
    :func:`build_backup`; ``sort_keys`` fixes field (dict) order, so a switch
    that has not changed serialises to the same string every time and two
    laptops reading the same switch hash identically (backups.md §1.1)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_hash(doc: dict) -> str:
    """A hash over ``{programs, unmatched}`` only — never ``meta``.

    Excluding ``meta`` is what lets a scheduled re-read that found nothing
    changed dedupe against the prior snapshot (backups.md §1.1, §2.3)."""
    return _sha256(canonical_json({
        "programs": doc.get("programs", {}),
        "unmatched": doc.get("unmatched", []),
    }))


def program_hashes(doc: dict) -> dict:
    """Per-program content hashes, for cheap "which programs changed" checks."""
    out: dict = {}
    for key, bucket in (doc.get("programs") or {}).items():
        out[key] = _sha256(canonical_json(bucket))
    return out


def identity_program_keys(catalog: Catalog) -> list:
    """The identity program keys :data:`IDENTITY_PROGRAM_KEYS` the catalog has."""
    return [k for k in IDENTITY_PROGRAM_KEYS if catalog.program(k) is not None]


def is_sensitive_field(field_name) -> bool:
    """True when a field name denotes a secret (password / community / FTP cred)."""
    return bool(field_name and _SENSITIVE_RE.search(str(field_name)))


def sensitive_field_refs(catalog: Catalog) -> list:
    """``"<progkey>/*/<field>"`` refs for every secret field in the catalog.

    Stored in ``meta.sensitive_fields`` so the exporter and the diff renderer
    redact / mask the same set the *writer* considered secret, even in a file a
    newer tool opens. The ``*`` is the row wildcard — every row's value of that
    field is sensitive."""
    refs: list = []
    for prog in catalog.programs.values():
        for fld in prog.fields:
            name = fld.get("name")
            if is_sensitive_field(name):
                refs.append(f"{prog.key}/*/{name}")
    return sorted(set(refs))


def _sensitive_fields_by_program(doc: dict, catalog: Catalog | None) -> dict:
    """``{prog_key: {field_name}}`` the redactor masks, from meta or the catalog."""
    by_prog: dict = {}
    refs = (doc.get("meta", {}) or {}).get("sensitive_fields")
    if not refs and catalog is not None:
        refs = sensitive_field_refs(catalog)
    for ref in refs or []:
        parts = str(ref).split("/")
        if len(parts) == 3:
            by_prog.setdefault(parts[0], set()).add(parts[2])
    return by_prog


def redact(doc: dict, *, catalog: Catalog | None = None) -> dict:
    """A deep copy with every sensitive field value replaced by a salted marker.

    Export / Share / Conduit push use this (backups.md §1.3). The marker is
    ``{"__redacted__": "sha256:<salted hash>"}``; the salt is the snapshot id so
    the same password still compares equal *within* a diff of two redacted files
    from one lineage but not across sites. ``programs`` shape is untouched (same
    keys, same rows) so a redacted file still opens in the viewer and diffs. A
    redacted value can never be written back — :mod:`restore` treats the marker
    as unsendable."""
    out = copy.deepcopy(doc)
    salt = (out.get("meta", {}) or {}).get("snapshot", {}).get("id") or ""
    by_prog = _sensitive_fields_by_program(out, catalog)
    for key, bucket in (out.get("programs") or {}).items():
        secret_names = by_prog.get(key)
        if not secret_names:
            continue
        for row in bucket.get("rows", []):
            fields = row.get("fields", {})
            for fk in list(fields):
                # field_key may be "name#oidsuffix" for duplicated columns.
                if fk.split("#", 1)[0] in secret_names and fields[fk] not in (
                        None, "", MISSING_SENTINEL):
                    digest = hashlib.sha256(
                        (salt + "\x00" + str(fields[fk])).encode("utf-8")
                    ).hexdigest()
                    fields[fk] = {REDACTED_KEY: "sha256:" + digest}
    out.setdefault("meta", {})["redacted"] = True
    return out


# A value that decode produced for "no data" — never redacted (nothing to hide).
MISSING_SENTINEL = decode_value(Value("missing"))


def is_redacted_value(value) -> bool:
    """True when a stored value is a redaction marker (cannot be restored)."""
    return isinstance(value, dict) and REDACTED_KEY in value


# --------------------------------------------------------------------------
# build (pure)
# --------------------------------------------------------------------------
def _row_sort_key(index: str):
    arcs = [int(a) for a in index.split(".")] if index else []
    return (len(arcs), arcs)


def _human_key(index: str) -> str:
    """A readable row key from the instance tail (the DN when there is one)."""
    if not index:
        return "_"
    try:
        arcs = tuple(int(a) for a in index.split("."))
    except ValueError:
        return index
    ri = parse_row_index(arcs)
    return ri.key


def _snapshot_meta(content_h: str, snapshot: dict | None, meta: dict) -> dict:
    """The ``meta.snapshot`` block (backups.md §1): id, kind, provenance.

    The id is ``<utc stamp>-<content_hash[:6]>`` — sortable, and equal for two
    identical reads (so dedupe keys on it fall out naturally)."""
    snap = dict(snapshot or {})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    short = content_h.split(":", 1)[-1][:6]
    snap.setdefault("id", f"{stamp}-{short}")
    snap.setdefault("kind", "manual")
    snap.setdefault("name", None)
    snap.setdefault("note", None)
    snap.setdefault("tags", [])
    snap.setdefault("pinned", False)
    snap.setdefault("parent", None)
    snap.setdefault("operator", None)
    snap.setdefault("transport", meta.get("transport") if meta else None)
    snap.setdefault("trigger", None)
    return snap


def build_backup(pairs, catalog: Catalog, *, meta: dict | None = None,
                 snapshot: dict | None = None) -> dict:
    """Assemble a v2 backup dict from collected ``(oid, Value)`` pairs. Pure.

    Every OID is attributed to its catalog field by longest-prefix match and
    filed under ``program key → row (by instance tail) → field``. OIDs with no
    catalog field survive verbatim in ``unmatched`` so a backup never silently
    drops data the device returned.

    ``snapshot`` supplies the v2 ``meta.snapshot`` provenance (kind, name, tags,
    parent, operator, transport, trigger); anything omitted gets a safe default.
    The content hash, per-program hashes, identity-program list and sensitive-
    field refs are computed here so every file carries its own dedupe key and
    the lists the writer considered identity / secret.
    """
    programs: dict[str, dict] = {}
    rows_by_prog: dict[str, dict[str, dict]] = {}
    unmatched: list[dict] = []
    row_count = 0

    for oid, val in pairs:
        attr = catalog.attribute_oid(oid)
        if attr is None:
            unmatched.append({"oid": oid, "value": decode_value(val)})
            continue
        prog_key, fld, tail = attr
        prog = catalog.programs[prog_key]
        bucket = programs.get(prog_key)
        if bucket is None:
            bucket = programs[prog_key] = {
                "number": prog.number, "name": prog.name,
                "group_oid": prog.group_oid, "rows": [],
            }
            rows_by_prog[prog_key] = {}
        index = tail or "0"
        row = rows_by_prog[prog_key].get(index)
        if row is None:
            row = {"index": index, "key": _human_key(index), "fields": {}}
            rows_by_prog[prog_key][index] = row
            row_count += 1
        row["fields"][prog.field_key(fld)] = catalog.decode_field_value(fld, val)

    # finalise: deterministic row order per program, deterministic unmatched
    for prog_key, bucket in programs.items():
        bucket["rows"] = sorted(rows_by_prog[prog_key].values(),
                                key=lambda r: _row_sort_key(r["index"]))
    unmatched.sort(key=lambda e: e.get("oid", ""))

    full_meta = {
        "swid": None, "chassis_mac": None, "site": None,
        "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": catalog.version,
        "source_ip": None, "tool_version": __version__,
        "scope": "all", "oids_read": len(pairs), "walk_error": None,
    }
    if meta:
        full_meta.update(meta)
    full_meta["programs_count"] = len(programs)
    full_meta["rows_count"] = row_count
    full_meta["unmatched_count"] = len(unmatched)

    doc = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "meta": full_meta,
        "programs": dict(sorted(programs.items())),
        "unmatched": unmatched,
    }
    # v2 meta: hashes and the identity / secret lists, over the final programs.
    content_h = content_hash(doc)
    full_meta["content_hash"] = content_h
    full_meta["program_hashes"] = program_hashes(doc)
    full_meta["identity_programs"] = identity_program_keys(catalog)
    full_meta["sensitive_fields"] = sensitive_field_refs(catalog)
    full_meta.setdefault("redacted", False)
    full_meta["snapshot"] = _snapshot_meta(content_h, snapshot, full_meta)
    return doc


# --------------------------------------------------------------------------
# orchestration (I/O)
# --------------------------------------------------------------------------
def backup(client, catalog: Catalog | None = None, *, site: str | None = None,
           programs=None, width: int = 10, max_total: int = 500000,
           snapshot: dict | None = None, transport: str | None = None) -> dict:
    """Read a live CIX and return a v2 backup dict (read-only).

    ``snapshot`` and ``transport`` flow into ``meta.snapshot`` provenance so the
    snapshot store can record who/what/how without a second read."""
    catalog = catalog or load_catalog()
    ident = read_identity(client)
    pairs, error = collect(client, catalog, programs=programs, width=width,
                           max_total=max_total)
    meta = {
        "swid": ident.get("swid"),
        "chassis_mac": ident.get("chassis_mac"),
        "site": site,
        "source_ip": getattr(client, "host", None),
        "scope": "all" if not programs else list(programs),
        "walk_error": error,
        "transport": transport,
    }
    return build_backup(pairs, catalog, meta=meta, snapshot=snapshot)


# --------------------------------------------------------------------------
# format family (pure)
# --------------------------------------------------------------------------
def load_document(path_or_obj) -> dict:
    """Load any format-family JSON (backup / template / change set / diff).

    Accepts a path or an already-parsed dict and returns it unchanged after a
    light shape check, so every reader in the app funnels through one entry
    point (backups.md §1.4). A v1 backup loads as-is; its missing v2 keys are
    defaulted by the readers that need them."""
    if isinstance(path_or_obj, dict):
        doc = path_or_obj
    else:
        with open(path_or_obj, encoding="utf-8") as fh:
            doc = json.load(fh)
    fmt = doc.get("format")
    if fmt not in (FORMAT, FORMAT_TEMPLATE, FORMAT_CHANGESET, FORMAT_DIFF):
        raise ValueError(f"not a Switchroom document (format={fmt!r})")
    return doc


def ensure_v2(doc: dict, catalog: Catalog | None = None) -> dict:
    """Return ``doc`` upgraded in place to v2: fill the hashes / lists / snapshot.

    A v1 file (or one built before the v2 fields existed) gains ``content_hash``,
    ``program_hashes``, ``identity_programs``, ``sensitive_fields`` and a
    ``meta.snapshot`` block without touching ``programs``. Idempotent — a file
    already carrying a content hash is returned unchanged."""
    meta = doc.setdefault("meta", {})
    if meta.get("content_hash"):
        return doc
    doc["format"] = doc.get("format", FORMAT)
    doc["format_version"] = FORMAT_VERSION
    content_h = content_hash(doc)
    meta["content_hash"] = content_h
    meta["program_hashes"] = program_hashes(doc)
    if catalog is not None:
        meta.setdefault("identity_programs", identity_program_keys(catalog))
        meta.setdefault("sensitive_fields", sensitive_field_refs(catalog))
    else:
        meta.setdefault("identity_programs", [])
        meta.setdefault("sensitive_fields", [])
    meta.setdefault("redacted", False)
    meta["snapshot"] = _snapshot_meta(content_h, meta.get("snapshot"), meta)
    return doc


# --------------------------------------------------------------------------
# rendering (pure)
# --------------------------------------------------------------------------
def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def _render_value(catalog, prog_key, fieldkey, value) -> str:
    if value is None:
        return ""
    if is_redacted_value(value):
        return "••••"
    if catalog is not None and isinstance(value, int) and not isinstance(value, bool):
        prog = catalog.program(prog_key)
        if prog is not None:
            fld = prog.field(fieldkey.split("#", 1)[0])
            if fld is not None and fld.get("syntax") == "EnumeratedINTEGER":
                label = catalog.enum_label(fld, value)
                if label:
                    return f"{value} ({label})"
    return str(value)


def render_backup_text(backup_doc: dict, *, catalog: Catalog | None = None,
                       program: str | None = None,
                       max_rows: int | None = None) -> str:
    """Human-readable rendering of a backup file: programs → rows → fields.

    ``program`` limits output to one program (catalog key, number or name);
    ``max_rows`` caps rows shown per program. When a ``catalog`` is supplied,
    EnumeratedINTEGER values are annotated with their label (once labels ship).
    """
    meta = backup_doc.get("meta", {})
    lines: list[str] = []
    lines.append(_hr("Toshiba Strata CIX — catalog backup"))
    lines.append(f"Software id     : {meta.get('swid', '?')}")
    lines.append(f"Chassis MAC     : {meta.get('chassis_mac', '?')}")
    lines.append(f"Site            : {meta.get('site') or '-'}")
    lines.append(f"Source IP       : {meta.get('source_ip') or '-'}")
    lines.append(f"Read at         : {meta.get('read_at', '?')}")
    lines.append(f"Catalog version : {meta.get('catalog_version', '?')}")
    lines.append(f"Tool version    : {meta.get('tool_version', '?')}")
    lines.append(f"Scope           : {meta.get('scope', '?')}")
    lines.append(f"Programs / rows : {meta.get('programs_count', '?')}"
                 f" / {meta.get('rows_count', '?')}")
    if meta.get("walk_error"):
        lines.append(f"WALK ERROR      : {meta['walk_error']} (partial)")
    lines.append("")

    progs = backup_doc.get("programs", {})
    want = None
    if program is not None:
        want = str(program)
    for prog_key in sorted(progs):
        bucket = progs[prog_key]
        if want is not None and want not in (
                prog_key, str(bucket.get("number")), bucket.get("name")):
            continue
        title = f"{prog_key}"
        num = bucket.get("number")
        if num:
            title += f"  (Program {num})"
        rows = bucket.get("rows", [])
        lines.append(_hr(f"{title} — {len(rows)} row(s)", "-"))
        shown = rows if max_rows is None else rows[:max_rows]
        for row in shown:
            lines.append(f"  [{row.get('key') or row.get('index')}]")
            for fk in sorted(row.get("fields", {})):
                lines.append(f"      {fk:<34} = "
                             f"{_render_value(catalog, prog_key, fk, row['fields'][fk])}")
        if max_rows is not None and len(rows) > max_rows:
            lines.append(f"  … {len(rows) - max_rows} more row(s)")
        lines.append("")

    unmatched = backup_doc.get("unmatched", [])
    if unmatched and program is None:
        lines.append(_hr(f"Unmatched OIDs (outside the catalog) — "
                         f"{len(unmatched)}", "-"))
        for e in unmatched[:50]:
            lines.append(f"  {e['oid']} = {e['value']}")
        if len(unmatched) > 50:
            lines.append(f"  … {len(unmatched) - 50} more")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "FORMAT", "FORMAT_VERSION", "FORMAT_TEMPLATE", "FORMAT_CHANGESET",
    "FORMAT_DIFF", "REDACTED_KEY", "IDENTITY_PROGRAM_KEYS",
    "SOFTWARE_ID_OID", "CHASSIS_MAC_OID",
    "walk_roots", "collect", "read_identity", "build_backup", "backup",
    "render_backup_text",
    "canonical_json", "content_hash", "program_hashes",
    "identity_program_keys", "is_sensitive_field", "sensitive_field_refs",
    "redact", "is_redacted_value", "load_document", "ensure_v2",
]
