"""Value index — search a snapshot by what it *holds*, not just by program.

eManager could only take a tech to a page. The questions that cost real time on
site — "what else points at 2104?", "where is 5551234 routed at night?" — had no
answer short of opening every page (improvements.md §2.1). This builds an
inverted index over every field value in a backup doc so any DN, name, digit
string or OID resolves to every program / row / field that holds it, and
**where-used is that search with a fixed query** (the one mechanism behind the
COS "used by 14 stations" chip, Delete-Station dependents, and the User page's
cross-checks).

Pure stdlib, no I/O: :func:`build_index` takes a backup doc (what the store
holds) and an optional catalog for display numbers / menu paths; the engine and
the CLI (`manage.py find`) share it. ``references.json`` (field name → referenced
entity kind) turns the broad value search into a *typed* where-used.
"""

from __future__ import annotations

import json
import re

from .backup import is_redacted_value
from .catalog import Catalog, _load_data_text

REFERENCES_FILENAME = "references.json"


def load_references() -> dict:
    """``{field_name: entity_kind}`` for typed where-used, or ``{}`` if absent."""
    text = _load_data_text(REFERENCES_FILENAME, "EMBEDDED_REFERENCES_JSON")
    if not text:
        return {}
    try:
        return dict(json.loads(text).get("fields") or {})
    except (ValueError, AttributeError):
        return {}


def _norm(value) -> str | None:
    """A value's searchable string form, or ``None`` for nothing-to-index.

    Redaction markers and empty/missing values are skipped; everything else is
    stringified (raw — labels are applied at render time, not indexed)."""
    if value is None or is_redacted_value(value):
        return None
    s = str(value).strip()
    if s == "" or s == "<no data>":
        return None
    return s


class Index:
    """An inverted index over a snapshot's field values.

    ``occurrences`` is the flat list; ``by_value`` maps an exact value string to
    the occurrences holding it (the fast where-used path). Prefix / substring
    search scan ``occurrences`` — a CIX full read is ~40 k values, which a linear
    scan handles in milliseconds, and keeps the structure simple and pure."""

    def __init__(self, occurrences: list, references: dict | None = None):
        self.occurrences = occurrences
        self.references = references or {}
        self.by_value: dict[str, list] = {}
        for occ in occurrences:
            self.by_value.setdefault(occ["value"], []).append(occ)

    # -- search ------------------------------------------------------------
    def lookup(self, value, *, programs=None, fields=None, kinds=None,
               match: str = "exact", limit: int | None = None) -> list:
        """Occurrences holding ``value``.

        ``match`` ∈ ``exact | prefix | substring`` (case-insensitive for the
        latter two). ``programs`` / ``fields`` restrict to those program keys /
        field names; ``kinds`` restricts to reference kinds (dn / vmid / did …)
        via ``references.json``."""
        q = _norm(value)
        if q is None:
            return []
        prog_set = set(programs) if programs else None
        field_set = set(fields) if fields else None
        kind_set = set(kinds) if kinds else None
        out: list = []
        if match == "exact":
            cand = self.by_value.get(q, [])
        else:
            ql = q.lower()
            cand = [o for o in self.occurrences
                    if (o["value"].lower().startswith(ql) if match == "prefix"
                        else ql in o["value"].lower())]
        for o in cand:
            if prog_set is not None and o["program"] not in prog_set \
                    and o["program_number"] not in prog_set:
                continue
            if field_set is not None and o["field"].split("#", 1)[0] not in field_set:
                continue
            if kind_set is not None and o.get("ref_kind") not in kind_set:
                continue
            out.append(o)
            if limit and len(out) >= limit:
                break
        return out

    def references_to(self, value, *, kind=None) -> list:
        """Typed where-used: occurrences in *reference* fields holding ``value``.

        With no ``kind``, any reference field (a field named in
        ``references.json``); with a kind (``"dn"``), only fields of that kind.
        This is what the Delete-Station dependents list and the where-used chip
        call — nothing dangles unless the tech is told it would."""
        kinds = {kind} if kind else set(self.references.values())
        return [o for o in self.lookup(value) if o.get("ref_kind") in kinds]

    def values(self) -> set:
        return set(self.by_value.keys())

    def __len__(self) -> int:
        return len(self.occurrences)


def build_index(doc: dict, catalog: Catalog | None = None,
                references: dict | None = None) -> Index:
    """Build an :class:`Index` over a backup doc's field values. Pure.

    Each occurrence is ``{program, program_number, index, row_key, field,
    display_no, menu_path, value, ref_kind}``. ``display_no`` / ``menu_path``
    need a catalog; ``ref_kind`` comes from ``references`` (defaults to the
    vendored ``references.json``)."""
    references = load_references() if references is None else references
    occurrences: list = []
    for prog_key, bucket in (doc.get("programs") or {}).items():
        prog = catalog.program(prog_key) if catalog is not None else None
        info = catalog.menu_info(prog_key) if catalog is not None else {}
        number = bucket.get("number")
        for row in bucket.get("rows", []):
            row_key = row.get("key")
            index = row.get("index")
            for fieldkey, value in (row.get("fields") or {}).items():
                s = _norm(value)
                if s is None:
                    continue
                base = fieldkey.split("#", 1)[0]
                fld = prog.field(base) if prog is not None else None
                col = fld.get("col") if fld else None
                occurrences.append({
                    "program": prog_key,
                    "program_number": number,
                    "index": index,
                    "row_key": row_key,
                    "field": fieldkey,
                    "display_no": f"{col:02d}" if isinstance(col, int) else "",
                    "menu_path": info.get("menu_path"),
                    "value": s,
                    "ref_kind": references.get(base),
                })
    # Also index unmatched OIDs by their value, so a raw search still finds them.
    for e in doc.get("unmatched", []):
        s = _norm(e.get("value"))
        if s is None:
            continue
        occurrences.append({
            "program": None, "program_number": None, "index": None,
            "row_key": None, "field": e.get("oid"), "display_no": "",
            "menu_path": "Unmatched", "value": s, "ref_kind": None,
        })
    return Index(occurrences, references)


def build_index_from_views(program_views: dict, references: dict | None = None) -> Index:
    """Build an :class:`Index` over a live ``program_views`` working copy. Pure.

    The session holds the enrich.py contract (``programs[].rows[].cells[]`` with
    ``field_name`` / ``raw_value`` / ``col``), not a backup doc, so the live
    palette value search indexes that directly — no catalog needed, the cells
    already carry their metadata."""
    references = load_references() if references is None else references
    occurrences: list = []
    for pv in (program_views or {}).get("programs", []):
        prog_key = pv.get("catalog_key")
        number = pv.get("program_number")
        menu_path = pv.get("menu_path")
        for row in pv.get("rows", []):
            row_key = row.get("key")
            index = row.get("index")
            for cell in row.get("cells", []):
                s = _norm(cell.get("raw_value"))
                if s is None:
                    continue
                name = cell.get("field_name") or ""
                col = cell.get("col")
                occurrences.append({
                    "program": prog_key, "program_number": number,
                    "index": index, "row_key": row_key, "field": name,
                    "display_no": f"{col:02d}" if isinstance(col, int) else "",
                    "menu_path": menu_path, "value": s,
                    "ref_kind": references.get(name.split("#", 1)[0]),
                })
    return Index(occurrences, references)


# --------------------------------------------------------------------------
# palette query grammar (improvements.md §2.1) — pure, over an Index
# --------------------------------------------------------------------------
_PREFIX_RE = re.compile(r"^(?P<key>[a-z]+):(?P<val>.*)$", re.IGNORECASE)


def search(index: Index, query: str, *, limit: int | None = 200) -> dict:
    """Resolve a palette value query into grouped results (improvements.md §2.1).

    Understands the prefixes the design lists — ``prg:``/``program:`` (program
    scope), ``field:`` (field-name scope), ``cos:`` (COS reverse), ``oid:``,
    ``dn:``/``vm:``/``pbx:`` — and otherwise does an exact-then-substring value
    search. Returns ``{query, groups:[{program, menu_path, occurrences}]}`` so
    the UI can show results in program sections. Pure."""
    q = (query or "").strip()
    programs = fields = kinds = None
    oid = None
    m = _PREFIX_RE.match(q)
    if m:
        key, val = m.group("key").lower(), m.group("val").strip()
        if key in ("prg", "program"):
            programs, q = [val], val
            occ = [o for o in index.occurrences
                   if o["program"] == val or o["program_number"] == val]
            return _group(occ[:limit] if limit else occ, q)
        if key == "field":
            fields, q = [val], val
            occ = [o for o in index.occurrences
                   if o["field"].split("#", 1)[0].lower() == val.lower()
                   or val.lower() in o["field"].lower()]
            return _group(occ[:limit] if limit else occ, q)
        if key == "cos":
            # 103 row N and every row whose value is N in a cos* field
            occ = [o for o in index.occurrences
                   if (o["program"] == "103ClassOfService" and o["row_key"] == val)
                   or (o["field"].lower().startswith("cos") and o["value"] == val)]
            return _group(occ[:limit] if limit else occ, q)
        if key == "oid":
            occ = [o for o in index.occurrences if o["field"] == val]
            return _group(occ, q)
        if key in ("dn",):
            kinds, q = ["dn"], val
        elif key == "vm":
            kinds, q = ["vmid"], val
        elif key == "pbx":
            q = val
    exact = index.lookup(q, programs=programs, fields=fields, kinds=kinds,
                         match="exact", limit=limit)
    if exact:
        return _group(exact, q)
    sub = index.lookup(q, programs=programs, fields=fields, kinds=kinds,
                       match="substring", limit=limit)
    return _group(sub, q)


def _group(occurrences: list, query: str) -> dict:
    groups: dict = {}
    for o in occurrences:
        key = o["program"] or "Unmatched"
        g = groups.setdefault(key, {"program": key,
                                    "program_number": o.get("program_number"),
                                    "menu_path": o.get("menu_path"),
                                    "occurrences": []})
        g["occurrences"].append(o)
    return {"query": query, "count": len(occurrences),
            "groups": sorted(groups.values(),
                             key=lambda g: str(g.get("program_number") or g["program"]))}


__all__ = ["Index", "build_index", "build_index_from_views", "search",
           "load_references", "REFERENCES_FILENAME"]
