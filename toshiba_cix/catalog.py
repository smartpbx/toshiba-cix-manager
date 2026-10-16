"""The eManager field→OID catalog that drives backup / view / diff / restore.

The catalog is the complete, machine-readable model of a Toshiba Strata CIX's
programming, reverse-engineered from the eManager MOF: **186 programs, 2366
fields (1653 writable)**. It is vendored verbatim (minified) into the app at
:data:`CATALOG_FILENAME` so the tool is self-contained — no network, no
eManager, no MOF files at runtime.

Shape of the vendored JSON (one entry per MOF table)::

    {"<catalog key>": {
        "number":    "200",                 # program number (may be null)
        "name":      "StationAssign",
        "group_oid": "1.3.6.1.4.1.186.1.22.3.200",
        "fields": [{
            "name":   "stationStationName",
            "oid":    "1.3.6.1.4.1.186.1.22.3.200.1.1.18",  # the COLUMN oid
            "col":    18,                    # may be null
            "syntax": "DisplayString",       # DisplayString|OCTETSTRING|INTEGER
                                             #   |EnumeratedINTEGER|IpAddress|Gauge32
            "enc":    "OCTETSTRING",         # on-wire family: OCTETSTRING|INTEGER
                                             #   |IpAddress|Gauge32
            "len":    "0..16",               # declared value range (advisory)
            "access": "rw",                  # "rw" writable | "r" read-only
            "key":    false,                 # part of the row key (index)
        }, ...]
    }, ...}

One hard-won fact drives the whole design: **the field ``oid`` is the only
authoritative locator.** The convenient
``ROOT.3.<program>.1.1.<column>.<index>`` shape holds for the station/line
tables but NOT in general — programs live under ``.3``, ``.4``, ``.6``,
``.11`` …; scalar tables (e.g. 104 System Timers) are ``group_oid.<col>`` with
no ``.1.1.``; a single program's fields can span sibling sub-trees (921); and
``col`` / ``number`` are often ``null``. So every lookup keys off the full
field OID, and an instance OID is attributed to its field by **longest-prefix
match**, never by reconstructing arcs.

The proven write anchor: station name = program **200 col 18**
(``stationStationName``, rw, DisplayString 0..16), OID ``…3.200.1.1.18.<DN>``.

EnumeratedINTEGER values are returned raw (the integer). Human labels are a
later deliverable (the UX-RE effort); :meth:`Catalog.enum_label` is the hook —
call :meth:`Catalog.set_enum_labels` with an ``{oid: {raw: label}}`` map and
renderers will light up with no other change.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field as dc_field
from typing import Iterable

from .decode import ENTERPRISE_ROOT, MISSING, decode_octet, decode_value
from .snmp import Value, ber_integer, ber_octet

CATALOG_FILENAME = "emanager_catalog.json"
ENUM_LABELS_FILENAME = "enum_labels.json"
PROGRAM_MENUS_FILENAME = "program_menus.json"

# Menu areas as eManager groups them, in the order the UI should show them.
# ``command_to_menu.json`` supplies the first ten; the last three are our
# buckets for the handful of internal MIB tables eManager never surfaced as a
# program (null-number entries: licensing, SNMP/FTP middleware, status trees).
MENU_AREA_ORDER = (
    "System", "Station", "Trunk", "IP-Telephony", "Networking", "LCR/DR",
    "External Devices", "Attendant", "Utilities", "Miscellaneous",
    "Licensing", "Maintenance", "Advanced",
)

# On-wire encoding families (the MOF ``enc``) → how a restore SETs the value.
_INTEGER_ENCS = frozenset({"INTEGER", "Gauge32"})
_INTEGER_SYNTAXES = frozenset({"INTEGER", "EnumeratedINTEGER", "Gauge32"})

_CATALOG_CACHE: "Catalog | None" = None


# --------------------------------------------------------------------------
# loading (mirrors webapp.load_html: embedded → PyInstaller bundle → package)
# --------------------------------------------------------------------------
def _data_candidate_paths(filename: str) -> list[str]:
    """Where a vendored ``data/<filename>`` may live, across every build.

    PyInstaller one-file (``sys._MEIPASS``) first, then the packaged ``data/``
    dir of a dev checkout. Same order as :func:`load_catalog_text`.
    """
    paths: list[str] = []
    meipass = getattr(sys, "_MEIPASS", None)          # PyInstaller one-file
    if meipass:
        paths.append(os.path.join(meipass, "toshiba_cix", "data", filename))
        paths.append(os.path.join(meipass, "data", filename))
        paths.append(os.path.join(meipass, filename))
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, "data", filename))
    return paths


def _candidate_paths() -> list[str]:
    return _data_candidate_paths(CATALOG_FILENAME)


def _load_data_text(filename: str, embedded_global: str) -> str | None:
    """Return a vendored data file's text, or ``None`` if it is unavailable.

    Mirrors :func:`load_catalog_text` (embedded global → PyInstaller bundle →
    packaged ``data/``) but **degrades gracefully**: a build that forgot to
    bundle the enum-label / menu sidecar still runs — just without those
    annotations — instead of crashing.
    """
    embedded = globals().get(embedded_global)
    if embedded:
        return embedded
    for path in _data_candidate_paths(filename):
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    return fh.read()
            except OSError:
                return None
    return None


def load_catalog_text() -> str:
    """Return the raw vendored catalog JSON text, wherever we run from.

    Order: the base64-embedded copy (the ``toshiba_cix_manager.py`` standalone),
    a PyInstaller bundle, then the packaged ``data/`` file. Mirrors
    :func:`toshiba_cix.webapp.load_html` so the same code backs the single-file
    build, the frozen ``.exe`` / AppImage and a dev checkout.
    """
    embedded = globals().get("EMBEDDED_CATALOG_JSON")
    if embedded:
        return embedded
    for path in _candidate_paths():
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return fh.read()
    raise FileNotFoundError(
        "emanager_catalog.json not found (looked in: "
        + ", ".join(_candidate_paths()) + ")")


def load_catalog(*, text: str | None = None, path: str | None = None,
                 cache: bool = True) -> "Catalog":
    """Load and index the catalog. Cached by default (it is read-only)."""
    global _CATALOG_CACHE
    if text is None and path is None and cache and _CATALOG_CACHE is not None:
        return _CATALOG_CACHE
    if path is not None:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    elif text is None:
        text = load_catalog_text()
    cat = Catalog(text)
    if text is None and path is None and cache:
        _CATALOG_CACHE = cat
    return cat


# --------------------------------------------------------------------------
# program / catalog views
# --------------------------------------------------------------------------
@dataclass
class Program:
    """One catalog program (MOF table) with per-field lookups."""

    key: str
    number: str | None
    name: str | None
    group_oid: str
    fields: list[dict]
    _by_name: dict[str, list[dict]] = dc_field(default_factory=dict)
    _by_col: dict[int, list[dict]] = dc_field(default_factory=dict)
    _dup_names: frozenset[str] = frozenset()

    @classmethod
    def from_entry(cls, key: str, entry: dict) -> "Program":
        fields = list(entry.get("fields", []))
        by_name: dict[str, list[dict]] = {}
        by_col: dict[int, list[dict]] = {}
        for f in fields:
            by_name.setdefault(f.get("name"), []).append(f)
            col = f.get("col")
            if col is not None:
                by_col.setdefault(col, []).append(f)
        dup = frozenset(n for n, fs in by_name.items() if n and len(fs) > 1)
        num = entry.get("number")
        return cls(
            key=key,
            number=str(num) if num is not None else None,
            name=entry.get("name"),
            group_oid=entry.get("group_oid", ""),
            fields=fields,
            _by_name=by_name,
            _by_col=by_col,
            _dup_names=dup,
        )

    def field(self, name: str) -> dict | None:
        """The field named ``name`` (the first, if the name is duplicated)."""
        fs = self._by_name.get(name)
        return fs[0] if fs else None

    def fields_named(self, name: str) -> list[dict]:
        return list(self._by_name.get(name, []))

    def field_by_column(self, col: int) -> dict | None:
        """The field at column ``col`` — only when that column is unambiguous.

        Many programs reuse a column number (50 of 186), and ``col`` is often
        ``null``, so this returns ``None`` rather than guess when more than one
        field claims the column.
        """
        fs = self._by_col.get(col)
        return fs[0] if fs and len(fs) == 1 else None

    def writable_fields(self) -> list[dict]:
        return [f for f in self.fields if f.get("access") == "rw"]

    def field_key(self, fld: dict) -> str:
        """A per-row-unique key for a field.

        The field name, unless the program reuses that name across *different*
        OIDs — then the distinguishing OID suffix is appended so two columns
        never collapse onto one row key. (Every duplicate name in the shipped
        catalog is an identical-OID entry, so both halves of such a pair map to
        the same key, which is correct — they are the same field.)
        """
        oid = fld.get("oid", "")
        name = fld.get("name") or f"oid_{oid.rsplit('.', 1)[-1]}"
        if name in self._dup_names:
            suffix = oid[len(ENTERPRISE_ROOT) + 1:] if oid.startswith(
                ENTERPRISE_ROOT) else oid
            return f"{name}#{suffix}"
        return name


class Catalog:
    """Loaded, indexed eManager catalog.

    Construction indexes the catalog three ways: by catalog key, by program
    number/name, and by full field OID (for longest-prefix attribution of an
    instance OID). All lookups are O(1)-ish; attribution strips arcs.
    """

    def __init__(self, text: str):
        self._raw: dict = json.loads(text)
        self.version = "re-" + hashlib.sha256(
            text.encode("utf-8")).hexdigest()[:12]
        self.programs: dict[str, Program] = {}
        self._by_number: dict[str, list[str]] = {}
        self._by_name: dict[str, list[str]] = {}
        self.by_oid: dict[str, tuple[str, dict]] = {}
        for key, entry in self._raw.items():
            prog = Program.from_entry(key, entry)
            self.programs[key] = prog
            if prog.number:
                self._by_number.setdefault(prog.number, []).append(key)
            if prog.name:
                self._by_name.setdefault(prog.name, []).append(key)
            for f in prog.fields:
                oid = f.get("oid")
                if oid:
                    # First writer wins on the rare exact-OID collision; the
                    # overlap set is tiny and in an obscure sub-tree.
                    self.by_oid.setdefault(oid, (key, f))
        # Per-call override hook (set_enum_labels); empty until a caller installs
        # one. The bundled labels below are the always-on base layer.
        self._enum_labels: dict[str, dict[int, str]] = {}
        self._bundled_enum_labels: dict[str, dict[int, str]] = \
            self._load_bundled_enum_labels()
        self._menu_by_number: dict[str, dict] = self._load_bundled_menus()

    # -- bundled annotations (enum labels + eManager menu areas) -----------
    @staticmethod
    def _load_bundled_enum_labels() -> dict[str, dict[int, str]]:
        text = _load_data_text(ENUM_LABELS_FILENAME, "EMBEDDED_ENUM_LABELS_JSON")
        if not text:
            return {}
        try:
            raw = json.loads(text)
        except ValueError:
            return {}
        out: dict[str, dict[int, str]] = {}
        for oid, mapping in raw.items():
            sub: dict[int, str] = {}
            for k, label in (mapping or {}).items():
                try:
                    sub[int(k)] = label
                except (TypeError, ValueError):
                    continue
            if sub:
                out[str(oid)] = sub
        return out

    @staticmethod
    def _load_bundled_menus() -> dict[str, dict]:
        text = _load_data_text(PROGRAM_MENUS_FILENAME, "EMBEDDED_PROGRAM_MENUS_JSON")
        if not text:
            return {}
        try:
            raw = json.loads(text)
        except ValueError:
            return {}
        by_number = raw.get("by_number") if isinstance(raw, dict) else None
        return by_number if isinstance(by_number, dict) else {}

    # -- counts ------------------------------------------------------------
    @property
    def program_count(self) -> int:
        return len(self.programs)

    @property
    def field_count(self) -> int:
        return sum(len(p.fields) for p in self.programs.values())

    @property
    def writable_count(self) -> int:
        return sum(len(p.writable_fields()) for p in self.programs.values())

    def summary(self) -> dict:
        return {
            "catalog_version": self.version,
            "programs": self.program_count,
            "fields": self.field_count,
            "writable": self.writable_count,
        }

    # -- program lookup ----------------------------------------------------
    def program(self, ident) -> Program | None:
        """Look a program up by catalog key, program number, or name."""
        if ident is None:
            return None
        ident = str(ident)
        if ident in self.programs:
            return self.programs[ident]
        for index in (self._by_number, self._by_name):
            keys = index.get(ident)
            if keys:
                return self.programs[keys[0]]
        return None

    def programs_for(self, idents: Iterable) -> list[Program]:
        out: list[Program] = []
        seen: set[str] = set()
        for ident in idents:
            p = self.program(ident)
            if p and p.key not in seen:
                seen.add(p.key)
                out.append(p)
        return out

    # -- field / OID -------------------------------------------------------
    def field(self, program_ident, field_name: str) -> dict | None:
        p = self.program(program_ident)
        return p.field(field_name) if p else None

    def field_for_oid(self, oid: str) -> dict | None:
        hit = self.by_oid.get(oid)
        return hit[1] if hit else None

    def instance_oid(self, field_or_oid, index) -> str:
        """Build the exact instance OID ``<field oid>.<index>``.

        ``field_or_oid`` is a field dict or its column OID; ``index`` is the
        instance tail as it was read (a dotted string like ``"1.3.50.48.48"``,
        a tuple of arcs, or ``""`` / ``None`` / ``"0"`` for a scalar). This is
        the inverse of :meth:`attribute_oid`.
        """
        base = field_or_oid["oid"] if isinstance(field_or_oid, dict) \
            else str(field_or_oid)
        base = base.rstrip(".")
        if index is None or index == "":
            return base
        if isinstance(index, (list, tuple)):
            index = ".".join(str(a) for a in index)
        return f"{base}.{str(index).lstrip('.')}"

    def attribute_oid(self, oid: str) -> tuple[str, dict, str] | None:
        """Attribute an instance OID to ``(program key, field, index tail)``.

        Longest-prefix match: the field whose column OID is the longest prefix
        of ``oid`` owns it; the remaining arcs are the instance tail. Returns
        ``None`` if no catalog field matches (unknown program/column).
        """
        parts = oid.split(".")
        for cut in range(len(parts), 0, -1):
            cand = ".".join(parts[:cut])
            hit = self.by_oid.get(cand)
            if hit:
                return hit[0], hit[1], ".".join(parts[cut:])
        return None

    # -- type / writability ------------------------------------------------
    @staticmethod
    def is_writable(fld: dict) -> bool:
        return fld.get("access") == "rw"

    @staticmethod
    def is_key(fld: dict) -> bool:
        return bool(fld.get("key"))

    # -- value decode / encode --------------------------------------------
    def decode_field_value(self, fld: dict, value: Value):
        """Render a wire :class:`Value` for the backup, honouring the field's
        syntax where the raw wire type would mislead.

        The wire type is trusted first (so an INTEGER-declared field that the
        agent actually returns as an OCTET digit string round-trips byte-for-
        byte on restore). The one syntax that needs help is ``IpAddress`` — its
        four bytes are not printable — which is rendered dotted-quad.
        """
        if value is None:
            return MISSING
        if value.is_missing or value.kind == "endofmib":
            return MISSING
        if fld.get("syntax") == "IpAddress" and value.kind == "octet" \
                and len(value.raw) == 4:
            return ".".join(str(b) for b in value.raw)
        return decode_value(value)

    def encode_field_value(self, fld: dict, value) -> tuple[str, bytes]:
        """Encode a stored backup value back to a ``(ber_type, value TLV)`` for
        a restore SET.

        Faithful to how the value was read: a stored ``int`` is written as an
        INTEGER, a stored ``str`` as an OCTET STRING (the pcap-proven path —
        this is how eManager writes station names, extensions and the digit
        strings the CIX uses for most numeric fields). ``ber_type`` is reported
        so the UI/CLI can flag anything other than the proven OCTET-STRING path
        for the first supervised live write.
        """
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, int):
            return "INTEGER", ber_integer(value)
        return "OCTET STRING", ber_octet(str(value))

    @staticmethod
    def wire_type_proven(fld: dict, value) -> bool:
        """True when the planned SET uses the pcap-proven OCTET-STRING-of-text
        path; False for INTEGER / IpAddress / Gauge32 writes, which are
        catalog-derived and await a supervised live write to confirm."""
        if isinstance(value, bool) or isinstance(value, int):
            return False
        return fld.get("syntax") != "IpAddress"

    # -- enum labels (hook; populated by a later UX-RE deliverable) --------
    def set_enum_labels(self, labels: dict) -> None:
        """Install an ``{oid: {raw_int: label}}`` **override** map.

        The reverse-engineered labels already ship bundled (see
        :meth:`enum_label`); this installs per-OID overrides that win over the
        bundle — for a site that renames a value, or a future catalog revision.
        Keys are normalised so an ``{raw: label}`` sub-map accepts int or str.
        """
        norm: dict[str, dict[int, str]] = {}
        for oid, mapping in (labels or {}).items():
            sub: dict[int, str] = {}
            for raw, label in mapping.items():
                try:
                    sub[int(raw)] = label
                except (TypeError, ValueError):
                    continue
            norm[str(oid)] = sub
        self._enum_labels = norm

    def enum_label(self, fld: dict, raw) -> str | None:
        """Human label for an EnumeratedINTEGER raw value, or ``None``.

        A per-call override installed with :meth:`set_enum_labels` wins; the
        bundled labels reverse-engineered from the MOF are the base layer, so
        787 enumerated fields resolve out of the box with no setup.
        """
        oid = fld.get("oid")
        try:
            r = int(raw)
        except (TypeError, ValueError):
            return None
        sub = self._enum_labels.get(oid)
        if sub and r in sub:
            return sub[r]
        sub = self._bundled_enum_labels.get(oid)
        if sub and r in sub:
            return sub[r]
        return None

    def enum_values(self, fld: dict) -> dict[int, str] | None:
        """The full ``{raw: label}`` map for an enumerated field, else ``None``.

        Override entries (if any) shadow the bundled map; the frontend uses this
        to render a dropdown of the allowed values for a writable enum field.
        """
        oid = fld.get("oid")
        merged: dict[int, str] = {}
        base = self._bundled_enum_labels.get(oid)
        if base:
            merged.update(base)
        over = self._enum_labels.get(oid)
        if over:
            merged.update(over)
        return merged or None

    # -- menu area (eManager grouping) -------------------------------------
    def menu_info(self, program_ident) -> dict:
        """eManager menu placement for a program: ``{area, menu_path, label}``.

        Resolved from the vendored ``program_menus.json`` by program number.
        The 31 internal MIB tables eManager never exposed as a program (null
        number — licensing, SNMP/FTP middleware, status trees) get a derived
        area so they are still reachable and grouped rather than orphaned.
        """
        prog = self.program(program_ident)
        if prog is None:
            return {"area": "Advanced", "menu_path": "", "label": str(program_ident)}
        if prog.number and prog.number in self._menu_by_number:
            info = self._menu_by_number[prog.number]
            return {"area": info.get("area") or "Advanced",
                    "menu_path": info.get("menu_path") or "",
                    "label": info.get("label") or prog.name or prog.number}
        return {"area": self._derived_area(prog),
                "menu_path": "", "label": prog.name or prog.key}

    def menu_area(self, program_ident) -> str:
        return self.menu_info(program_ident)["area"]

    @staticmethod
    def _derived_area(prog: "Program") -> str:
        """Area for a program the eManager menu map does not name (null number).

        Keyed off the field OID subtree so licensing, middleware and the status
        trees land somewhere sensible instead of a generic bucket.
        """
        g = prog.group_oid or ""
        root = ENTERPRISE_ROOT + "."
        if g.startswith(root):
            tail = g[len(root):]
            top = tail.split(".", 1)[0]
            if top == "10":
                return "Licensing"
            if top in ("2", "5", "6", "8"):
                return "Maintenance"
            if top in ("4",):
                return "System"
        key = (prog.key or "").lower()
        if "ftp" in key or "community" in key or "middleware" in key:
            return "Networking"
        if "license" in key:
            return "Licensing"
        return "Advanced"


__all__ = [
    "CATALOG_FILENAME", "ENUM_LABELS_FILENAME", "PROGRAM_MENUS_FILENAME",
    "MENU_AREA_ORDER", "Catalog", "Program",
    "load_catalog", "load_catalog_text",
]
