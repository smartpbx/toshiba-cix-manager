#!/usr/bin/env python3
"""Generate ``toshiba_cix/data/ui_schema.json`` — the one static UI data file.

Switchroom renders 186 eManager programs with **zero hand-written forms**: the
engine and the React UI read the *same* generated schema for every label, enum
caption, control type, display number, archetype, danger flag and menu
placement, so they can never disagree (DESIGN_PLAN 2.1, 3.3/3.4, 10.2, 11-P0).

This tool is **build-time only** — it never ships in the lean stdlib reader,
the AppImage or the exe. It merges, for each catalog program:

* the field -> OID catalog           (``toshiba_cix/data/emanager_catalog.json``)
* reverse-engineered enum symbols    (``toshiba_cix/data/enum_labels.json``)
* eManager menu placement            (``toshiba_cix/data/program_menus.json`` +
                                       ``tools/re_artifacts/command_to_menu.json``)
* the ``.tbl`` UI controls + titles  (``tools/re_artifacts/tbl_program_headers.json``)
* feature-key labels                 (``tools/re_artifacts/feature_key_labels.csv``)
* the native title pool + help text   (``tools/re_artifacts/native_field_titles.txt``,
                                       ``native_possible_values.txt``)

layered with the hand-maintained ``tools/ui_overrides.json`` (archetype, tier,
danger, special layouts, primary fields, hard write-exclusions) and the
deterministic title-caser in :mod:`labels` (+ ``enum_label_overrides.json`` /
``binary_pairs.json``).

The output is written with ``sort_keys=True`` and no timestamp so a rebuild is
**byte-identical**; ``--check`` re-builds in memory and diffs against the
committed file (the CI freshness gate, alongside the amalgam / webui checks).

    python3 tools/build_ui_schema.py            # write the schema
    python3 tools/build_ui_schema.py --check     # fail if the committed file is stale
    python3 tools/build_ui_schema.py --stdout     # print, write nothing
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from labels import enum_caption, humanize_name  # noqa: E402

DATA_DIR = os.path.join(ROOT, "toshiba_cix", "data")
RE_DIR = os.path.join(HERE, "re_artifacts")
OUT_PATH = os.path.join(DATA_DIR, "ui_schema.json")

SCHEMA_VERSION = "1"
ENTERPRISE_ROOT = "1.3.6.1.4.1.186.1.22"

# eManager menu areas in the order the UI shows them (mirrors catalog.MENU_AREA_ORDER).
MENU_AREA_ORDER = (
    "System", "Station", "Trunk", "IP-Telephony", "Networking", "LCR/DR",
    "External Devices", "Attendant", "Utilities", "Miscellaneous",
    "Licensing", "Maintenance", "Advanced",
)

# .tbl ui_type -> the UI control the frontend renders (DESIGN_PLAN 3.4). A key
# field is read-only in the form regardless; a recognised binary pair upgrades
# "select" to "segmented" after the fact.
_UI_TYPE_CONTROL = {
    "TEXTFIELD": "text", "KEYTEXTFIELD": "text",
    "NUMERALFIELD": "number", "KEYNUMERALFIELD": "number",
    "SELECT_RANGE": "number", "KEYSELECT_RANGE": "number", "LIST_RANGE": "number",
    "SELECT_OPTION": "select", "KEYSELECT_OPTION": "select",
    "LIST_OPTION": "multiselect",
    "RADIOBUTTON": "radio",
    "PASSWORD": "password",
    "CHECKBOX": "checkbox",
    "IPADDRESS": "ipaddress",
    "EQUIPMENTNUM": "port", "KEYEQUIPMENTNUM": "port",
    "CARDSLOTNUM": "port", "KEYCARDSLOTNUM": "port",
    "SETTIME": "time",
    "SELECT_DISABLED": "action",
    "LABELONLY": "readonly", "NONE": "readonly",
    "HIDDEN": "hidden",
}

_SECRET_HINTS = ("passw", "pwd", "secret")


# --------------------------------------------------------------------------
# input loading
# --------------------------------------------------------------------------
def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_inputs() -> dict:
    """Load every merge input as text + parsed form, with a hash of each."""
    files = {
        "emanager_catalog.json": os.path.join(DATA_DIR, "emanager_catalog.json"),
        "enum_labels.json": os.path.join(DATA_DIR, "enum_labels.json"),
        "program_menus.json": os.path.join(DATA_DIR, "program_menus.json"),
        "tbl_program_headers.json": os.path.join(RE_DIR, "tbl_program_headers.json"),
        "command_to_menu.json": os.path.join(RE_DIR, "command_to_menu.json"),
        "feature_key_labels.csv": os.path.join(RE_DIR, "feature_key_labels.csv"),
        "native_field_titles.txt": os.path.join(RE_DIR, "native_field_titles.txt"),
        "ui_overrides.json": os.path.join(HERE, "ui_overrides.json"),
        "enum_label_overrides.json": os.path.join(HERE, "enum_label_overrides.json"),
        "binary_pairs.json": os.path.join(HERE, "binary_pairs.json"),
        "task_menu.json": os.path.join(HERE, "task_menu.json"),
    }
    text = {name: _read_text(path) for name, path in files.items()}
    hashes = {name: _sha(text[name]) for name in sorted(text)}
    return {
        "catalog": json.loads(text["emanager_catalog.json"]),
        "catalog_version": "re-" + hashlib.sha256(
            text["emanager_catalog.json"].encode("utf-8")).hexdigest()[:12],
        "enum_labels": json.loads(text["enum_labels.json"]),
        "program_menus": (json.loads(text["program_menus.json"]) or {}).get("by_number", {}),
        "tbl": json.loads(text["tbl_program_headers.json"]),
        "command_to_menu": json.loads(text["command_to_menu.json"]),
        "feature_keys": list(csv.DictReader(
            text["feature_key_labels.csv"].splitlines())),
        "title_pool": [l.rstrip() for l in
                       text["native_field_titles.txt"].splitlines() if l.strip()],
        "overrides": json.loads(text["ui_overrides.json"]),
        "enum_overrides": {k: v for k, v in
                           json.loads(text["enum_label_overrides.json"]).items()
                           if not k.startswith("_")},
        "binary_pairs": json.loads(text["binary_pairs.json"]).get("pairs", []),
        "task_menu": json.loads(text["task_menu.json"]),
        "source_hashes": hashes,
    }


# --------------------------------------------------------------------------
# per-program helpers
# --------------------------------------------------------------------------
def _derived_area(group_oid: str, key: str) -> str:
    """Menu area for a program eManager never surfaced (mirrors catalog)."""
    g = group_oid or ""
    root = ENTERPRISE_ROOT + "."
    if g.startswith(root):
        top = g[len(root):].split(".", 1)[0]
        if top == "10":
            return "Licensing"
        if top in ("2", "5", "6", "8"):
            return "Maintenance"
        if top == "4":
            return "System"
    k = (key or "").lower()
    if "ftp" in k or "community" in k or "middleware" in k:
        return "Networking"
    if "license" in k:
        return "Licensing"
    return "Advanced"


def _menu_for(number, key, group_oid, program_menus, cmd_by_number) -> dict:
    """{area, menu_path, label, page_id} for a program."""
    num = str(number) if number is not None else None
    if num and num in cmd_by_number:
        c = cmd_by_number[num]
        area = (c.get("menu_path") or "").split(" - ", 1)[0] or "Advanced"
        return {"area": area, "menu_path": c.get("menu_path") or "",
                "label": c.get("program_label") or num,
                "page_id": c.get("page_id") or ""}
    if num and num in program_menus:
        m = program_menus[num]
        return {"area": m.get("area") or "Advanced",
                "menu_path": m.get("menu_path") or "",
                "label": m.get("label") or num, "page_id": ""}
    return {"area": _derived_area(group_oid, key),
            "menu_path": "", "label": key, "page_id": ""}


def _enum_values(field, enum_labels, enum_overrides):
    """{raw_str: caption} for an enumerated field, raw-ascending, else None."""
    oid = field.get("oid")
    raw = enum_labels.get(oid)
    if not raw:
        return None
    out = {}
    for rk in sorted(raw, key=lambda r: int(r) if str(r).lstrip("-").isdigit() else r):
        out[str(rk)] = enum_caption(raw[rk], overrides=enum_overrides)
    return out or None


def _binary_pair(field, enum_labels, binary_pairs, enum_overrides):
    """A {on,off}+captions descriptor when the field's two symbols match a pair."""
    oid = field.get("oid")
    raw = enum_labels.get(oid)
    if not raw or len(raw) != 2:
        return None
    sym_to_raw = {v: int(k) if str(k).lstrip("-").isdigit() else k
                  for k, v in raw.items()}
    syms = set(sym_to_raw)
    for pair in binary_pairs:
        on_s, off_s = pair.get("on"), pair.get("off")
        if syms == {on_s, off_s}:
            return {
                "on": {"raw": sym_to_raw[on_s],
                       "label": enum_caption(on_s, overrides=enum_overrides)},
                "off": {"raw": sym_to_raw[off_s],
                        "label": enum_caption(off_s, overrides=enum_overrides)},
            }
    return None


def _program_title(tbl, fallback_name) -> str:
    """A program's screen title: the native ``.tbl`` title, else the name.

    An ALL-CAPS native title (``STATION DATA``) is title-cased; a mixed-case
    one (``CTX/CIX Date & Time``) is kept verbatim so acronyms survive.
    """
    if tbl and tbl.get("title"):
        t = tbl["title"].strip()
        return t.title() if t.isupper() else t
    return humanize_name(fallback_name)


def _control(field, ui_type, is_binary) -> str:
    if (field.get("access") or "") == "r":
        base = _UI_TYPE_CONTROL.get(ui_type or "", None)
        if base in ("action", "hidden"):
            return base
        return "readonly"
    if is_binary:
        return "segmented"
    if ui_type and ui_type in _UI_TYPE_CONTROL:
        return _UI_TYPE_CONTROL[ui_type]
    # No .tbl control: fall back on the catalog syntax (DESIGN_PLAN 3.4).
    syntax = field.get("syntax")
    if syntax == "EnumeratedINTEGER":
        return "select"
    if syntax in ("INTEGER", "Gauge32"):
        return "number"
    if syntax == "IpAddress":
        return "ipaddress"
    return "text"


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------
def build_schema(inp: dict) -> dict:
    catalog = inp["catalog"]
    enum_labels = inp["enum_labels"]
    enum_overrides = inp["enum_overrides"]
    binary_pairs = inp["binary_pairs"]
    overrides = inp["overrides"]
    program_menus = inp["program_menus"]
    cmd_by_number = {str(c["program"]): c for c in inp["command_to_menu"]
                     if c.get("program") is not None}
    tbl_by_number = {str(t["program"]): t for t in inp["tbl"]
                     if t.get("program") is not None}

    ov_arch = overrides.get("archetype", {})
    ov_special = overrides.get("special_layout", {})
    ov_danger = set(overrides.get("danger", []))
    ov_tier = overrides.get("tier", {})
    ov_primary = overrides.get("primary_fields", {})
    ov_display = overrides.get("display_no", {})
    ov_never = set(overrides.get("never_write", []))
    ov_level0 = set(overrides.get("level0", []))
    ov_field_meta = overrides.get("field_meta", {})

    programs: dict[str, dict] = {}
    enum_field_total = 0

    for key in sorted(catalog):
        entry = catalog[key]
        number = entry.get("number")
        name = entry.get("name")
        group_oid = entry.get("group_oid", "")
        cat_fields = entry.get("fields", [])
        tbl = tbl_by_number.get(str(number)) if number is not None else None
        tbl_order = {}
        tbl_type = {}
        if tbl:
            for i, f in enumerate(tbl.get("ui_fields", [])):
                tbl_type[f.get("name")] = f.get("ui_type")
                tbl_order.setdefault(f.get("name"), i)

        # Display order: .tbl order where known, catalog order otherwise.
        def _order_key(f):
            n = f.get("name")
            return (0, tbl_order[n]) if n in tbl_order else (1, 0)

        ordered = sorted(enumerate(cat_fields), key=lambda it: (_order_key(it[1]), it[0]))
        disp_over = ov_display.get(key, {})
        field_meta = ov_field_meta.get(key, {})

        fields = []
        key_fields = []
        seg = 0
        for _, f in ordered:
            fname = f.get("name") or ""
            ui_type = tbl_type.get(fname)
            is_enum = f.get("syntax") == "EnumeratedINTEGER"
            if is_enum:
                enum_field_total += 1
            enum_values = _enum_values(f, enum_labels, enum_overrides) if is_enum else None
            binary = (_binary_pair(f, enum_labels, binary_pairs, enum_overrides)
                      if is_enum else None)
            is_key = bool(f.get("key"))
            if is_key:
                key_fields.append(fname)
            display_no = disp_over.get(fname) or f"{seg:02d}"
            seg += 1
            cell = {
                "name": fname,
                "display_no": display_no,
                "title": humanize_name(fname),
                "oid": f.get("oid"),
                "col": f.get("col"),
                "syntax": f.get("syntax"),
                "enc": f.get("enc"),
                "access": f.get("access"),
                "len": f.get("len"),
                "key": is_key,
                "writable": f.get("access") == "rw" and key not in ov_never,
                "ui_type": ui_type,
                "control": _control(f, ui_type, bool(binary)),
                "is_enum": is_enum,
                "is_binary_pair": bool(binary),
                "is_secret": any(h in fname.lower() for h in _SECRET_HINTS),
            }
            if enum_values:
                cell["enum_values"] = enum_values
            if binary:
                cell["binary_pair"] = binary
            # Hand-maintained grouping + plain-English description for the
            # single-record form pages (e.g. 105 System settings). Ungrouped
            # fields fall back to "Advanced" in the UI.
            meta = field_meta.get(fname)
            if meta:
                if meta.get("group"):
                    cell["group"] = meta["group"]
                if meta.get("desc"):
                    cell["desc"] = meta["desc"]
            fields.append(cell)

        row_keyed = bool(key_fields)
        archetype = ov_arch.get(key) or ("grid_record" if row_keyed else "form")
        danger = key in ov_danger
        tier = ov_tier.get(key, 3 if danger else 1)
        menu = _menu_for(number, key, group_oid, program_menus, cmd_by_number)

        if key in ov_primary:
            primary = [p for p in ov_primary[key]
                       if any(c["name"] == p for c in fields)]
        else:
            primary = [c["name"] for c in fields
                       if c["writable"] and not c["key"]
                       and c["control"] not in ("hidden", "readonly")][:4]
        primary_set = set(primary)
        for c in fields:
            c["primary"] = c["name"] in primary_set

        pv = {
            "catalog_key": key,
            "program_number": str(number) if number is not None else None,
            "program_name": name,
            "title": _program_title(tbl, name or key),
            "description": (tbl.get("description") if tbl else "") or "",
            "menu_area": menu["area"],
            "menu_path": menu["menu_path"],
            "label": menu["label"],
            "page_id": menu["page_id"],
            "archetype": archetype,
            "tier": tier,
            "danger": danger,
            "never_write": key in ov_never,
            "level0": key in ov_level0,
            "row_keyed": row_keyed,
            "key_fields": key_fields,
            "primary_fields": primary,
            "group_oid": group_oid,
            "field_count": len(fields),
            "fields": fields,
        }
        if key in ov_special:
            pv["special_layout"] = ov_special[key]
        programs[key] = pv

    menu_tree = _build_menu_tree(programs)
    task_tree = _build_task_tree(inp["task_menu"], programs)
    feature_keys = [{"code": r.get("feature_key_code", "").strip(),
                     "name": r.get("feature_name", "").strip()}
                    for r in inp["feature_keys"]
                    if r.get("feature_key_code")]

    # Action commands: catalog programs whose archetype is "action".
    actions = [{"catalog_key": k, "program_number": p["program_number"],
                "title": p["title"], "danger": p["danger"],
                "menu_area": p["menu_area"]}
               for k, p in sorted(programs.items())
               if p["archetype"] == "action"]

    counts = {
        "programs": len(programs),
        "fields": sum(p["field_count"] for p in programs.values()),
        "enum_fields": enum_field_total,
        "danger": sum(1 for p in programs.values() if p["danger"]),
        "special": sum(1 for p in programs.values() if "special_layout" in p),
        "grid_record": sum(1 for p in programs.values() if p["archetype"] == "grid_record"),
        "form": sum(1 for p in programs.values() if p["archetype"] == "form"),
        "actions": len(actions),
        "feature_keys": len(feature_keys),
        "menu_areas": len(menu_tree),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "catalog_version": inp["catalog_version"],
        "source_hashes": inp["source_hashes"],
        "counts": counts,
        "menu_area_order": list(MENU_AREA_ORDER),
        "menu_tree": menu_tree,
        "task_tree": task_tree,
        "programs": programs,
        "feature_keys": feature_keys,
        "actions": actions,
        "binary_pairs": [{"on": p["on"], "off": p["off"]}
                         for p in binary_pairs],
        "title_pool": inp["title_pool"],
    }


def _build_task_tree(task_menu: dict, programs: dict) -> list:
    """The hand-maintained task-first nav (Switchroom 2a) as validated data.

    Groups -> items; each item is either the Home entry (``kind: "home"``) or a
    set of real catalog programs grouped under one plain-English name. Every
    program key is validated against the built catalog so a typo fails the build
    rather than shipping a dead nav row. ``num`` is the first program's display
    number (what the menu shows secondary); anything not listed here stays
    reachable through Ctrl K search and the "All programs" footer link.
    """
    groups_out = []
    for g in task_menu.get("groups", []):
        items_out = []
        for it in g.get("items", []):
            title = it.get("title") or ""
            kind = it.get("kind", "program")
            if kind == "home":
                items_out.append({
                    "title": title, "icon": it.get("icon", "house"),
                    "kind": "home", "programs": [], "num": None,
                })
                continue
            prog_keys = list(it.get("programs", []))
            for k in prog_keys:
                if k not in programs:
                    raise ValueError(
                        f"task_menu.json: unknown program key {k!r} in item "
                        f"{title!r} — it is not in the catalog.")
            num = programs[prog_keys[0]]["program_number"] if prog_keys else None
            items_out.append({
                "title": title, "icon": it.get("icon", "dot"),
                "kind": "program", "programs": prog_keys, "num": num,
            })
        groups_out.append({"label": g.get("label"), "items": items_out})
    return groups_out


def _build_menu_tree(programs: dict) -> list:
    """Areas -> menu items -> programs, deterministic from menu placement.

    An item groups the programs that share a ``menu_path`` (eManager shows
    "Day Night Service (106,112,113)" as one entry spanning three programs);
    programs with no eManager menu entry collect under their derived area.
    """
    def _area_rank(area):
        return MENU_AREA_ORDER.index(area) if area in MENU_AREA_ORDER \
            else len(MENU_AREA_ORDER)

    areas: dict[str, dict] = {}
    for key in sorted(programs):
        p = programs[key]
        area = p["menu_area"]
        a = areas.setdefault(area, {})
        item_title = (p["menu_path"].split(" - ", 1)[1]
                      if " - " in p["menu_path"] else "") or p["label"]
        it = a.setdefault(p["menu_path"] or f"~{item_title}",
                          {"title": item_title, "menu_path": p["menu_path"],
                           "page_id": p["page_id"], "programs": [], "level0": True})
        it["programs"].append(key)
        it["level0"] = it["level0"] and p["level0"]

    out = []
    for area in sorted(areas, key=lambda a: (_area_rank(a), a)):
        items = []
        for mp in sorted(areas[area]):
            it = areas[area][mp]
            it["programs"] = sorted(it["programs"])
            items.append(it)
        out.append({"area": area, "items": items})
    return out


# --------------------------------------------------------------------------
# serialise / CLI
# --------------------------------------------------------------------------
def dumps(schema: dict) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed ui_schema.json is stale")
    ap.add_argument("--stdout", action="store_true",
                    help="print the schema to stdout and write nothing")
    ap.add_argument("--out", default=OUT_PATH, help="output path")
    args = ap.parse_args(argv)

    schema = build_schema(load_inputs())
    text = dumps(schema)

    if args.stdout:
        sys.stdout.write(text)
        return 0
    if args.check:
        if not os.path.exists(args.out):
            print(f"MISSING {args.out} — run: python3 tools/build_ui_schema.py",
                  file=sys.stderr)
            return 1
        current = _read_text(args.out)
        if current != text:
            print("STALE ui_schema.json — it does not match a fresh build.\n"
                  "  Run: python3 tools/build_ui_schema.py", file=sys.stderr)
            return 1
        print(f"ui_schema.json is fresh ({schema['counts']['programs']} programs, "
              f"{schema['counts']['fields']} fields).")
        return 0

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    c = schema["counts"]
    print(f"wrote {args.out}\n  {c['programs']} programs "
          f"({c['grid_record']} grid, {c['form']} form, {c['special']} special, "
          f"{c['actions']} action), {c['fields']} fields, "
          f"{c['enum_fields']} enum, {c['feature_keys']} feature keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
