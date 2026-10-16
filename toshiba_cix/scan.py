"""High-level Toshiba Strata CIX reader: walk the MIB, build structured data.

:class:`CIXReader` is the importable core. It owns no I/O policy beyond the
SNMP client it is handed, so it unit-tests against captured varbinds and runs
unchanged on a Raspberry Pi RSM or inside a Conduit worker.

Flow
----
1. GETNEXT-walk the whole Toshiba enterprise subtree (read-only).
2. Classify every varbind by OID shape into: system scalars (``.7``),
   equipment table (``.1.1.1``), or program data (``.3``).
3. Promote what the capture proves — the station directory (Program 1200),
   network/FTP credentials (``.2.3.1.1``), system numbering (Program 579),
   key assignments (Program 205) — into named fields, and attach every other
   per-station program cell to its station by DN. Nothing is discarded:
   unclassified cells keep their raw OID in ``raw_programs`` / ``raw_unknown``.
4. Flag factory-default security postures (community string, FTP creds).

The result is a plain ``dict`` ready for ``json.dumps`` and for
:mod:`toshiba_cix.report`.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from . import decode as D
from .snmp import SnmpError, SnmpV1, Value


# Programs the capture shows are per-station detail. They attach to a station
# that Program 1200 (the authoritative directory) already created; a row whose
# DN has no 1200 entry is kept as an orphan in raw_programs rather than
# inventing a station. Undocumented programs never create stations at all.
PER_STATION_PROGRAMS = {"200", "204", "205", "207", "214", "220", "1322"}

# Top-level branches walked whole in CORE scope, and the ``.3`` programs that
# hold everything we decode or attach (station directory + per-station detail,
# system numbering, network/FTP). A CORE read skips the hundreds of other
# programs, so it finishes in a fraction of the time of a full ALL read while
# still capturing every documented structure.
CORE_TOP_BRANCHES = ("1", "7")                       # equipment, system
CORE_PROGRAMS = ("2", "200", "204", "205", "207",    # 2 = network/FTP table
                 "214", "220", "579", "1200", "1322")


class CIXReader:
    def __init__(self, client: SnmpV1, *, logger: logging.Logger | None = None,
                 max_oids: int = 200000, strategy: str = "bulk",
                 width: int = 10, scope: str = "all",
                 keep_raw_walk: bool = False, enrich: bool = True,
                 catalog=None, max_seconds: float | None = None):
        self.client = client
        self.log = logger or logging.getLogger(__name__)
        # Optional wall-clock budget for the whole walk: a guard so a huge or
        # non-terminating subtree (``--scope all`` against a big CIX) cannot run
        # forever. ``None`` = unbounded (the default; behaviour unchanged).
        self.max_seconds = max_seconds
        # "all" (whole tree), "core" (fast), or a catalog-driven scope such as a
        # feature group (trunks/groups/voicemail/licensing/stations/phantom) or
        # a menu-area name — resolved against the catalog, falling back to a
        # whole-tree walk when the catalog is unavailable (e.g. the lean build).
        self.scope = scope
        self.max_oids = max_oids
        self.strategy = strategy      # "bulk" (fast, batched) or "serial"
        self.width = width            # cursors per GETNEXT PDU in bulk mode
        # Build the named, menu-grouped program_views from the walk (the
        # frontend contract). Off in the lean reader build, where the catalog
        # and enrich modules are not bundled.
        self._enrich = enrich
        self._catalog = catalog       # cached across the scope + enrich passes
        self.varbinds: list[tuple[str, Value]] = []
        # When True, the full flat (oid, value) walk is attached to the result
        # as doc["raw_oid_walk"]. Off by default so the CLI/adapter docs stay
        # lean; the web app turns it on so a backup export can include the raw
        # walk alongside the structured JSON and the report.
        self.keep_raw_walk = keep_raw_walk

    # -- public ------------------------------------------------------------
    def read(self) -> dict:
        """Walk the device and return the full structured document."""
        varbinds, walk_error = self._collect()
        self.varbinds = varbinds
        records = [self._classify(oid, val) for oid, val in varbinds]
        doc = self._build(records)
        doc["device"] = {
            "ip": self.client.host,
            "port": self.client.port,
            "community": self.client.community,
            "enterprise_root": D.ENTERPRISE_ROOT,
            "read_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "oids_read": len(varbinds),
            "scope": self.scope,
            "walk_error": walk_error,
        }
        doc["security_findings"] = self._security_findings(doc)
        # Named, menu-grouped program views — the stable frontend contract.
        doc["program_views"] = self._program_views(varbinds)
        if self.keep_raw_walk:
            doc["raw_oid_walk"] = [
                {"oid": oid, "value": D.decode_value(val)}
                for oid, val in varbinds
            ]
        return doc

    def _program_views(self, varbinds) -> dict:
        """Catalog-driven enrichment; empty when the catalog is unavailable."""
        if self._enrich:
            try:
                # Lazy + guarded: in the lean reader build these submodules are
                # not bundled, so the names stay undefined and we degrade to
                # empty views instead of failing the read.
                from .enrich import build_program_views
                from .catalog import load_catalog
                cat = self._catalog or load_catalog()
                self._catalog = cat
                return build_program_views(varbinds, cat)
            except Exception as exc:  # noqa: BLE001
                self.log.debug("program_views unavailable: %r", exc)
        return {"programs": [], "menu_areas": [], "feature_views": [],
                "uncataloged": [],
                "stats": {"programs": 0, "rows": 0, "cells": 0,
                          "named_cells": 0, "raw_oid_cells": 0,
                          "uncataloged": 0}}

    # -- collection --------------------------------------------------------
    def _deadline(self) -> float | None:
        """A :func:`time.monotonic` instant to stop the walk, or ``None``."""
        return (time.monotonic() + self.max_seconds) if self.max_seconds else None

    def _collect(self) -> tuple[list[tuple[str, Value]], str | None]:
        deadline = self._deadline()
        preset = self._preset_roots()
        if preset is not None:
            return self._collect_roots(preset, deadline)
        if self.strategy == "serial":
            return self._collect_serial(deadline)
        try:
            return self._collect_bulk(deadline)
        except SnmpError as exc:
            # The batched path needs several round trips to enumerate before
            # it reads anything; if the device is flaky, fall back to the
            # dead-simple serial walk rather than returning nothing.
            self.log.warning("bulk collect failed (%s); falling back to serial",
                             exc)
            return self._collect_serial(deadline)

    def _dedup(self, pairs) -> list[tuple[str, Value]]:
        seen: set[str] = set()
        out = []
        for oid, val in pairs:
            if oid not in seen:
                seen.add(oid)
                out.append((oid, val))
        return out

    def _preset_roots(self) -> list[str] | None:
        """GETNEXT roots for a catalog-driven scope (feature group / menu area).

        Returns ``None`` for ``core`` / ``all`` (handled by the branch walkers)
        and for any scope the catalog cannot resolve — including the lean reader
        build, where the enrich/catalog submodules are not bundled, so the
        guarded import below leaves the names undefined and we fall back.
        """
        if self.scope in ("core", "all"):
            return None
        try:
            from .enrich import scope_roots
            from .catalog import load_catalog
            cat = self._catalog or load_catalog()
            self._catalog = cat
            roots = scope_roots(cat, self.scope)
            if roots:
                # Always include the identity branch so meta (software id,
                # chassis MAC) and security findings still populate.
                return list(roots) + [f"{D.ENTERPRISE_ROOT}.7"]
            return None
        except Exception as exc:  # noqa: BLE001
            self.log.debug("scope %r not catalog-resolvable: %r", self.scope, exc)
            return None

    def _collect_roots(self, roots: list[str], deadline: float | None = None
                       ) -> tuple[list[tuple[str, Value]], str | None]:
        """Walk an explicit list of subtree roots (catalog-driven scopes).

        Bulk when possible (many cursors), with a serial fallback so a flaky
        device degrades to a partial read rather than nothing."""
        if self.strategy != "serial":
            try:
                pairs = self.client.bulk_walk(roots, width=self.width,
                                              max_total=self.max_oids,
                                              deadline=deadline)
                return self._dedup(pairs), None
            except SnmpError as exc:
                self.log.warning("bulk scope walk failed (%s); serial fallback",
                                 exc)
        out: list[tuple[str, Value]] = []
        error: str | None = None
        for root in roots:
            try:
                out.extend(self.client.walk(root, max_oids=self.max_oids,
                                            deadline=deadline))
            except SnmpError as exc:
                self.log.warning("root %s interrupted: %s", root, exc)
                error = str(exc)
        return self._dedup(out), error

    def _collect_serial(self, deadline: float | None = None
                        ) -> tuple[list[tuple[str, Value]], str | None]:
        """Per-branch single-varbind GETNEXT walk — the simplest, most robust
        strategy. In ALL scope it walks every top-level branch (so the small
        ``.7`` identity branch is captured even if ``.3`` is huge); in CORE
        scope it walks only the documented branches/programs."""
        out: list[tuple[str, Value]] = []
        error: str | None = None
        if self.scope == "core":
            roots = [f"{D.ENTERPRISE_ROOT}.{b}" for b in CORE_TOP_BRANCHES]
            roots += [f"{D.ENTERPRISE_ROOT}.3.{p}" for p in CORE_PROGRAMS]
        else:
            roots = [f"{D.ENTERPRISE_ROOT}.{c}" for c in range(1, 11)]
        for root in roots:
            try:
                out.extend(self.client.walk(root, max_oids=self.max_oids,
                                            deadline=deadline))
            except SnmpError as exc:
                self.log.warning("branch %s interrupted: %s", root, exc)
                error = str(exc)
        return self._dedup(out), error

    def _collect_bulk(self, deadline: float | None = None
                      ) -> tuple[list[tuple[str, Value]], str | None]:
        """Enumerate program/column roots, then walk them all in parallel.

        Splitting each big table by column gives the batched walk many
        independent cursors. Enumeration itself is cheap (one round trip per
        discovered node)."""
        roots = self._discover_roots()
        pairs = self.client.bulk_walk(roots, width=self.width,
                                      max_total=self.max_oids,
                                      deadline=deadline)
        return self._dedup(pairs), None

    def _discover_roots(self) -> list[str]:
        """Build a disjoint set of subtree roots.

        ALL scope covers the whole MIB (every top-level branch; every program
        under ``.3`` split by column). CORE scope covers only the documented
        branches and programs — far fewer OIDs, so it is the fast option for a
        routine read. Under ``.3`` each program is descended through its
        singleton entry chain to the column dimension so columns walk
        concurrently."""
        root = D.ENTERPRISE_ROOT
        roots: list[str] = []
        if self.scope == "core":
            roots += [f"{root}.{b}" for b in CORE_TOP_BRANCHES]
            for prog in CORE_PROGRAMS:
                roots += self._roots_for_program(f"{root}.3", prog)
            return roots or [root]
        for child in self.client.enumerate_children(root):
            if child == "3":
                for prog in self.client.enumerate_children(f"{root}.3"):
                    roots += self._roots_for_program(f"{root}.3", prog)
            else:
                roots.append(f"{root}.{child}")
        # Defensive: if enumeration found nothing, fall back to whole-tree.
        return roots or [root]

    def _roots_for_program(self, base3: str, prog: str) -> list[str]:
        """Column-split roots for one ``.3.<prog>`` subtree (see _discover_roots)."""
        node = f"{base3}.{prog}"
        parent = node          # never fall back above the program itself
        children = self.client.enumerate_children(node)
        depth = 0
        while len(children) == 1 and depth < 24:
            parent = node
            node = f"{node}.{children[0]}"
            children = self.client.enumerate_children(node)
            depth += 1
        if children:
            # Fan-out level: one cursor per child (prefix) walks its rows.
            return [f"{node}.{c}" for c in children]
        # Singleton chain bottomed out at a leaf; GETNEXT never returns the
        # node it sits on, so walk from the PARENT prefix to capture the leaf.
        return [parent]

    # -- classification ----------------------------------------------------
    @staticmethod
    def _classify(oid: str, val: Value) -> dict:
        """Parse one OID into {section, program, col, index, oid, value}."""
        root = D.ENTERPRISE_ROOT + "."
        rec = {"oid": oid, "value": val, "section": "unknown"}
        if not oid.startswith(root):
            return rec
        tail = oid[len(root):]
        arcs = [int(a) for a in tail.split(".")]
        rec["tail"] = tuple(arcs)

        if arcs[0] == 7:
            rec["section"] = "system"
            rec["scalar_tail"] = tail
            return rec

        if arcs[0] == 1 and len(arcs) >= 4 and arcs[1] == 1 and arcs[2] == 1:
            rec["section"] = "equipment"
            rec["program"] = "EQUIP"
            rec["col"] = arcs[3]
            rec["index"] = D.parse_row_index(tuple(arcs[4:]))
            return rec

        if arcs[0] == 3:
            rest = arcs[1:]
            marker = _find_entry_marker(rest)
            if marker is not None:
                prog = ".".join(str(a) for a in rest[:marker]) or "3"
                after = rest[marker + 2:]
                rec["section"] = "program"
                rec["program"] = prog
                rec["col"] = after[0] if after else None
                rec["index"] = D.parse_row_index(tuple(after[1:]))
            else:
                # Scalar-style program (e.g. 579): .3.<prog>.<field>.<inst>
                rec["section"] = "program_scalar"
                rec["program"] = str(rest[0]) if rest else "3"
                rec["field"] = ".".join(str(a) for a in rest[1:])
            return rec

        return rec

    # -- build -------------------------------------------------------------
    def _build(self, records: list[dict]) -> dict:
        system: dict = {"status": {}, "numbering_config": {}}
        equipment: dict[str, dict] = {}
        stations: dict[str, dict] = {}
        network_access: dict[int, dict] = {}
        raw_programs: dict[str, dict] = {}
        raw_unknown: list[dict] = []

        # Per-station program rows are deferred to a second pass: Program 1200
        # (which creates the stations) sorts lexically *after* Programs 200/204
        # /205, so attaching in one pass would orphan every one of them.
        deferred: list[dict] = []
        for rec in records:
            sec = rec["section"]
            if sec == "system":
                self._add_system(system, rec)
            elif sec == "equipment":
                self._add_equipment(equipment, rec)
            elif sec == "program_scalar":
                self._add_program_scalar(system, raw_programs, rec)
            elif sec == "program":
                if rec["program"] in PER_STATION_PROGRAMS:
                    deferred.append(rec)
                else:
                    self._add_program(stations, network_access, raw_programs, rec)
            else:
                raw_unknown.append(
                    {"oid": rec["oid"],
                     "value": D.decode_value(rec["value"])}
                )

        # Second pass: attach per-station detail to the stations 1200 created.
        for rec in deferred:
            self._add_station_detail(stations, raw_programs, rec)

        return {
            "system": system,
            "equipment": [equipment[k] for k in sorted(equipment)],
            "stations": self._finalise_stations(stations),
            "network_access": [network_access[k] for k in sorted(network_access)],
            "raw_programs": raw_programs,
            "raw_unknown": raw_unknown,
            "stats": {
                "stations": len(stations),
                "equipment_rows": len(equipment),
                "network_access_rows": len(network_access),
                "raw_program_count": len(raw_programs),
                "raw_unknown_count": len(raw_unknown),
            },
        }

    # -- section writers ---------------------------------------------------
    @staticmethod
    def _add_system(system: dict, rec: dict) -> None:
        tail = rec["scalar_tail"]
        known = D.SYSTEM_SCALARS.get(tail)
        if known:
            name, hint = known
            value = D.decode_value(rec["value"], as_mac=(hint == "mac"))
            system[name] = value
        else:
            system["status"][tail] = D.decode_value(rec["value"])

    @staticmethod
    def _add_equipment(equipment: dict, rec: dict) -> None:
        idx = rec["index"]
        key = idx.key
        row = equipment.setdefault(key, {"index": list(idx.raw)})
        prog = D.PROGRAMS["EQUIP"]
        colname = prog.columns.get(rec["col"], f"col{rec['col']}")
        row[colname] = D.decode_value(rec["value"])

    @staticmethod
    def _add_program_scalar(system: dict, raw_programs: dict, rec: dict) -> None:
        prog = rec["program"]
        label = f"{prog}.{rec['field']}"
        value = D.decode_value(rec["value"])
        if prog == "579":
            system["numbering_config"][label] = value
        else:
            bucket = raw_programs.setdefault(prog, {"name": _prog_name(prog),
                                                    "rows": {}})
            bucket["rows"].setdefault("_scalar", {})[rec["field"]] = {
                "value": value, "oid": rec["oid"],
            }

    def _add_program(self, stations: dict, network_access: dict,
                     raw_programs: dict, rec: dict) -> None:
        """First-pass handler: network table, Program 1200, and raw passthrough.

        Per-station detail programs are NOT handled here — they are deferred
        to :meth:`_add_station_detail` so Program 1200 has already built the
        stations they attach to.
        """
        prog = rec["program"]
        col = rec["col"]
        idx = rec["index"]
        value = D.decode_value(rec["value"])

        # Network / FTP credential table (.3.2.3.1.1) — flat rows, no DN.
        if prog == "2.3":
            row_id = idx.raw[-1] if idx.raw else 0
            row = network_access.setdefault(row_id, {"index": row_id})
            colname = D.PROGRAMS["2.3"].columns.get(col, f"col{col}")
            row[colname] = value
            return

        # Station directory (Program 1200) — the authoritative DN list, and
        # the ONLY program allowed to create a station record.
        if prog == "1200" and idx.dn is not None:
            st = stations.setdefault(idx.dn, _new_station(idx.dn))
            colname = D.PROGRAMS["1200"].columns.get(col)
            if colname:
                st[colname] = value
                # Keep the exact source OID so the (stubbed) write path can
                # derive a precise SET target without re-reading the device.
                st["source_oids"][colname] = rec["oid"]
            else:
                st["flags"][f"col{col}"] = value
                st["source_oids"][f"col{col}"] = rec["oid"]
            return

        # Anything else (undocumented programs, DN-less rows) → raw passthrough
        # keyed by program, preserving the raw OID. Never invents a station.
        self._raw_cell(raw_programs, prog, idx.key, col, value, rec["oid"])

    def _add_station_detail(self, stations: dict, raw_programs: dict,
                            rec: dict) -> None:
        """Second-pass handler for the per-station detail programs."""
        prog = rec["program"]
        col = rec["col"]
        idx = rec["index"]
        value = D.decode_value(rec["value"])
        st = stations.get(idx.dn) if idx.dn is not None else None
        if st is None:
            # DN has no Program 1200 entry (or no DN) → keep as an orphan row
            # rather than fabricating a station. Nothing is lost.
            self._raw_cell(raw_programs, prog, idx.key, col, value, rec["oid"])
            return
        if prog == "205":
            # Key / button assignments: the trailing suffix is the key number.
            keynum = idx.suffix[0] if idx.suffix else 0
            entry = st["keys"].setdefault(keynum, {"key": keynum})
            entry[f"col{col}"] = value
            return
        detail = st["programs"].setdefault(
            prog, {"name": _prog_name(prog), "rows": {}}
        )
        subkey = "/".join(str(s) for s in idx.suffix) or "_"
        detail["rows"].setdefault(subkey, {})[f"col{col}"] = {
            "value": value, "oid": rec["oid"],
        }

    @staticmethod
    def _raw_cell(raw_programs: dict, prog: str, rowkey: str, col,
                  value, oid: str) -> None:
        bucket = raw_programs.setdefault(prog, {"name": _prog_name(prog),
                                                "rows": {}})
        bucket["rows"].setdefault(rowkey, {})[f"col{col}"] = {
            "value": value, "oid": oid,
        }

    @staticmethod
    def _finalise_stations(stations: dict) -> list[dict]:
        out = []
        for dn in sorted(stations, key=_dn_sort_key):
            st = stations[dn]
            st["keys"] = [st["keys"][k] for k in sorted(st["keys"])]
            out.append(st)
        return out

    # -- findings ----------------------------------------------------------
    @staticmethod
    def _security_findings(doc: dict) -> list[dict]:
        findings: list[dict] = []
        comm = doc["device"]["community"]
        if comm == "communityName":
            findings.append({
                "severity": "high",
                "code": "default_snmp_community",
                "detail": "SNMP community is the Toshiba factory default "
                          "'communityName'. Anyone on the LAN can read the "
                          "entire programming. Change it in eManager.",
            })
        for row in doc.get("network_access", []):
            user = row.get("username")
            pw = row.get("password")
            if user == "sysadmin" and pw == "wksi76dbga":
                findings.append({
                    "severity": "high",
                    "code": "default_ftp_credentials",
                    "detail": "SD-card FTP login is the Toshiba factory "
                              "default (user 'sysadmin' with the published "
                              "default password).",
                })
        return findings


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _find_entry_marker(arcs: list[int]) -> int | None:
    """Index of the first ``1,1`` table entry/column marker, else None."""
    for i in range(len(arcs) - 1):
        if arcs[i] == 1 and arcs[i + 1] == 1:
            return i
    return None


def _prog_name(prog: str) -> str:
    p = D.PROGRAMS.get(prog)
    return p.name if p else f"Program {prog} (undocumented)"


def _new_station(dn: str) -> dict:
    return {
        "dn": dn,
        "extension": None,
        "equipment_port": None,
        "type": None,
        "name": None,
        "flags": {},
        "keys": {},         # keynum -> {...}; finalised to a list
        "programs": {},     # prog -> {name, rows}
        "source_oids": {},  # colname -> exact source OID (for the write path)
    }


def _dn_sort_key(dn: str):
    return (0, int(dn)) if dn.isdigit() else (1, dn)


__all__ = ["CIXReader"]
