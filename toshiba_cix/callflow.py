"""Call Flow adapter for the Toshiba Strata CIX — build the neutral routing graph.

Pure stdlib, no I/O. Consumes the ``program_views`` working copy (the enrich.py
contract: ``{"programs": [ {catalog_key, program_number, rows:[{cells:[...]}]} ]}``)
and emits the **frozen Call Flow contract** graph (callflow-port/CONTRACT.md
v1.0.0)::

    {version, entrypoints, nodes, edges, stats}

with the invariants that contract freezes:

  * Entrypoints are DIDs (program 309) **and** analog line / digital trunk
    groups (program 304 ILG). A group node carries its member physical ports
    (``ports`` array) with each port's equipment location.
  * Edge source/target fields are ``src``/``tgt`` verbatim (the ported layout.js
    is written against them).
  * **Never drop an edge.** A destination that cannot be resolved becomes an
    ``unknown`` node and is counted in ``stats.unresolved``.
  * Group / DID → answer-point edges carry the CIX time mode
    (``day`` / ``day2`` / ``night``) on ``condition``.

Resolution: CIX stores destinations as **literal dialed digit strings**, not
foreign keys. A ``…Destination`` string is matched against the DN-bearing tables
via :mod:`toshiba_cix.index` (``build_index_from_views`` → ``Index.lookup``),
with a fixed precedence over the owning tables (200 / 206 / 209 / 517 / 540 /
580) because CIX does not enforce one-object-per-number. Unmatched digits become
``external`` (off-system PSTN) or counted ``unknown`` nodes.

Honest gaps (CIX SNMP cannot express these — see DESIGN.md §3.1):
  * **No auto-attendant / IVR key-press menu.** A DID/DIT/line routed to DISA
    (destination type ``dISA``) draws a single terminal ``ivr_menu`` node; the
    actual digit→destination menu lives in the separate Stratagy voicemail
    device (serial, not SNMP) and is a v2 cross-device join.
  * **Day/night switch-over times are unparsed** (113/10113 raw octets). The
    graph shows the day/day2/night branches; it never invents a schedule.
  * **No live "current mode" flag** — all three mode branches are drawn equally.
"""

from __future__ import annotations

from .decode import MISSING, looks_like_port
from .index import build_index_from_views

CONTRACT_VERSION = "1.1.0"

# Program numbers of the routing tables this adapter reads. If none of the
# core four returned data the snapshot is almost certainly a CORE-only read
# (routing programs come only from a full / feature scan) — the caller shows
# "run a full scan" rather than an empty diagram.
ROUTING_PROGRAMS = ("309", "304", "310", "318")

# DN-owning tables in precedence order (mirrors UniqueExtension's
# one-object-per-number guarantee, which CIX does not enforce for digit
# strings): the first table that claims a DN owns it.
#   (program_number, owning DN field, neutral node kind, id prefix)
_OWNERS = (
    ("200", "stationDn", "extension", "ext"),
    ("206", "phDn", "extension", "ext"),
    ("209", "stationHuntPilotNumber", "ring_group", "rg"),
    ("517", "multipleCallingGroupPilotNumber", "ring_group", "rg"),
    ("540", "acdPilotDn", "queue", "acd"),
    ("580", "vmDataDN", "voicemail", "vm"),
)

# trunkSignaling (program 300 col 6) → neutral PortType.
_SIGNALING_PORT_TYPE = {
    "dID": "did", "lOOP": "loop_start", "gROUND": "ground_start",
    "tIE": "e_and_m", "lP": "loop_start", "sR": "analog_co", "aCU": "analog_co",
}
_ANALOG_PORT_TYPES = {"loop_start", "ground_start", "e_and_m", "analog_co", "did"}

# Flexible-button feature codes (program 205 col 3, `featureCode`) that make a
# station ring on incoming CO calls — the key-system inbound path on small
# Toshiba systems that have NO DID/DIT answer-point table. Codes are eManager's
# own flexible-button feature codes (feature_key_labels.csv in the eManager
# reverse-engineering catalog): 120=CO (individual line), 130=CO Line Group,
# 140=Pooled Line Key. featureParameter1 carries the referenced line / group /
# pool number. Nothing else is treated as a ring key, so no ring is invented.
_FK_CO_LINE = "120"        # featureParameter1 = CO line (trunk) number
_FK_CO_LINE_GROUP = "130"  # featureParameter1 = incoming line group (ILG) number
_FK_POOLED_LINE = "140"    # featureParameter1 = pooled line group number
_RING_KEY_CODES = (_FK_CO_LINE, _FK_CO_LINE_GROUP, _FK_POOLED_LINE)

# systemCallForwardType (500 col 4) → condition.
_CF_TYPE_CONDITION = {
    "busy": "busy", "noAnswer": "no_answer",
    "busyNoAnswer": "busy_no_answer", "dND": "dnd",
}
# systemCallForwardDayNightMode (500 col 3) → condition / label.
_CF_MODE = {"day": "day", "day2": "day2", "night": "night"}
# multipleCallingMembersDestCallType (518 col 5) → condition.
_RING_CADENCE = {"immediate": "immediate", "delay1": "delay1", "delay2": "delay2"}


def _s(cell) -> str:
    """A cell's human/string value, or ``""`` for missing / no-data."""
    if not cell:
        return ""
    raw = cell.get("raw_value")
    if raw is None or raw is MISSING:
        return ""
    dv = cell.get("display_value")
    if dv not in (None, ""):
        return str(dv)
    s = str(raw).strip()
    return "" if s in ("<no data>", "<MISSING>") else s


def _format_equipment(raw: str) -> str:
    """CIX equipment octet → ``cabinet/slot/circuit`` (e.g. ``1/3/4``).

    The reader decodes the OCTETSTRING to a 6-char cab/slot/ckt digit string
    (``decode.decode_octet``); render it as stripped ``c/s/k``. Anything that is
    not a clean 6-digit port id (a hex-fallback blob) returns ``""`` so the
    caller can flag it in the group ``meta`` rather than draw a fake location.
    """
    s = str(raw or "").strip()
    if not looks_like_port(s):
        return ""
    return f"{int(s[0:2])}/{int(s[2:4])}/{int(s[4:6])}"


class _Builder:
    """Assembles the neutral graph from a ``program_views`` working copy."""

    def __init__(self, program_views: dict):
        self.by_num: dict[str, list] = {}
        for pv in (program_views or {}).get("programs", []):
            num = pv.get("program_number")
            if num is not None:
                self.by_num.setdefault(str(num), pv)
        self.idx = build_index_from_views(program_views)
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.entrypoints: list[str] = []
        self._edge_seen: set = set()
        self._queue: list[str] = []
        self._expanded: set = set()
        self._dn_cache: dict[str, str | None] = {}
        # ILG group number → its entrypoint node id (lg:/tg:), filled by
        # build_groups so ring-by-key can wire a CO-line key to the right group.
        self._group_node_by_ilg: dict[str, str] = {}
        # Pooled-line-group number → the ILG group numbers that belong to it.
        self._ilgs_by_pool: dict[str, list[str]] = {}

    # -- row access --------------------------------------------------------
    def rows(self, num: str) -> list[dict]:
        """Program ``num`` as a list of ``{index, key, f: {field_name: cell}}``."""
        pv = self.by_num.get(num)
        if not pv:
            return []
        out = []
        for r in pv.get("rows", []):
            cells = {c.get("field_name"): c for c in r.get("cells", [])}
            out.append({"index": r.get("index"), "key": r.get("key"), "f": cells})
        return out

    @staticmethod
    def f(row: dict, name: str) -> str:
        return _s(row["f"].get(name))

    # -- node / edge registry ---------------------------------------------
    def add_node(self, node_id: str, kind: str, num: str, label: str,
                 meta: str = "", ports: list | None = None) -> str:
        if node_id not in self.nodes:
            node = {"id": node_id, "kind": kind, "num": num or "",
                    "label": label or "", "meta": meta or ""}
            if ports is not None:
                node["ports"] = ports
            self.nodes[node_id] = node
        return node_id

    def add_edge(self, src: str, tgt: str, kind: str, label: str = "",
                 condition: str | None = None) -> None:
        key = (src, tgt, kind, label, condition)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        edge = {"src": src, "tgt": tgt, "kind": kind, "label": label or ""}
        if condition:
            edge["condition"] = condition
        self.edges.append(edge)

    def enqueue(self, node_id: str | None) -> None:
        if node_id and node_id not in self._expanded and node_id not in self._queue:
            self._queue.append(node_id)

    # -- destination resolution -------------------------------------------
    def resolve_dn(self, dn) -> str | None:
        """Resolve a dialed digit string to a node id, or ``None`` if blank.

        Owning-table precedence (``_OWNERS``) over the value index; unmatched
        digits synthesise an ``external`` or counted ``unknown`` terminal.
        """
        dn = str(dn or "").strip()
        if not dn:
            return None
        if dn in self._dn_cache:
            return self._dn_cache[dn]
        occ = self.idx.lookup(dn)
        node_id = None
        for prog, field, kind, prefix in _OWNERS:
            if any(o.get("program_number") == prog
                   and str(o.get("field", "")).split("#", 1)[0] == field
                   for o in occ):
                node_id = self._owner_node(prog, field, kind, prefix, dn)
                break
        if node_id is None:
            node_id = self._synthesise(dn)
        self._dn_cache[dn] = node_id
        return node_id

    def _owner_node(self, prog: str, field: str, kind: str, prefix: str,
                    dn: str) -> str:
        node_id = f"{prefix}:{dn}"
        if node_id in self.nodes:
            self.enqueue(node_id)
            return node_id
        label, num, meta = dn, dn, ""
        if prog in ("200", "206"):
            row = self._find_row(prog, field, dn)
            if row is not None:
                if prog == "200":
                    label = (self.f(row, "stationStationName")
                             or self.f(row, "stationDisplayDN") or f"Station {dn}")
                else:
                    label = (self.f(row, "phDNParameterUserName")
                             or self.f(row, "phDNParameterDisplayDN")
                             or f"Phantom DN {dn}")
                    meta = "Phantom DN"
        elif kind == "ring_group":
            label = f"Ring group {dn}"
        elif kind == "queue":
            label = f"ACD queue {dn}"
        elif kind == "voicemail":
            label = f"Voicemail port {dn}"
        self.add_node(node_id, kind, num, label, meta)
        self.enqueue(node_id)
        return node_id

    def _find_row(self, prog: str, field: str, value: str) -> dict | None:
        for row in self.rows(prog):
            if self.f(row, field) == value:
                return row
        return None

    def _synthesise(self, dn: str) -> str:
        """A terminal for an unresolved digit string — never a dropped edge."""
        if dn.startswith("+") or (dn.isdigit() and len(dn) >= 10):
            return self.add_node(f"ext:{dn}", "external", dn,
                                 f"External {dn}", "Off-system PSTN number")
        if dn[:1] in ("*", "#"):
            return self.add_node(f"feat:{dn}", "feature", dn, f"Feature {dn}")
        return self.add_node(
            f"syn:{dn}", "unknown", dn, f"Unresolved {dn}",
            "This dialed destination did not match any DN in the snapshot.")

    def _dest_from_type(self, type_label: str, dest: str):
        """A ``(destination type, dialed digits)`` pair → node id, or ``None``.

        ``type_label`` is the enum label as read (``dialingDigits`` / ``dISA`` /
        ``nightBell`` / ``built-inModem`` / ``noData`` / ``none``) — robust across
        the DID/DIT and intercept type enums, which share labels but not ints.
        """
        t = (type_label or "").strip()
        if t == "dialingDigits":
            return self.resolve_dn(dest)
        if t == "dISA":
            return self._disa_node(dest)
        if t == "nightBell":
            return self.add_node("feat:nightbell", "feature", "",
                                 "Night bell", "Night ringing / night bell")
        if t == "built-inModem":
            return self.add_node("feat:modem", "feature", "",
                                 "Built-in modem", "Built-in modem / data port")
        # noData / none / blank → no onward destination
        return None

    def _disa_node(self, dest: str) -> str:
        node_id = f"disa:{dest or 'disa'}"
        return self.add_node(
            node_id, "ivr_menu", dest or "",
            "DISA / Auto attendant",
            "CIX routes here to DISA / the auto attendant. The key-press menu "
            "lives in the separate Stratagy voicemail (serial, not in SNMP), so "
            "it is drawn as a terminal — menu branches are a v2 cross-device join.")

    def _vmid_node(self, vmid: str) -> str | None:
        vmid = str(vmid or "").strip()
        if not vmid:
            return None
        return self.add_node(f"vm:{vmid}", "voicemail", vmid,
                             f"Voicemail {vmid}", "Mailbox / VMID")

    # -- mode-collapsed answer edges --------------------------------------
    def emit_mode_edges(self, src: str, pairs, kind: str = "route") -> None:
        """Emit answer edges, collapsing identical destinations across modes.

        ``pairs`` is ``[(mode, dest_id), ...]`` for modes present. Destinations
        shared by every present mode draw one edge (no condition); otherwise one
        edge per destination labelled with its mode(s).
        """
        present = [m for m, _ in pairs]
        by_dest: dict[str, list[str]] = {}
        for mode, dest in pairs:
            if dest:
                by_dest.setdefault(dest, []).append(mode)
        for dest, modes in by_dest.items():
            if len(present) > 1 and len(modes) == len(present):
                self.add_edge(src, dest, kind, "all modes")
            else:
                label = "/".join(modes)
                cond = modes[0] if len(modes) == 1 else None
                self.add_edge(src, dest, kind, label, cond)

    # -- entrypoints: DIDs (309) ------------------------------------------
    # Note: 318 NoCpnDID is NOT a standalone DID — it is the per-ILG "call with
    # no DID digits" default, so it is modelled as the line/trunk group's
    # fallback answer in build_groups(), not as its own entrypoint here.
    def build_dids(self) -> None:
        for row in self.rows("309"):
            self._build_did_row(row)

    def _build_did_row(self, row) -> None:
        ilg = self.f(row, "didIlg")
        num = self.f(row, "didNumber") or (row.get("key") or "")
        node_id = f"did:{num or row.get('key')}"
        label = self.f(row, "didDestinationName") or (f"DID {num}" if num else "DID")
        meta = f"Inbound DID · incoming group {ilg}" if ilg else "Inbound DID"
        self.add_node(node_id, "did", num, label, meta)
        self.entrypoints.append(node_id)

        pairs = []
        for mode, prefix in (("day", "didDay1"), ("day2", "didDay2"),
                             ("night", "didNight")):
            node = self._dest_from_type(
                self.f(row, f"{prefix}AudioDestinationType"),
                self.f(row, f"{prefix}AudioDestination"))
            if node:
                pairs.append((mode, node))
        self.emit_mode_edges(node_id, pairs)
        vm = self._vmid_node(self.f(row, "didVoiceMailId"))
        if vm:
            self.add_edge(node_id, vm, "vm", "voicemail")

    # -- entrypoints: incoming line / trunk groups (304 ILG) --------------
    def build_groups(self) -> None:
        dit_by_equip = self._dit_index()
        nocpn_by_ilg: dict[str, dict] = {}
        for row in self.rows("318"):
            ilg = self.f(row, "noDidIlg")
            if ilg:
                nocpn_by_ilg.setdefault(ilg, row)
        for row in self.rows("304"):
            self._build_group_row(row, dit_by_equip, nocpn_by_ilg)

    def _dit_index(self) -> dict:
        out: dict[str, dict] = {}
        for row in self.rows("310"):
            equip = _format_equipment(self.f(row, "ditEquipment"))
            if equip:
                out[equip] = row
        return out

    def _group_members(self, grp: str):
        """Member ports of ILG ``grp``: ``[(port_dict, equipment_str)]``."""
        members = []
        # 300 TrunkAssign — analog CO / loop / ground / E&M / DID trunks.
        for row in self.rows("300"):
            if self.f(row, "trunkIlg") != grp:
                continue
            equip = _format_equipment(self.f(row, "trunkEquipment"))
            ptype = _SIGNALING_PORT_TYPE.get(self.f(row, "trunkSignaling"),
                                             "analog_co")
            tno = self.f(row, "trunkNo")
            label = self.f(row, "trunkTrunkName") or (f"CO trunk {tno}" if tno
                                                      else "CO trunk")
            members.append(({"id": f"grp:{grp}/trunk:{tno or equip or len(members)}",
                             "label": label, "equipment": equip, "type": ptype},
                            equip))
        # 302 ISDN primary (PRI) / 317 ISDN basic (BRI).
        for prog, ilg_f, eq_f, ch_f, ptype in (
            ("302", "isdnPrimaryTrunkIlg", "isdnPrimaryTrunkEquipment",
             "isdnPrimaryTrunkChGrp", "pri"),
            ("317", "isdnBasicTrunkIlg", "isdnBasicTrunkEquipment",
             "isdnBasicChGroup", "bri"),
        ):
            for row in self.rows(prog):
                if self.f(row, ilg_f) != grp:
                    continue
                equip = _format_equipment(self.f(row, eq_f))
                ch = self.f(row, ch_f)
                members.append(({"id": f"grp:{grp}/{ptype}:{ch or equip or len(members)}",
                                 "label": f"{ptype.upper()} channel {ch}".strip(),
                                 "equipment": equip, "type": ptype}, equip))
        return members

    def _build_group_row(self, row, dit_by_equip, nocpn_by_ilg) -> None:
        grp = self.f(row, "ilgGrpNo") or (row.get("key") or "")
        members = self._group_members(grp)
        ports = [p for p, _ in members]
        types = {p["type"] for p in ports}
        analog = bool(types) and types <= _ANALOG_PORT_TYPES
        if not ports:  # no members derivable → fall back to the ILG's own type
            analog = self.f(row, "ilgAnalogISDNType") == "analog"
        kind = "line_group" if analog else "trunk_group"
        prefix = "lg" if analog else "tg"
        node_id = f"{prefix}:{grp}"

        kindword = "analog CO line" if analog else "trunk"
        meta_bits = [f"{len(ports)} member {kindword}"
                     f"{'s' if len(ports) != 1 else ''}"]
        if any(not p["equipment"] for p in ports):
            meta_bits.append("some member equipment did not decode to a "
                             "cabinet/slot/circuit and is shown blank")
        meta_bits.append("day/night switch-over times are set at the switch, "
                         "not stored in SNMP")
        label = (f"Analog line group {grp}" if analog
                 else f"Trunk group {grp}")
        self.add_node(node_id, kind, grp, label, " · ".join(meta_bits),
                      ports=ports)
        self.entrypoints.append(node_id)
        # Remember how to reach this group by its ILG number and pool, so
        # build_ring_keys() can wire a station's CO-line key to it.
        self._group_node_by_ilg[grp] = node_id
        pool = self.f(row, "ilgPoolLineGroup")
        if pool and pool != "0":
            self._ilgs_by_pool.setdefault(pool, []).append(grp)

        # Answer points: member DIT (310) entries, by mode.
        pairs = []
        for _, equip in members:
            dit = dit_by_equip.get(equip) if equip else None
            if not dit:
                continue
            for mode, pfx in (("day", "ditDay1"), ("day2", "ditDay2"),
                              ("night", "ditNight")):
                node = self._dest_from_type(
                    self.f(dit, f"{pfx}AudioDestinationType"),
                    self.f(dit, f"{pfx}AudioDestination"))
                if node:
                    pairs.append((mode, node))
        # Fallback: the ILG's no-DID default (318) when no DIT answer exists.
        if not pairs and grp in nocpn_by_ilg:
            nr = nocpn_by_ilg[grp]
            for mode, pfx in (("day", "noDidDay1"), ("day2", "noDidDay2"),
                              ("night", "noDidNight")):
                node = self._dest_from_type(
                    self.f(nr, f"{pfx}AudioDestinationType"),
                    self.f(nr, f"{pfx}AudioDestination"))
                if node:
                    pairs.append((mode, node))
        self.emit_mode_edges(node_id, pairs)

    # -- ring-by-key: the key-system inbound path (no answer-point table) --
    def build_ring_keys(self) -> None:
        """Wire each incoming line/trunk group to the stations that ring on its
        CO lines by **key appearance** (program 205 flexible buttons).

        On a small Toshiba key system there is no DID/DIT answer point — the CO
        lines simply ring the phones that carry those line keys. This reads that
        programming and draws a ``ring_key`` edge group→station for every real
        appearance. Nothing is invented: a ring is drawn only where the key is
        actually programmed and both the group and the station resolve.

        Must run after :meth:`build_groups` (group nodes + the ILG/pool maps).
        """
        if not self._group_node_by_ilg:
            return
        trunk_ilg = {self.f(r, "trunkNo"): self.f(r, "trunkIlg")
                     for r in self.rows("300") if self.f(r, "trunkNo")}
        for row in self.rows("205"):
            code = self.f(row, "featureCode")
            if code not in _RING_KEY_CODES:
                continue
            station = self.f(row, "featureDn")
            ref = self.f(row, "featureParameter1")
            if not station or not ref:
                continue
            group_ids = self._ring_key_groups(code, ref, trunk_ilg)
            if not group_ids:
                continue
            tgt = self.resolve_dn(station)
            if not tgt or self.nodes.get(tgt, {}).get("kind") != "extension":
                continue
            for gid in group_ids:
                self.add_edge(gid, tgt, "ring_key", "rings")

    def _ring_key_groups(self, code: str, ref: str, trunk_ilg: dict) -> list[str]:
        """The group entrypoint node id(s) a ring key of ``code`` points at.

        120 CO → the ILG of trunk ``ref``; 130 CO Line Group → ILG ``ref``
        directly; 140 Pooled Line → every ILG in pool ``ref``. Unknown refs
        yield nothing (the station simply isn't drawn ringing — never a guess).
        """
        if code == _FK_CO_LINE:
            ilg = trunk_ilg.get(ref)
            gid = self._group_node_by_ilg.get(ilg) if ilg else None
            return [gid] if gid else []
        if code == _FK_CO_LINE_GROUP:
            gid = self._group_node_by_ilg.get(ref)
            return [gid] if gid else []
        if code == _FK_POOLED_LINE:
            return [self._group_node_by_ilg[g]
                    for g in self._ilgs_by_pool.get(ref, [])
                    if g in self._group_node_by_ilg]
        return []

    # -- expansion of referenced destinations -----------------------------
    def expand_all(self) -> None:
        while self._queue:
            node_id = self._queue.pop(0)
            if node_id in self._expanded:
                continue
            self._expanded.add(node_id)
            node = self.nodes.get(node_id)
            if not node:
                continue
            kind = node["kind"]
            if kind == "extension":
                self._expand_extension(node)
            elif kind == "ring_group":
                self._expand_ring_group(node)
            elif kind == "queue":
                self._expand_queue(node)
            elif kind == "attendant":
                self._expand_attendant(node)

    def _expand_extension(self, node) -> None:
        dn = node["num"]
        row = self._find_row("200", "stationDn", dn) or \
            self._find_row("206", "phDn", dn)
        if row is None:
            return
        vmid = self.f(row, "stationVoiceMailId") or \
            self.f(row, "phDNParameterVoiceMailId")
        vm = self._vmid_node(vmid)
        if vm:
            self.add_edge(node["id"], vm, "vm", "voicemail")
        cf_index = self.f(row, "phDNParameterCallForwardIndex")
        if cf_index:
            self._expand_system_cf(node["id"], cf_index)

    def _expand_ring_group(self, node) -> None:
        dn = node["num"]
        hunt = self._find_row("209", "stationHuntPilotNumber", dn)
        if hunt is not None:
            grp = self.f(hunt, "stationHuntGrp")
            method = self.f(hunt, "stationHuntMethod")
            if method:
                node["meta"] = (f"Hunt group · strategy: {method}"
                                + (" · ipVoiceMail" if method == "ipVoiceMail"
                                   else ""))
            members = [(self.f(m, "huntGrpMemberIndex"), self.f(m, "huntGrpMemberDn"))
                       for m in self.rows("218")
                       if self.f(m, "huntGrpMemberNumber") == grp]
            for _, mdn in sorted(members, key=lambda x: _as_int(x[0])):
                tgt = self.resolve_dn(mdn)
                if tgt:
                    self.add_edge(node["id"], tgt, "member", "rings")
            cf_index = self.f(hunt, "stationHuntCallForwardIndex")
            if cf_index:
                self._expand_system_cf(node["id"], cf_index)
            return
        mcg = self._find_row("517", "multipleCallingGroupPilotNumber", dn)
        if mcg is not None:
            grp = self.f(mcg, "multipleCallingGroupIndex")
            node["meta"] = "Multiple-calling (ring) group"
            for m in self.rows("518"):
                if self.f(m, "multipleCallingMembersIndex") != grp:
                    continue
                tgt = self._dest_from_type(
                    self.f(m, "multipleCallingMembersDestinationType"),
                    self.f(m, "multipleCallingMembersDestinationNumber"))
                if tgt:
                    cadence = _RING_CADENCE.get(
                        self.f(m, "multipleCallingMembersDestCallType"))
                    self.add_edge(node["id"], tgt, "member",
                                  cadence or "rings", cadence)
            vm = self._vmid_node(self.f(mcg, "multipleCallingGroupVoiceMailID"))
            if vm:
                self.add_edge(node["id"], vm, "vm", "voicemail")
            cf_index = self.f(mcg, "multipleCallingGroupSystemCFIndex")
            if cf_index:
                self._expand_system_cf(node["id"], cf_index)

    def _expand_queue(self, node) -> None:
        dn = node["num"]
        row = self._find_row("540", "acdPilotDn", dn)
        if row is None:
            return
        tgt = self._dest_from_type(
            self.f(row, "acdPilotAfterShiftForwardType"),
            self.f(row, "acdPilotAfterShiftForwardDestination"))
        if tgt:
            self.add_edge(node["id"], tgt, "timeout", "after shift", "overflow")
        vm = self._vmid_node(self.f(row, "acdPilotVoiceMailId"))
        if vm:
            self.add_edge(node["id"], vm, "vm", "voicemail")

    def _expand_attendant(self, node) -> None:
        grp = node["num"]
        row = self._find_row("404", "attendantGroupNumber", grp)
        if row is None:
            return
        for field, label, cond in (
            ("attendantOverflowDestination", "overflow", "overflow"),
            ("attendantAlternativeDest", "alternate", "overflow"),
        ):
            tgt = self.resolve_dn(self.f(row, field))
            if tgt:
                self.add_edge(node["id"], tgt, "timeout", label, cond)
        vm = self._vmid_node(self.f(row, "attendantVoiceMailId"))
        if vm:
            self.add_edge(node["id"], vm, "vm", "voicemail")

    def _expand_system_cf(self, src: str, index: str) -> None:
        for row in self.rows("500"):
            if self.f(row, "systemCallForwardIndex") != index:
                continue
            cond = _CF_TYPE_CONDITION.get(self.f(row, "systemCallForwardType"))
            mode = _CF_MODE.get(self.f(row, "systemCallForwardDayNightMode"))
            for dest_field in ("systemCallForwardFirstDestination",
                               "systemCallForwardSecondDestination"):
                tgt = self.resolve_dn(self.f(row, dest_field))
                if tgt:
                    label = cond or "forward"
                    if mode:
                        label = f"{label} ({mode})"
                    self.add_edge(src, tgt, "fwd", label, cond or "forward")

    # -- assembly ----------------------------------------------------------
    def graph(self) -> dict:
        self.build_dids()
        self.build_groups()
        self.build_ring_keys()
        self.expand_all()
        # Entrypoints, de-duplicated, order preserved.
        seen: set = set()
        entry = [e for e in self.entrypoints
                 if e in self.nodes and not (e in seen or seen.add(e))]
        nodes = list(self.nodes.values())
        unresolved = sum(1 for n in nodes if n["kind"] == "unknown")
        return {
            "version": CONTRACT_VERSION,
            "entrypoints": entry,
            "nodes": nodes,
            "edges": self.edges,
            "stats": {"nodes": len(nodes), "edges": len(self.edges),
                      "unresolved": unresolved},
        }


def _as_int(s) -> int:
    try:
        return int(str(s))
    except (TypeError, ValueError):
        return 1 << 30


def callflow_available(program_views: dict) -> bool:
    """True when the snapshot holds inbound-routing programs (not CORE-only)."""
    by_num = {str(pv.get("program_number")): pv
              for pv in (program_views or {}).get("programs", [])
              if pv.get("program_number") is not None}
    return any(by_num.get(n, {}).get("rows") for n in ROUTING_PROGRAMS)


def build_callflow(program_views: dict) -> dict:
    """Build the neutral Call Flow graph from a ``program_views`` working copy."""
    return _Builder(program_views or {}).graph()


# --------------------------------------------------------------------------
# Read coverage + honest diagnosis — ENVELOPE metadata, not the graph.
#
# The graph object is the FROZEN contract (callflow.schema.json has
# additionalProperties:false on the object *and* on stats), so none of this can
# live inside it. It rides on the /callflow endpoint envelope instead, so the UI
# can tell these cases apart that otherwise all look like an empty diagram:
#   1. CORE-only read            → routing programs not read at all
#   2. partial / scoped read     → an answer-point table (310/318/309) is missing
#   3. genuinely unrouted system → the tables ARE read, every destination is
#      'no data', AND no station has these lines as a ring key — nothing to draw.
# Since 1.1.0 ring-by-key (program 205) is drawn, so case 3 now means *no*
# documented inbound at all, not merely "no answer-point table".
# --------------------------------------------------------------------------
_ENTRYPOINT_PROGRAMS = {"309": "DID numbers",
                        "304": "Incoming line / trunk groups"}
_ANSWER_POINT_PROGRAMS = {"310": "DIT — per-line answer points",
                          "318": "No-DID answer points",
                          "309": "DID answer points"}
_RING_KEY_PROGRAMS = {"205": "Station CO-line ring keys"}

# Per program, the (day1, day2, night) destination-TYPE field triple whose value
# says whether a mode answers anywhere. Mirrors what build_groups/build_dids read.
_ANSWER_TYPE_FIELDS = {
    "310": ("ditDay1AudioDestinationType", "ditDay2AudioDestinationType",
            "ditNightAudioDestinationType"),
    "318": ("noDidDay1AudioDestinationType", "noDidDay2AudioDestinationType",
            "noDidNightAudioDestinationType"),
    "309": ("didDay1AudioDestinationType", "didDay2AudioDestinationType",
            "didNightAudioDestinationType"),
}
# Destination types that actually send a call somewhere (vs noData / none).
_ROUTING_DEST_TYPES = {"dialingDigits", "dISA", "nightBell", "built-inModem"}


def _program_rows(program_views: dict, num: str):
    """Rows of program ``num``, or ``None`` when the program is absent entirely.

    ``None`` (not read) is deliberately distinct from ``[]`` (read, no rows)."""
    for pv in (program_views or {}).get("programs", []):
        if str(pv.get("program_number")) == num:
            return pv.get("rows") or []
    return None


def callflow_coverage(program_views: dict) -> dict:
    """Read coverage of the inbound-routing tables + a count of answer points
    actually programmed (a non-'no data' destination in any mode). Pure."""
    def status(num: str) -> str:
        rows = _program_rows(program_views, num)
        if rows is None:
            return "missing"
        return "present" if rows else "empty"

    programs = {num: {"title": title, "status": status(num)}
                for num, title in {**_ENTRYPOINT_PROGRAMS,
                                   **_ANSWER_POINT_PROGRAMS,
                                   **_RING_KEY_PROGRAMS}.items()}
    programmed = 0
    for num, type_fields in _ANSWER_TYPE_FIELDS.items():
        for row in (_program_rows(program_views, num) or []):
            cells = {c.get("field_name"): c for c in row.get("cells", [])}
            if any(_s(cells.get(f)) in _ROUTING_DEST_TYPES for f in type_fields):
                programmed += 1
    return {"programs": programs, "answer_points_programmed": programmed}


def callflow_diagnosis(program_views: dict) -> dict:
    """Everything the /callflow endpoint returns: availability, the frozen-shape
    graph, read coverage, and — when entry points exist but nothing could be
    drawn — an honest reason distinguishing an incomplete read from a system
    whose inbound routing simply is not in the SNMP routing tables. Pure.

    ``routing_complete`` is True when every entry point reaches an answer (or
    there are no entry points at all); False means the diagram would be entry
    points with no onward edges, and ``reason`` says why.
    """
    available = callflow_available(program_views)
    coverage = callflow_coverage(program_views)
    if not available:
        return {
            "available": False,
            "routing_complete": False,
            "graph": None,
            "coverage": coverage,
            "reason": (
                "No inbound-routing programs (304 / 309 / 310 / 318) in this "
                "read — it was almost certainly a CORE-only read. Run a full "
                "read (Connect does core→all; the Backups page can take a full "
                "snapshot) so the routing tables are present."),
        }

    graph = build_callflow(program_views)
    entry_ids = set(graph["entrypoints"])
    answer_edges = sum(1 for e in graph["edges"] if e["src"] in entry_ids)
    complete = (not entry_ids) or answer_edges > 0

    reason = None
    if entry_ids and answer_edges == 0:
        progs = coverage["programs"]
        has_did = bool(_program_rows(program_views, "309"))
        # Answer-point tables that matter for what is present: the ILG tables
        # always, the DID table only when there are DIDs.
        critical = ["310", "318"] + (["309"] if has_did else [])
        missing = [n for n in critical
                   if progs.get(n, {}).get("status") == "missing"]
        if missing:
            names = ", ".join(f"program {n}" for n in missing)
            reason = (
                f"Routing data is incomplete — the answer-point "
                f"{'tables' if len(missing) != 1 else 'table'} ({names}) "
                f"{'were' if len(missing) != 1 else 'was'} not in this read. "
                "Run a full read (Connect does core→all, or take a full "
                "snapshot) so the inbound routing can be drawn.")
        elif _program_rows(program_views, "205") is None:
            # No answer points AND the station key map wasn't read, so
            # ring-by-key could not even be checked — treat as a partial read.
            reason = (
                "Entry points were found, but the DID / DIT answer-point tables "
                "are all ‘no data’ and the station key programming (program 205) "
                "was not in this read, so ring-by-key can’t be checked. Run a "
                "full read (Connect does core→all, or take a full snapshot).")
        else:
            # Answer points are all 'no data' AND no station rings these lines by
            # key — there is genuinely no documented inbound path to draw.
            reason = (
                "Entry points were found, but there is no inbound routing to "
                "draw: the DID / DIT answer-point tables are all ‘no data’ and "
                "no station has these lines as a CO-line ring key. Inbound "
                "handling may be off-switch (a carrier or auto-attendant) or "
                "not yet programmed.")

    return {
        "available": True,
        "routing_complete": complete,
        "graph": graph,
        "coverage": coverage,
        "reason": reason,
    }


__all__ = ["build_callflow", "callflow_available", "callflow_coverage",
           "callflow_diagnosis", "CONTRACT_VERSION", "ROUTING_PROGRAMS"]
