"""The one exclusive voicemail session the server owns.

The LVMU serial session is **stateful and exclusive** — the card refuses a
second admin login (voicemail-map §3.5) — so the server holds exactly one
:class:`VmSession` per process, every VM request goes through its lock, and the
decoded model is cached per session with a single explicit *Refresh* (never
polling the serial line). All reads use confirmed opcodes; the save surface is
**plan-only** (two-phase contract + Simulate) and performs no hardware write in
P1.

Offline, ``transport="fake"`` drives the :class:`~toshiba_cix.vm_link.FakeLVMU`
protocol twin so the whole UI and its tests run with no hardware.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional

from . import vm_backup
from . import vm_catalog
from . import vm_link
from . import vm_pbxdb
from . import vm_records
from . import vm_reports
from . import vm_serial

# Map decoded-mailbox keys to catalog field names (the editor reads values here).
_VALUE_MAP = {
    "box": "user_id", "comment": "comment", "extension": "extension",
    "name": "name1", "security_code": "security_code",
    "created": "box_created", "modified": "box_saved",
}


class VmSession:
    def __init__(self):
        self._lock = threading.RLock()
        self._link: Optional[vm_link.VMLink] = None
        self.transport_name = ""
        self.transport_kind = ""
        # per-session caches
        self._directory: Optional[Dict[str, str]] = None
        self._boxes: Dict[str, dict] = {}
        self._sysparams: Optional[dict] = None
        self._pbxdb: Optional[dict] = None

    # -- lifecycle --------------------------------------------------------
    def connect(self, spec: dict) -> dict:
        with self._lock:
            self.disconnect()
            kind = (spec or {}).get("transport") or "serial"
            if kind == "fake":
                transport = vm_link.FakeLVMU()
            else:
                transport = vm_serial.open_transport(spec)
            link = vm_link.VMLink(transport, password=spec.get("password")
                                  or "Stratagy")
            link.connect()  # banner -> login -> preamble (raises on failure)
            self._link = link
            self.transport_kind = kind
            self.transport_name = getattr(transport, "name", kind)
            self._clear_cache()
            return self.status()

    def disconnect(self) -> None:
        with self._lock:
            if self._link is not None:
                self._link.close()
            self._link = None
            self._clear_cache()

    def _clear_cache(self) -> None:
        self._directory = None
        self._boxes = {}
        self._sysparams = None
        self._pbxdb = None

    @property
    def connected(self) -> bool:
        return self._link is not None and self._link.connected

    def _require(self) -> vm_link.VMLink:
        if not self.connected:
            raise VmNotConnected("no voicemail session — Connect first")
        return self._link  # type: ignore[return-value]

    # -- status -----------------------------------------------------------
    def status(self) -> dict:
        link = self._link
        return {
            "connected": self.connected,
            "transport": self.transport_kind,
            "port": self.transport_name,
            "firmware": getattr(link, "firmware", "") if link else "",
            "admin_box": getattr(link, "admin_box", "") if link else "",
            "log_name": getattr(link, "log_name", "") if link else "",
            "trace_frames": len(link.trace) if link else 0,
            "shutdown": self._shutdown_text(),
            "writes_enabled": vm_catalog.VM_WRITES_ENABLED,
        }

    def _shutdown_text(self) -> Optional[str]:
        sp = self._sysparams
        if not sp:
            return None
        for p in sp.get("params", []):
            if p["name"] == "shutdown" and p["enabled"]:
                return p.get("decoded") or p.get("value")
        return None

    # -- reads ------------------------------------------------------------
    def directory(self, refresh: bool = False) -> Dict[str, str]:
        with self._lock:
            link = self._require()
            if self._directory is None or refresh:
                self._directory = link.read_directory()
                if refresh:
                    self._boxes = {}
            return self._directory

    def boxes(self, refresh: bool = False) -> list:
        """The Box List: User ID | Comment | Extension | Name | Messages,
        reserved boxes (411, 990-999) flagged muted, never hidden."""
        directory = self.directory(refresh=refresh)
        rows = []
        for box in sorted(directory, key=lambda b: (len(b), b)):
            rows.append({
                "box": box,
                "name": directory[box],
                "reserved": _is_reserved(box),
            })
        return rows

    def box(self, box_id: str, refresh: bool = False) -> dict:
        with self._lock:
            link = self._require()
            if box_id not in self._boxes or refresh:
                mb = vm_records.read_mailbox(link, box_id)
                if not mb.name:
                    mb.name = (self._directory or {}).get(box_id, "")
                self._boxes[box_id] = mb.as_dict()
            rec = self._boxes[box_id]
            return {"mailbox": rec, "editor": self._editor_for(rec),
                    "reserved": _is_reserved(box_id)}

    def _editor_for(self, rec: dict) -> dict:
        """The catalog editor model with this box's confirmed values filled in."""
        model = vm_catalog.editor_model()
        values = {}
        for mkey, fname in _VALUE_MAP.items():
            if rec.get(mkey) not in (None, ""):
                values[fname] = rec.get(mkey)
        model["values"] = values
        return model

    def sysparams(self, refresh: bool = False) -> dict:
        with self._lock:
            link = self._require()
            if self._sysparams is None or refresh:
                from . import vm_sysparams
                text = link.read_file("INSTALL.CFG").decode("latin-1", "replace")
                self._sysparams = vm_sysparams.parse_install_cfg(text)
            return self._sysparams

    def pbxdb(self, refresh: bool = False, compare: bool = False) -> dict:
        with self._lock:
            link = self._require()
            if self._pbxdb is None or refresh:
                sp = self.sysparams()
                model = _param(sp, "pbx_type") or "CIX100S"
                text = ""
                for path in (f"C:\\Stratagy\\PBX.DB\\{model}.PBX", f"{model}.PBX"):
                    try:
                        text = link.read_file(path).decode("latin-1", "replace")
                    except Exception:  # noqa: BLE001
                        text = ""
                    if text.strip():
                        break
                parsed = vm_pbxdb.parse_pbx(text)
                parsed["model"] = model
                self._pbxdb = parsed
            result = dict(self._pbxdb)
            if compare:
                result["compare"] = vm_pbxdb.compare_with_default(
                    self._pbxdb, self._pbxdb.get("model", ""))
            return result

    def backup_json(self, *, site: Optional[str] = None, progress=None) -> dict:
        with self._lock:
            link = self._require()
            doc = vm_backup.build_json_backup(link, site=site, progress=progress)
            # warm the per-box cache from the backup read
            self._boxes.update(doc.get("boxes", {}))
            self._directory = doc.get("directory", self._directory)
            self._sysparams = doc.get("sysparams", self._sysparams)
            return doc

    def run_report(self, template_id: str, *, first=None, last=None) -> dict:
        with self._lock:
            tmpls = {t["id"]: t for t in vm_reports.default_templates()}
            tmpl = tmpls.get(template_id)
            if tmpl is None:
                raise ValueError(f"unknown report template {template_id!r}")
            # Reports are client-side over a full read (voicemail-map §5.6): make
            # sure every box is in the cache, not just ones opened individually.
            directory = self.directory()
            full = {b for b, r in self._boxes.items() if "error" not in r}
            if not directory or not full.issuperset(directory):
                self.backup_json()
            return vm_reports.run_report(tmpl, self._boxes, first=first, last=last)

    def trace_text(self) -> str:
        link = self._link
        return link.trace_text() if link else ""

    # -- plan-only save (two-phase; Simulate; no hardware write in P1) ----
    def plan_save(self, box_id: str, changes: dict) -> dict:
        """Compute a preview of the record patch WITHOUT writing.

        This is the *plan* phase of plan->review->apply. P1 never applies: the
        write path is gated behind VM_WRITES_ENABLED (OFF) and a supervised lab
        write (voicemail-map §6.4). Only confirmed-offset fields can even be
        planned; everything else is refused with its reason."""
        with self._lock:
            info = self.box(box_id)
            rec = info["mailbox"]
            cat = vm_catalog.load_vm_catalog()["by_name"]
            planned, refused = [], []
            ua_hex = rec.get("raw_ua_hex", "")
            for fname, new_value in (changes or {}).items():
                field = cat.get(fname, {})
                if field.get("status") != "confirmed":
                    refused.append({"field": fname, "reason":
                                    "field offset unverified — read-only in this "
                                    "version"})
                    continue
                if fname == "security_code" and ua_hex:
                    try:
                        before = bytes.fromhex(ua_hex)
                        after = vm_records.rewrite_security_code(
                            before, str(new_value))
                        planned.append({
                            "field": fname, "old": "••••", "new": "••••",
                            "wire": "UA segment (patch-in-place, length-preserving)",
                            "bytes_changed": sum(1 for x, y in zip(before, after)
                                                 if x != y),
                            "proven": False,
                            "note": "write UNCONFIRMED against hardware — "
                                    "requires a supervised lab write (P3)",
                        })
                    except ValueError as exc:
                        refused.append({"field": fname, "reason": str(exc)})
                else:
                    planned.append({"field": fname, "old": rec.get(fname),
                                    "new": new_value, "proven": True})
            return {
                "box": box_id,
                "mode": "simulate",
                "writes_enabled": vm_catalog.VM_WRITES_ENABLED,
                "planned": planned,
                "refused": refused,
                "apply_allowed": False,
                "reason": ("Voicemail writes are disabled in this release "
                           "(read-only). This is a preview only."),
            }


class VmNotConnected(RuntimeError):
    pass


def _is_reserved(box: str) -> bool:
    try:
        n = int(box)
    except (TypeError, ValueError):
        return True  # named system boxes (GREETING, SOFTMODEM, …)
    return n == 411 or 990 <= n <= 999


def _param(sysparams: dict, name: str) -> Optional[str]:
    for p in sysparams.get("params", []):
        if p["name"] == name and p["enabled"]:
            return p["value"]
    return None


class VmSessionManager:
    """One process-wide exclusive VM session (the card allows only one)."""

    def __init__(self):
        self.session = VmSession()


__all__ = ["VmSession", "VmSessionManager", "VmNotConnected"]
