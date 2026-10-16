"""The site book — ``sites.json``, the tech's equipment list.

A **site** is one customer system (eManager "Client Equipment" ∪ VM Manager
"Connection") with two legs — a PBX leg over SNMP and a Voice Mail leg over
serial/TCP — in the shape DESIGN_PLAN 2.3 fixes::

    {"id": "104670-tonerfarms", "name": "104670 Toner Farms — CIX100",
     "pbx": {"host": "...", "port": 161, "community": "...", "via": "overlay",
             "direct_host": "...", "identity": {...}},
     "vm":  {"transport": "tcp", "host": "...", "port": 7001,
             "direct_port": "COM3", "stratagy_type": "LVMU", "baud": 9600,
             "password_ref": "ask"},
     "notes": "...", "conduit_component_id": 1234,
     "flags": {"integer_write_proven": false, "persistence_verified": null},
     "vm_templates": []}

This module is pure stdlib and I/O-injected: :class:`SiteBook` takes an explicit
path, so a test drives it against a temp file. The file is written atomically
and ``0600`` — it holds community strings and (optionally) the Stratagy
password because the tool is useless without them, but **Conduit's credential
store stays the system of record** (architecture.md 3.1).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile

_VIA = ("direct", "overlay", "agent")


def slugify_id(name: str) -> str:
    """A stable, filename-safe id from a site name (``104670 Toner Farms`` ->
    ``104670-toner-farms``)."""
    s = str(name or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-") or "site"


def new_site(name: str, *, id=None, pbx=None, vm=None, notes="",
             conduit_component_id=None) -> dict:
    """Build a normalised site record (does not persist it)."""
    return normalize({
        "id": id or slugify_id(name),
        "name": name,
        "pbx": pbx or {},
        "vm": vm or {},
        "notes": notes,
        "conduit_component_id": conduit_component_id,
    })


def normalize(site: dict) -> dict:
    """Return a copy with every expected key present and legs shaped.

    Lenient on input (unknown keys are preserved); only fills defaults and
    coerces the two legs so downstream code never guards for missing keys.
    """
    s = dict(site or {})
    s["id"] = str(s.get("id") or slugify_id(s.get("name", "")))
    s["name"] = s.get("name") or s["id"]
    s["notes"] = s.get("notes") or ""
    s.setdefault("conduit_component_id", None)

    pbx = dict(s.get("pbx") or {})
    pbx.setdefault("host", pbx.get("host"))
    pbx.setdefault("port", pbx.get("port") or 161)
    pbx.setdefault("community", pbx.get("community") or "communityName")
    pbx.setdefault("via", pbx.get("via") if pbx.get("via") in _VIA else "direct")
    s["pbx"] = pbx

    vm = dict(s.get("vm") or {})
    vm.setdefault("transport", vm.get("transport") or "serial")
    vm.setdefault("baud", vm.get("baud") or 9600)
    vm.setdefault("stratagy_type", vm.get("stratagy_type") or "LVMU")
    s["vm"] = vm

    flags = dict(s.get("flags") or {})
    flags.setdefault("integer_write_proven", False)
    flags.setdefault("persistence_verified", None)
    s["flags"] = flags

    s.setdefault("vm_templates", list(s.get("vm_templates") or []))
    return s


class SiteBook:
    """Load / query / mutate ``sites.json`` at a given path. I/O-injected."""

    def __init__(self, path: str):
        self.path = path

    # -- read --------------------------------------------------------------
    def load(self) -> list[dict]:
        """Every site, normalised. Missing / empty / corrupt file -> ``[]``."""
        try:
            with open(self.path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (FileNotFoundError, ValueError):
            return []
        sites = raw.get("sites") if isinstance(raw, dict) else raw
        if not isinstance(sites, list):
            return []
        return [normalize(s) for s in sites if isinstance(s, dict)]

    def get(self, site_id: str):
        for s in self.load():
            if s["id"] == site_id:
                return s
        return None

    # -- write -------------------------------------------------------------
    def save_all(self, sites) -> list[dict]:
        """Replace the whole book (normalising each) and persist atomically."""
        out = [normalize(s) for s in sites]
        self._write(out)
        return out

    def upsert(self, site: dict) -> dict:
        """Insert or replace a site by id; returns the normalised record."""
        s = normalize(site)
        sites = self.load()
        for i, existing in enumerate(sites):
            if existing["id"] == s["id"]:
                sites[i] = s
                break
        else:
            sites.append(s)
        self._write(sites)
        return s

    def delete(self, site_id: str) -> bool:
        sites = self.load()
        kept = [s for s in sites if s["id"] != site_id]
        if len(kept) == len(sites):
            return False
        self._write(kept)
        return True

    # -- internals ---------------------------------------------------------
    def _write(self, sites: list[dict]) -> None:
        payload = json.dumps({"sites": sites}, indent=2, ensure_ascii=False) + "\n"
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".sites-", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            _chmod_private(tmp)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def from_root(root) -> SiteBook:
    """A :class:`SiteBook` at ``<root>/sites.json`` (``root`` is a path or AppDirs)."""
    path = root.sites_file if hasattr(root, "sites_file") \
        else os.path.join(str(root), "sites.json")
    return SiteBook(path)


def _chmod_private(path: str) -> None:
    try:
        if not sys.platform.startswith("win"):
            os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass


__all__ = ["SiteBook", "slugify_id", "new_site", "normalize", "from_root"]
