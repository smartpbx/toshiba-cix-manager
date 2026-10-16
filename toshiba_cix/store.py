"""On-disk snapshot store — the local cache that makes browsing feel instant.

DESIGN_PLAN 2.1/5.1/11-P1: browsing reads the *local snapshot*, only Refresh /
Backup / Apply touch the device, and the app cold-starts from the last snapshot
in under a second (look up a DN in the parking lot with the laptop barely on).
This module is that cache: one JSON file per saved snapshot under the per-site
folder, with a tiny header so listing never parses the big ``program_views``
payload.

Layout under ``<store root>``::

    snapshots/<site id>/<sid>.json        one snapshot (header + program_views)

A snapshot file is ``{"sid", "site_id", "saved_at", "label", "pinned",
"kind", "identity", "meta", "program_views"}``. ``program_views`` is the exact
enrich.py contract the UI renders, so a cold-start load and a live read render
through the same code path (DESIGN_PLAN rule 6, "same screens live or from a
file").

Pure disk I/O against an injected root dir (like appdirs / sites / journal), so
it is unit-tested against a temp directory with no real profile touched. Writes
are atomic (temp file + ``os.replace``) so a crash mid-save never corrupts a
prior snapshot.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_HEADER_KEYS = ("sid", "site_id", "saved_at", "label", "pinned", "kind",
                "identity", "counts")


def _safe(part: str) -> str:
    """A filesystem-safe slug for a site id / sid (never empty, never a path)."""
    slug = _SAFE.sub("-", str(part or "").strip()).strip("-.")
    return slug or "unnamed"


def _new_sid() -> str:
    """A sortable, unique snapshot id: ``YYYYMMDD-HHMMSS-ffffff-<4 hex>``.

    Microsecond precision plus a short random suffix so two saves in the same
    instant never collide (overwrite) and the lexical order matches time order.
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d-%H%M%S-%f-") + uuid.uuid4().hex[:4]


class SnapshotStore:
    """Save / list / load snapshots under ``<root>/snapshots/<site>``."""

    def __init__(self, root: str):
        self.root = root

    def _site_dir(self, site_id: str) -> str:
        return os.path.join(self.root, "snapshots", _safe(site_id))

    def _path(self, site_id: str, sid: str) -> str:
        return os.path.join(self._site_dir(site_id), _safe(sid) + ".json")

    # -- save --------------------------------------------------------------
    def save(self, site_id: str, program_views: dict, *, identity=None,
             meta=None, label=None, pinned: bool = False,
             kind: str = "snapshot") -> dict:
        """Write a snapshot and return its header. ``sid`` is generated.

        ``program_views`` is the enrich.py contract dict; ``identity`` the live
        device identity (swid / chassis mac); ``meta`` any extra provenance
        (scope, walk_error, source ip). ``kind`` is ``"snapshot"`` (the default,
        the auto *Snapshot on connect*) or ``"backup"`` (a named .cixbak-style
        keep). Returns the header dict (no ``program_views``)."""
        site_dir = self._site_dir(site_id)
        os.makedirs(site_dir, exist_ok=True)
        sid = _new_sid()
        counts = (program_views or {}).get("stats", {})
        doc = {
            "sid": sid,
            "site_id": site_id,
            "saved_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "label": label,
            "pinned": bool(pinned),
            "kind": kind,
            "identity": identity or {},
            "meta": meta or {},
            "counts": {k: counts.get(k) for k in ("programs", "rows", "cells")},
            "program_views": program_views or {},
        }
        self._atomic_write(self._path(site_id, sid), doc)
        return self._header(doc)

    # -- list / load -------------------------------------------------------
    def list(self, site_id: str) -> list:
        """Headers for every saved snapshot, newest first (no payload read)."""
        site_dir = self._site_dir(site_id)
        if not os.path.isdir(site_dir):
            return []
        out = []
        for name in os.listdir(site_dir):
            if not name.endswith(".json"):
                continue
            doc = self._read(os.path.join(site_dir, name))
            if doc:
                out.append(self._header(doc))
        out.sort(key=lambda h: (h.get("saved_at") or "", h.get("sid") or ""),
                 reverse=True)
        return out

    def get(self, site_id: str, sid: str) -> dict:
        """One full snapshot (header + ``program_views``), or ``None``."""
        return self._read(self._path(site_id, sid))

    def latest(self, site_id: str) -> dict:
        """The most recent full snapshot for cold start, or ``None``."""
        headers = self.list(site_id)
        if not headers:
            return None
        return self.get(site_id, headers[0]["sid"])

    # -- mutate header -----------------------------------------------------
    def set_label(self, site_id: str, sid: str, label) -> dict:
        return self._patch(site_id, sid, {"label": label})

    def set_pinned(self, site_id: str, sid: str, pinned: bool) -> dict:
        return self._patch(site_id, sid, {"pinned": bool(pinned)})

    def delete(self, site_id: str, sid: str) -> bool:
        path = self._path(site_id, sid)
        try:
            os.remove(path)
            return True
        except OSError:
            return False

    # -- internals ---------------------------------------------------------
    def _patch(self, site_id: str, sid: str, changes: dict):
        doc = self.get(site_id, sid)
        if doc is None:
            return None
        doc.update(changes)
        self._atomic_write(self._path(site_id, sid), doc)
        return self._header(doc)

    @staticmethod
    def _header(doc: dict) -> dict:
        return {k: doc.get(k) for k in _HEADER_KEYS}

    @staticmethod
    def _read(path: str):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    @staticmethod
    def _atomic_write(path: str, doc: dict) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, default=str)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise


def store_from_root(appdirs_or_root) -> SnapshotStore:
    """Build a :class:`SnapshotStore` from an AppDirs or a plain root path."""
    root = getattr(appdirs_or_root, "root", None) or appdirs_or_root
    return SnapshotStore(root)


__all__ = ["SnapshotStore", "store_from_root"]
