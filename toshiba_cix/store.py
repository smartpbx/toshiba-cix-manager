"""The snapshot store — version history for a switch's programming.

A **snapshot** is the v2 ``toshiba-cix-backup`` document (``backup.py``); this
module is where snapshots live on disk, how they are listed, deduped, named,
pinned, pruned, packed into ``.cixbak`` containers, exported (redacted) and
imported, and the ``activity.jsonl`` trail that answers *who changed this, and
when* (backups.md §2, DESIGN_PLAN §7).

Layout under ``<root>`` (``<root>/backups`` matches :class:`appdirs.AppDirs`)::

    backups/<site>/
        index.json          [{id, kind, name, tags, pinned, parent, read_at,
                              scope, swid, content_hash, counts, bytes, path,
                              dedupe_of, note}]  — the timeline, loaded once
        <id>.cixbak          one snapshot (zip: backup.json + report.txt + MANIFEST)
        changesets/          change-set documents (P2)
        activity.jsonl       one line per snapshot / write / restore / arm

Canonical JSON (``backup.canonical_json``) means an unchanged switch hashes
identically, so a scheduled re-read that found nothing new costs one index line
(``dedupe_of``), not a file (§2.3). Pinned, named, the newest full snapshot, and
anything a pending change set references are never pruned (§13). Secrets are
plaintext in the local store (the laptop is the trust boundary, same as
eManager's SQL Server) and **redacted by default on export** (§1.3).

Pure disk I/O against an injected root, atomic writes (temp + ``os.replace``),
so it is unit-tested against a temp directory with no real profile touched.
"""

from __future__ import annotations

import io
import json
import os
import re
import tempfile
import time
import zipfile
from datetime import datetime, timezone

from . import __version__
from .backup import (FORMAT, canonical_json, content_hash, ensure_v2, redact,
                     render_backup_text)

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_UNSET = object()

# Container member names (backups.md §1.2).
MEMBER_BACKUP = "backup.json"
MEMBER_REPORT = "report.txt"
MEMBER_MANIFEST = "MANIFEST.json"

# Default retention by kind (backups.md §2.2). ``keep`` = newest N; ``days`` =
# older than N days are prunable. Pinned / named / newest-all / referenced are
# always kept regardless (enforced in :meth:`prune`).
DEFAULT_POLICY = {
    "manual": {"keep": 30},
    "snapshot": {"keep": 30},            # auto Snapshot-on-connect
    "auto-pre-write": {"keep": 50, "days": 30},
    "auto-post-write": {"keep": 30, "days": 30},
    "compare-live": {"keep": 5},
    "scheduled": {"keep": 14},
    "template-apply": {"keep": 30, "days": 30},
    "named": {"keep": None},             # forever
    "imported": {"keep": None},          # forever
    "offline-edit": {"keep": None},
}


def _safe(part: str) -> str:
    """A filesystem-safe slug for a site id / sid (never empty, never a path)."""
    slug = _SAFE.sub("-", str(part or "").strip()).strip("-.")
    return slug or "unnamed"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _scope_tag(scope) -> str:
    """A stable tag for a snapshot's scope, so dedupe only compares like reads."""
    if isinstance(scope, (list, tuple)):
        return "scope:" + ",".join(sorted(str(s) for s in scope))
    return str(scope or "all")


# --------------------------------------------------------------------------
# .cixbak container (pure, in-memory)
# --------------------------------------------------------------------------
def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pack_cixbak(doc: dict, *, catalog=None, report: str | None = None,
                attachments=None) -> bytes:
    """Pack a backup doc into a ``.cixbak`` zip (backups.md §1.2).

    Members: ``backup.json`` (required), ``report.txt`` (readable with no tool),
    ``MANIFEST.json`` (ids + per-member sha256), and any ``attachments``
    (``{path: bytes}`` — the 910 image, voicemail dumps). Deterministic member
    order so an unchanged snapshot packs identically."""
    body = canonical_json(doc).encode("utf-8")
    if report is None:
        try:
            report = render_backup_text(doc, catalog=catalog)
        except Exception:  # noqa: BLE001 — a report must never block a save
            report = ""
    report_b = report.encode("utf-8")
    members = [(MEMBER_BACKUP, body), (MEMBER_REPORT, report_b)]
    for path, data in sorted((attachments or {}).items()):
        members.append((path, data))
    meta = doc.get("meta", {})
    manifest = {
        "format": doc.get("format", FORMAT),
        "snapshot": (meta.get("snapshot") or {}).get("id"),
        "site": meta.get("site"),
        "swid": meta.get("swid"),
        "content_hash": meta.get("content_hash"),
        "tool_version": __version__,
        "members": [{"path": p, "sha256": _sha256_bytes(d)} for p, d in members],
    }
    members.append((MEMBER_MANIFEST,
                    json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")))
    buf = io.BytesIO()
    # Fixed timestamp in the zip so the bytes are reproducible for a given doc.
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in members:
            zi = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)
    return buf.getvalue()


def unpack_cixbak(data_or_path) -> tuple[dict, dict]:
    """Return ``(backup_doc, members)`` from a ``.cixbak`` (bytes or path).

    ``members`` maps every member path to its bytes (so an attachment survives a
    round-trip). Raises ``ValueError`` if the required ``backup.json`` is absent."""
    if isinstance(data_or_path, (bytes, bytearray)):
        src = io.BytesIO(data_or_path)
    else:
        src = data_or_path
    with zipfile.ZipFile(src, "r") as zf:
        members = {name: zf.read(name) for name in zf.namelist()}
    if MEMBER_BACKUP not in members:
        raise ValueError("not a .cixbak: no backup.json member")
    doc = json.loads(members[MEMBER_BACKUP].decode("utf-8"))
    return doc, members


class SnapshotStore:
    """Save / list / dedupe / name / pin / prune / export snapshots under a root."""

    def __init__(self, root: str, *, catalog=None):
        self.root = root
        self._catalog = catalog

    # -- paths -------------------------------------------------------------
    def _site_dir(self, site_id: str) -> str:
        return os.path.join(self.root, "backups", _safe(site_id))

    def _index_path(self, site_id: str) -> str:
        return os.path.join(self._site_dir(site_id), "index.json")

    def _activity_path(self, site_id: str) -> str:
        return os.path.join(self._site_dir(site_id), "activity.jsonl")

    def _snap_path(self, site_id: str, sid: str, container: str) -> str:
        ext = ".cixbak" if container == "cixbak" else ".json"
        return os.path.join(self._site_dir(site_id), _safe(sid) + ext)

    # -- index (the timeline) ----------------------------------------------
    def _read_index(self, site_id: str) -> list:
        data = _read_json(self._index_path(site_id))
        return data if isinstance(data, list) else []

    def _write_index(self, site_id: str, entries: list) -> None:
        _atomic_write_json(self._index_path(site_id), entries)

    def index(self, site_id: str, *, kind=None, tag=None) -> list:
        """Timeline entries, newest first, optionally filtered by kind / tag."""
        out = self._read_index(site_id)
        if kind is not None:
            out = [e for e in out if e.get("kind") == kind]
        if tag is not None:
            out = [e for e in out if tag in (e.get("tags") or [])]
        out = sorted(out, key=lambda e: (e.get("read_at") or "", e.get("id") or ""),
                     reverse=True)
        return out

    # Back-compat alias — the browse routes call ``list``.
    def list(self, site_id: str) -> list:
        return self.index(site_id)

    def get_entry(self, site_id: str, sid: str):
        return next((e for e in self._read_index(site_id) if e.get("id") == sid), None)

    # -- put / take --------------------------------------------------------
    def put(self, site_id: str, doc: dict, *, kind=None, name=None, tags=None,
            pinned=None, note=None, parent=None, trigger=None, operator=None,
            transport=None, container: str = "cixbak", report=None,
            attachments=None) -> dict:
        """Store a backup doc; dedupe on content hash; return the index entry.

        The doc is upgraded to v2 if needed and its ``meta.snapshot`` block is
        patched with any provenance given. If its content hash equals the most
        recent snapshot of the **same scope**, no file is written — the index
        gets a ``dedupe_of`` row — so a quiet switch costs one line a day."""
        os.makedirs(self._site_dir(site_id), exist_ok=True)
        ensure_v2(doc, self._catalog)
        snap = doc["meta"].setdefault("snapshot", {})
        if kind is not None:
            snap["kind"] = kind
        for key, val in (("name", name), ("note", note), ("parent", parent),
                         ("trigger", trigger), ("operator", operator),
                         ("transport", transport)):
            if val is not None:
                snap[key] = val
        if tags is not None:
            snap["tags"] = list(tags)
        if pinned is not None:
            snap["pinned"] = bool(pinned)

        sid = snap["id"]
        ch = doc["meta"]["content_hash"]
        scope = doc["meta"].get("scope")
        scope_tag = _scope_tag(scope)
        entries = self._read_index(site_id)

        prev = _latest_real_for_scope(entries, scope_tag)
        entry = {
            "id": sid,
            "kind": snap.get("kind", "manual"),
            "name": snap.get("name"),
            "tags": list(snap.get("tags") or []),
            "pinned": bool(snap.get("pinned")),
            "parent": snap.get("parent"),
            "read_at": doc["meta"].get("read_at") or _now_iso(),
            "scope": scope,
            "scope_tag": scope_tag,
            "swid": doc["meta"].get("swid"),
            "counts": {"programs": doc["meta"].get("programs_count"),
                       "rows": doc["meta"].get("rows_count")},
            "content_hash": ch,
            "note": snap.get("note"),
            "redacted": bool(doc["meta"].get("redacted")),
        }
        if prev is not None and prev.get("content_hash") == ch \
                and not name and pinned is None:
            # Unchanged since the last like read: a distinct index-only row that
            # points at the original's file, so the timeline still shows "last
            # verified unchanged" without a second copy. Its id must be unique —
            # identical content yields an identical <stamp>-<hash6>, so append a
            # short uniquifier rather than overwrite the original's row.
            import uuid
            dedupe_id = f"{sid}.{uuid.uuid4().hex[:6]}"
            entry["id"] = dedupe_id
            entry["read_at"] = _now_iso()
            entry["dedupe_of"] = prev["id"]
            entry["path"] = None
            entry["bytes"] = 0
            entries.append(entry)
            self._write_index(site_id, entries)
            self.append_activity(site_id, {"event": "snapshot", "id": dedupe_id,
                                           "kind": entry["kind"], "at": entry["read_at"],
                                           "scope": scope_tag, "content_hash": ch,
                                           "dedupe_of": prev["id"],
                                           "trigger": snap.get("trigger")})
            return entry

        path = self._snap_path(site_id, sid, container)
        if container == "cixbak":
            data = pack_cixbak(doc, catalog=self._catalog, report=report,
                               attachments=attachments)
            _atomic_write_bytes(path, data)
            entry["bytes"] = len(data)
        else:
            _atomic_write_json(path, doc)
            entry["bytes"] = os.path.getsize(path)
        entry["path"] = os.path.basename(path)
        entry["container"] = container
        entries = [e for e in entries if e.get("id") != sid]
        entries.append(entry)
        self._write_index(site_id, entries)
        self.append_activity(site_id, {"event": "snapshot", "id": sid,
                                       "kind": entry["kind"], "at": entry["read_at"],
                                       "scope": scope_tag, "content_hash": ch,
                                       "trigger": snap.get("trigger")})
        return entry

    def take(self, client, *, site_id: str, catalog=None, scope="all",
             programs=None, name=None, kind="manual", site=None,
             transport=None, **put_kw) -> dict:
        """Read a live CIX and store the snapshot (the I/O path for the CLI /
        the Conduit worker). Read-only; delegates the walk to ``backup.backup``."""
        from .backup import backup as _backup
        cat = catalog or self._catalog
        progs = None if scope == "all" else (programs or scope)
        doc = _backup(client, cat, site=site, programs=progs, transport=transport)
        return self.put(site_id, doc, kind=kind, name=name, transport=transport,
                        **put_kw)

    # -- get / latest ------------------------------------------------------
    def get(self, site_id: str, sid: str):
        """The full backup doc for ``sid`` (resolving a dedupe pointer), or None."""
        entry = self.get_entry(site_id, sid)
        if entry is None:
            return None
        if entry.get("dedupe_of") and not entry.get("path"):
            return self._load_doc(site_id, entry["dedupe_of"])
        return self._load_doc_at(self._site_dir(site_id), entry)

    def _load_doc(self, site_id: str, sid: str):
        entry = self.get_entry(site_id, sid)
        if entry is None:
            return None
        return self._load_doc_at(self._site_dir(site_id), entry)

    @staticmethod
    def _load_doc_at(site_dir: str, entry: dict):
        path = entry.get("path")
        if not path:
            return None
        full = os.path.join(site_dir, path)
        if path.endswith(".cixbak"):
            try:
                doc, _ = unpack_cixbak(full)
                return doc
            except (OSError, ValueError, zipfile.BadZipFile):
                return None
        return _read_json(full)

    def latest(self, site_id: str, *, scope=None):
        """The most recent full snapshot (optionally of a scope) — cold start."""
        for e in self.index(site_id):
            if scope is not None and e.get("scope_tag") != _scope_tag(scope):
                continue
            doc = self.get(site_id, e["id"])
            if doc is not None:
                return doc
        return None

    # -- mutate header -----------------------------------------------------
    def set_meta(self, site_id: str, sid: str, *, name=_UNSET, note=_UNSET,
                 tags=_UNSET, pinned=_UNSET) -> dict | None:
        """Rename / note / tag / pin, updating both the index and the stored doc."""
        entries = self._read_index(site_id)
        entry = next((e for e in entries if e.get("id") == sid), None)
        if entry is None:
            return None
        if name is not _UNSET:
            entry["name"] = name
        if note is not _UNSET:
            entry["note"] = note
        if tags is not _UNSET:
            entry["tags"] = list(tags or [])
        if pinned is not _UNSET:
            entry["pinned"] = bool(pinned)
        self._write_index(site_id, entries)
        # Mirror into the stored document so an exported file carries it too.
        if entry.get("path"):
            doc = self.get(site_id, sid)
            if doc is not None:
                snap = doc.setdefault("meta", {}).setdefault("snapshot", {})
                for key, sentinel in (("name", name), ("note", note),
                                      ("tags", tags), ("pinned", pinned)):
                    if sentinel is not _UNSET:
                        snap[key] = (list(sentinel or []) if key == "tags"
                                     else (bool(sentinel) if key == "pinned" else sentinel))
                self._rewrite_doc(site_id, entry, doc)
        return entry

    def name(self, site_id, sid, label):
        # A named snapshot is kept forever: promote its kind too.
        entries = self._read_index(site_id)
        e = next((x for x in entries if x.get("id") == sid), None)
        if e is not None and label and e.get("kind") not in ("named",):
            e["kind"] = "named"
            self._write_index(site_id, entries)
        return self.set_meta(site_id, sid, name=label)

    def pin(self, site_id, sid, pinned=True):
        return self.set_meta(site_id, sid, pinned=pinned)

    def tag(self, site_id, sid, tags):
        return self.set_meta(site_id, sid, tags=tags)

    # Back-compat with the first browse cut.
    def set_label(self, site_id, sid, label):
        return self.set_meta(site_id, sid, name=label)

    def set_pinned(self, site_id, sid, pinned):
        return self.set_meta(site_id, sid, pinned=pinned)

    def _rewrite_doc(self, site_id: str, entry: dict, doc: dict) -> None:
        path = os.path.join(self._site_dir(site_id), entry["path"])
        if entry["path"].endswith(".cixbak"):
            _atomic_write_bytes(path, pack_cixbak(doc, catalog=self._catalog))
        else:
            _atomic_write_json(path, doc)

    # -- delete / prune ----------------------------------------------------
    def _is_protected(self, entries: list, entry: dict) -> str | None:
        """Why a snapshot cannot be deleted / pruned, or None if it may go."""
        if entry.get("pinned"):
            return "pinned"
        if entry.get("kind") == "named" or entry.get("name"):
            return "named"
        newest_all = _newest_full_all(entries)
        if newest_all is not None and newest_all["id"] == entry["id"]:
            return "newest full snapshot"
        # Anything a deduped row points at must stay (it is that row's data).
        if any(e.get("dedupe_of") == entry["id"] for e in entries):
            return "referenced by a deduped snapshot"
        # Anything referenced as a parent/base by another snapshot stays.
        if any(e.get("parent") == entry["id"] for e in entries):
            return "referenced as a parent"
        return None

    def delete(self, site_id: str, sid: str, *, force: bool = False):
        """Delete one snapshot; refuses a protected one unless ``force``.

        Returns ``(ok, reason)``. ``reason`` names the protection on a refusal."""
        entries = self._read_index(site_id)
        entry = next((e for e in entries if e.get("id") == sid), None)
        if entry is None:
            return False, "not found"
        reason = None if force else self._is_protected(entries, entry)
        if reason:
            return False, reason
        if entry.get("path"):
            try:
                os.remove(os.path.join(self._site_dir(site_id), entry["path"]))
            except OSError:
                pass
        self._write_index(site_id, [e for e in entries if e.get("id") != sid])
        self.append_activity(site_id, {"event": "delete", "id": sid,
                                       "at": _now_iso()})
        return True, None

    def prune(self, site_id: str, policy: dict | None = None) -> list:
        """Apply retention per kind; never touch protected snapshots. Returns the
        removed entries. Idempotent — safe to run after every save."""
        policy = policy or DEFAULT_POLICY
        entries = self._read_index(site_id)
        newest_first = sorted(entries,
                              key=lambda e: (e.get("read_at") or "", e.get("id") or ""),
                              reverse=True)
        now = time.time()
        removable: list = []
        seen_by_kind: dict = {}
        for e in newest_first:
            if self._is_protected(entries, e):
                continue
            rule = policy.get(e.get("kind"))
            if not rule:
                continue
            kind = e.get("kind")
            seen_by_kind[kind] = seen_by_kind.get(kind, 0) + 1
            over_keep = rule.get("keep") is not None and seen_by_kind[kind] > rule["keep"]
            too_old = False
            if rule.get("days"):
                age = now - _epoch(e.get("read_at"))
                too_old = age > rule["days"] * 86400
            if over_keep or (rule.get("days") and too_old and over_keep):
                removable.append(e)
        removed = []
        for e in removable:
            ok, _ = self.delete(site_id, e["id"])
            if ok:
                removed.append(e)
        return removed

    # -- export / import ---------------------------------------------------
    def export(self, site_id: str, sid: str, *, redact_secrets: bool = True,
               container: str = "cixbak"):
        """Bytes for download: the snapshot, **redacted by default** (§1.3).

        Returns ``(filename, bytes)``. A redacted export carries masked secrets
        and ``meta.redacted = true`` so a later restore refuses those fields."""
        doc = self.get(site_id, sid)
        if doc is None:
            return None
        if redact_secrets:
            doc = redact(doc, catalog=self._catalog)
        stem = f"{_safe(site_id)}_{_safe(sid)}"
        if container == "cixbak":
            return stem + ".cixbak", pack_cixbak(doc, catalog=self._catalog)
        return stem + ".json", canonical_json(doc).encode("utf-8")

    def import_doc(self, site_id: str, source, *, kind: str = "imported",
                   name=None) -> dict:
        """Import a ``.json`` / ``.cixbak`` (bytes or path) or a parsed doc as a
        kept ``imported`` snapshot. Returns the index entry."""
        if isinstance(source, dict):
            doc = source
        elif isinstance(source, (bytes, bytearray)):
            if source[:2] == b"PK":
                doc, _ = unpack_cixbak(bytes(source))
            else:
                doc = json.loads(bytes(source).decode("utf-8"))
        else:  # a path
            if str(source).endswith(".cixbak"):
                doc, _ = unpack_cixbak(source)
            else:
                doc = _read_json(source)
        if not isinstance(doc, dict):
            raise ValueError("could not read a backup document from the source")
        return self.put(site_id, doc, kind=kind, name=name)

    # -- activity trail ----------------------------------------------------
    def append_activity(self, site_id: str, record: dict) -> None:
        """Append one JSON line to ``activity.jsonl`` (best-effort, never raises
        into the caller — a save must not fail because the log is unwritable)."""
        path = self._activity_path(site_id)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass

    def read_activity(self, site_id: str, *, limit: int | None = None) -> list:
        """Activity records, newest first (for the diff's attribution / blame)."""
        path = self._activity_path(site_id)
        out: list = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            out.append(json.loads(line))
                        except ValueError:
                            continue
        except OSError:
            return []
        out.reverse()
        return out[:limit] if limit else out


# --------------------------------------------------------------------------
# index helpers (pure)
# --------------------------------------------------------------------------
def _latest_real_for_scope(entries: list, scope_tag: str):
    """The newest entry with a file (not a dedupe pointer) of the given scope."""
    cands = [e for e in entries
             if e.get("scope_tag") == scope_tag and e.get("path")]
    if not cands:
        return None
    return max(cands, key=lambda e: (e.get("read_at") or "", e.get("id") or ""))


def _newest_full_all(entries: list):
    """The newest ``scope == all`` snapshot that has a file (never pruned)."""
    cands = [e for e in entries
             if _scope_tag(e.get("scope")) == "all" and e.get("path")]
    if not cands:
        return None
    return max(cands, key=lambda e: (e.get("read_at") or "", e.get("id") or ""))


def _epoch(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 0.0


# --------------------------------------------------------------------------
# atomic disk helpers
# --------------------------------------------------------------------------
def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _atomic_write_bytes(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _atomic_write_json(path: str, obj) -> None:
    _atomic_write_bytes(path, json.dumps(obj, default=str).encode("utf-8"))


def store_from_root(appdirs_or_root, *, catalog=None) -> SnapshotStore:
    """Build a :class:`SnapshotStore` from an AppDirs or a plain root path."""
    root = getattr(appdirs_or_root, "root", None) or appdirs_or_root
    return SnapshotStore(root, catalog=catalog)


__all__ = ["SnapshotStore", "store_from_root", "pack_cixbak", "unpack_cixbak",
           "DEFAULT_POLICY", "MEMBER_BACKUP", "MEMBER_REPORT", "MEMBER_MANIFEST"]
