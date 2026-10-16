"""The change journal — ``journal.sqlite`` + a human ``changes.log``.

Every commit (including a cancelled preview, recorded as ``mode=preview``) and
every read-back goes here (DESIGN_PLAN safety layer 10; architecture.md 4.3).
Two tables::

    commits(id, site, device_identity, started, finished, mode, transport,
            user, snapshot_path, ok)
    ops(commit_id, program, idx, field, oid, old, new, read_back, match)

``idx`` holds the row index (``index`` is a SQL keyword); it is surfaced as
``index`` in the dicts this module returns. A plain-text ``changes.log`` is
appended alongside because techs grep. Pure stdlib (``sqlite3``) and
path-injected: :class:`Journal` takes a db path (``":memory:"`` for tests) and
an optional log path.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS commits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site            TEXT,
    device_identity TEXT,
    started         TEXT,
    finished        TEXT,
    mode            TEXT,
    transport       TEXT,
    user            TEXT,
    snapshot_path   TEXT,
    ok              INTEGER
);
CREATE TABLE IF NOT EXISTS ops (
    commit_id INTEGER REFERENCES commits(id),
    program   TEXT,
    idx       TEXT,
    field     TEXT,
    oid       TEXT,
    old       TEXT,
    new       TEXT,
    read_back TEXT,
    match     INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ops_commit ON ops(commit_id);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_scalar(v):
    """Store non-scalars as JSON so old/new/read_back survive a list or dict."""
    if v is None or isinstance(v, (str, int, float)):
        return v
    return json.dumps(v, default=str)


class Journal:
    """A sqlite commit journal with a sidecar human log. Path-injected."""

    def __init__(self, db_path: str, changes_log: str | None = None):
        self.db_path = db_path
        self.changes_log = changes_log
        if db_path != ":memory:":
            d = os.path.dirname(os.path.abspath(db_path)) or "."
            os.makedirs(d, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- write -------------------------------------------------------------
    def start_commit(self, *, site, mode="write", transport=None,
                     device_identity=None, user=None, snapshot_path=None) -> int:
        """Open a commit row and return its id. ``started`` is stamped now."""
        cur = self._conn.execute(
            "INSERT INTO commits (site, device_identity, started, mode, "
            "transport, user, snapshot_path, ok) VALUES (?,?,?,?,?,?,?,?)",
            (site, device_identity, _utc_now(), mode, transport, user,
             snapshot_path, None))
        self._conn.commit()
        return int(cur.lastrowid)

    def add_op(self, commit_id: int, *, program=None, index=None, field=None,
               oid=None, old=None, new=None, read_back=None, match=None) -> None:
        self._conn.execute(
            "INSERT INTO ops (commit_id, program, idx, field, oid, old, new, "
            "read_back, match) VALUES (?,?,?,?,?,?,?,?,?)",
            (commit_id, program, (None if index is None else str(index)), field,
             oid, _json_scalar(old), _json_scalar(new), _json_scalar(read_back),
             (None if match is None else int(bool(match)))))
        self._conn.commit()

    def add_ops(self, commit_id: int, ops) -> None:
        for op in ops:
            self.add_op(commit_id, **op)

    def finish_commit(self, commit_id: int, *, ok: bool,
                      finished: str | None = None) -> None:
        self._conn.execute(
            "UPDATE commits SET finished=?, ok=? WHERE id=?",
            (finished or _utc_now(), int(bool(ok)), commit_id))
        self._conn.commit()

    def log_line(self, text: str) -> None:
        """Append a line to ``changes.log`` (best-effort; never raises)."""
        if not self.changes_log:
            return
        try:
            d = os.path.dirname(os.path.abspath(self.changes_log)) or "."
            os.makedirs(d, exist_ok=True)
            with open(self.changes_log, "a", encoding="utf-8") as fh:
                fh.write(f"{_utc_now()}  {text}\n")
        except OSError:  # pragma: no cover
            pass

    # -- read --------------------------------------------------------------
    def list_commits(self, limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM commits ORDER BY id DESC LIMIT ?", (limit,))
        return [self._commit_dict(r) for r in rows]

    def get_commit(self, commit_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM commits WHERE id=?", (commit_id,)).fetchone()
        if row is None:
            return None
        d = self._commit_dict(row)
        d["ops"] = self.ops_for(commit_id)
        return d

    def ops_for(self, commit_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM ops WHERE commit_id=? ORDER BY rowid", (commit_id,))
        return [self._op_dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()

    # -- row mapping -------------------------------------------------------
    @staticmethod
    def _commit_dict(r: sqlite3.Row) -> dict:
        d = dict(r)
        if d.get("ok") is not None:
            d["ok"] = bool(d["ok"])
        return d

    @staticmethod
    def _op_dict(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["index"] = d.pop("idx", None)
        if d.get("match") is not None:
            d["match"] = bool(d["match"])
        return d


def journal_from_root(root) -> Journal:
    """A :class:`Journal` at ``<root>/journal.sqlite`` + ``<root>/changes.log``."""
    if hasattr(root, "journal_db"):
        return Journal(root.journal_db, root.changes_log)
    base = str(root)
    return Journal(os.path.join(base, "journal.sqlite"),
                   os.path.join(base, "changes.log"))


__all__ = ["Journal", "journal_from_root"]
