"""Mailbox reports — client-side, instant, over a read model (voicemail-map §5.6).

VM Manager's report is a **template** (an ordered column list over a User ID
range) run with optional *Reset Statistics*. Because the app holds every box in
memory after a read, *Run Report* is client-side and instant: no serial traffic,
no range re-read. *Reset Statistics* is the only part that needs a write and is
gated like any write (not in P1). Security codes are masked in report output.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Every column a report may list, with its display label and the mailbox-dict
# key it reads. Security code is intentionally masked (never dumped in a report).
COLUMNS: Dict[str, dict] = {
    "box": {"label": "User ID", "key": "box"},
    "comment": {"label": "Comment", "key": "comment"},
    "extension": {"label": "Extension", "key": "extension"},
    "name": {"label": "Name", "key": "name"},
    "security_code": {"label": "Security code", "key": "security_code", "mask": True},
    "created": {"label": "Box created", "key": "created"},
    "modified": {"label": "Box saved", "key": "modified"},
    "record_len": {"label": "Record bytes", "key": "record_len"},
}

TEMPLATES: List[dict] = [
    {"id": "directory", "name": "Directory",
     "columns": ["box", "name", "extension", "comment"]},
    {"id": "audit", "name": "Security audit",
     "columns": ["box", "name", "security_code", "modified"]},
    {"id": "full", "name": "Full mailbox list",
     "columns": ["box", "comment", "extension", "name", "created", "modified"]},
]


def default_templates() -> List[dict]:
    return [dict(t) for t in TEMPLATES]


def _in_range(box: str, lo: Optional[str], hi: Optional[str]) -> bool:
    try:
        n = int(box)
    except (TypeError, ValueError):
        return True
    if lo not in (None, "") and n < int(lo):
        return False
    if hi not in (None, "") and n > int(hi):
        return False
    return True


def run_report(template: dict, boxes: Dict[str, dict], *,
               first: Optional[str] = None, last: Optional[str] = None) -> dict:
    """Run a template over a read model's ``boxes`` map. Pure; no I/O."""
    cols = [c for c in template.get("columns", []) if c in COLUMNS]
    header = [{"name": c, "label": COLUMNS[c]["label"]} for c in cols]
    rows: List[List[str]] = []
    for box in sorted(boxes, key=lambda b: (len(b), b)):
        if not _in_range(box, first, last):
            continue
        rec = boxes[box]
        row = []
        for c in cols:
            spec = COLUMNS[c]
            val = rec.get(spec["key"])
            if spec.get("mask") and val:
                val = "••••"
            row.append("" if val is None else str(val))
        rows.append(row)
    return {"template": template.get("id"), "columns": header, "rows": rows,
            "row_count": len(rows)}


def to_csv(report: dict) -> str:
    """CSV text for Save/download (the old report export)."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([c["label"] for c in report.get("columns", [])])
    for row in report.get("rows", []):
        w.writerow(row)
    return buf.getvalue()


__all__ = ["COLUMNS", "TEMPLATES", "default_templates", "run_report", "to_csv"]
