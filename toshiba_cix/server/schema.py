"""Load the generated ``ui_schema.json`` and serve it at ``GET /api/schema``.

The schema is the one static UI data file (DESIGN_PLAN 2.1): the engine and the
React store both read it, so they agree on every label, enum, range, archetype
and menu. Loading reuses :func:`toshiba_cix.catalog._load_data_text`, so it
resolves identically across every packaging — the base64 embed in the
single-file amalgam, the PyInstaller ``_MEIPASS`` bundle and the packaged
``toshiba_cix/data/`` dir of a dev checkout — and degrades to a clear error if
a build forgot to bundle it rather than crashing at import.
"""

from __future__ import annotations

import json

from ..catalog import _load_data_text

UI_SCHEMA_FILENAME = "ui_schema.json"
_CACHE: dict | None = None
_TEXT_CACHE: str | None = None


def load_ui_schema_text() -> str:
    global _TEXT_CACHE
    if _TEXT_CACHE is not None:
        return _TEXT_CACHE
    text = _load_data_text(UI_SCHEMA_FILENAME, "EMBEDDED_UI_SCHEMA_JSON")
    if text is None:
        raise FileNotFoundError(
            "ui_schema.json not found — run: python3 tools/build_ui_schema.py")
    _TEXT_CACHE = text
    return text


def load_ui_schema(*, cache: bool = True) -> dict:
    global _CACHE
    if cache and _CACHE is not None:
        return _CACHE
    data = json.loads(load_ui_schema_text())
    if cache:
        _CACHE = data
    return data


def schema_summary() -> dict:
    """Small identity for ``/api/health`` (version + counts), schema-missing safe."""
    try:
        s = load_ui_schema()
    except Exception:  # noqa: BLE001
        return {"schema_available": False}
    return {"schema_available": True,
            "schema_version": s.get("schema_version"),
            "catalog_version": s.get("catalog_version"),
            "counts": s.get("counts", {})}


__all__ = ["load_ui_schema", "load_ui_schema_text", "schema_summary",
           "UI_SCHEMA_FILENAME"]
