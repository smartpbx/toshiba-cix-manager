"""The write path is two-phase: the UI may call the apply (write) endpoint ONLY
from the Review & Write dialog (DESIGN_PLAN 10.3: "a test greps the UI for any
call to a write endpoint outside the review dialog").

This greps the committed React source and fails if:

* the apply call (``applyChangeset`` / the ``/apply`` endpoint) is invoked from
  any component other than the review dialog, or from the store;
* the review dialog does not actually wire the apply call (the gate is dead);
* the legacy direct-write route ``/api/save`` is referenced anywhere in the UI.

It is pure text analysis of ``webui/src`` — no build, no browser.

Run:  python3 tests/test_ui_write_gated.py
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "webui", "src")

# The transport layer (one fetch helper per endpoint) legitimately *defines* the
# apply method; the rule is about CALL SITES in components/views/store.
TRANSPORT = os.path.join("lib", "api.ts")
DIALOG_BASENAME = "ReviewWriteDialog.tsx"
APPLY_TOKEN = "applyChangeset"          # the one method that can write
LEGACY_WRITE = "/api/save"              # the legacy direct-write route


def _walk_src():
    for dirpath, _dirs, files in os.walk(SRC):
        for f in files:
            if f.endswith((".ts", ".tsx")):
                yield os.path.join(dirpath, f)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_src_dir_present():
    assert os.path.isdir(SRC), f"webui/src not found at {SRC}"


def test_apply_called_only_in_review_dialog():
    offenders = []
    dialog_has_it = False
    for path in _walk_src():
        rel = os.path.relpath(path, SRC)
        if rel == TRANSPORT:
            continue  # the transport layer may define the method
        text = _read(path)
        if APPLY_TOKEN in text:
            if os.path.basename(path) == DIALOG_BASENAME:
                dialog_has_it = True
            else:
                offenders.append(rel)
    assert not offenders, (
        f"apply ({APPLY_TOKEN}) called outside the review dialog: {offenders}")
    assert dialog_has_it, (
        f"{DIALOG_BASENAME} does not call {APPLY_TOKEN} — the write gate is dead")


def test_legacy_direct_write_route_not_used():
    hits = [os.path.relpath(p, SRC) for p in _walk_src() if LEGACY_WRITE in _read(p)]
    assert not hits, f"legacy direct-write route {LEGACY_WRITE} used in UI: {hits}"


def test_review_dialog_exists():
    found = any(os.path.basename(p) == DIALOG_BASENAME for p in _walk_src())
    assert found, f"{DIALOG_BASENAME} not found under {SRC}"


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {exc!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
