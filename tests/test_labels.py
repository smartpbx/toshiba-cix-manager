"""Offline tests for the deterministic UI-schema label caster (``tools/labels``).

The whole generated ``ui_schema.json`` is byte-reproducible only because every
MOF symbol maps to exactly one caption; these pin the rules the DESIGN_PLAN
calls out by example (``dKT`` -> ``DKT``, ``notAllowed`` -> ``Not Allowed``,
``time80msec`` -> ``80 ms``) so a refactor of the caster cannot silently move a
label under the whole fleet.

Run:  python3 tests/test_labels.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from labels import enum_caption, humanize_name, title_case_symbol  # noqa: E402


def test_title_case_symbol_design_examples():
    assert title_case_symbol("dKT") == "DKT"
    assert title_case_symbol("notAllowed") == "Not Allowed"
    assert title_case_symbol("time80msec") == "80 ms"


def test_title_case_symbol_simple_words():
    assert title_case_symbol("enable") == "Enable"
    assert title_case_symbol("disable") == "Disable"
    assert title_case_symbol("none") == "None"


def test_title_case_symbol_units():
    assert title_case_symbol("time6sec") == "6 s"
    assert title_case_symbol("time450ms") == "450 ms"
    assert title_case_symbol("interval80ms") == "80 ms"
    assert title_case_symbol("minus3DB") == "-3 dB"


def test_title_case_symbol_acronyms():
    assert title_case_symbol("dTMF") == "DTMF"
    assert title_case_symbol("aNIAndDNIS") == "ANI And DNIS"
    assert title_case_symbol("dNKeyOnly") == "DN Key Only"


def test_title_case_symbol_empty():
    assert title_case_symbol("") == ""
    assert title_case_symbol("   ") == ""


def test_title_case_symbol_is_deterministic():
    for s in ("notAllowed", "dKT", "time80msec", "workingDay"):
        assert title_case_symbol(s) == title_case_symbol(s)


def test_humanize_name():
    assert humanize_name("stationStationName") == "Station Station Name"
    assert humanize_name("trunkNo") == "Trunk No"
    assert humanize_name("vmSystemApplication") == "VM System Application"


def test_enum_caption_override_wins():
    # The mechanical cast of "oFF" is "OFF"; the override corrects it to "Off".
    assert title_case_symbol("oFF") == "OFF"
    assert enum_caption("oFF", overrides={"oFF": "Off"}) == "Off"


def test_enum_caption_falls_back_to_cast():
    assert enum_caption("enable") == "Enable"
    assert enum_caption("enable", overrides={}) == "Enable"


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
