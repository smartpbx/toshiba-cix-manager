"""Offline tests for validate.py (L1 field + L2 row/batch validation)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix.validate import (has_errors, validate_op,  # noqa: E402
                                   validate_ops)
from toshiba_cix.write import WriteOp

ROOT = "1.3.6.1.4.1.186.1.22"


class _Prog:
    number = "1200"
    fields = [
        {"name": "name", "access": "rw", "len": "8", "syntax": "OCTET STRING"},
        {"name": "cos", "access": "rw", "syntax": "INTEGER"},
        {"name": "ip", "access": "rw", "ui_type": "ipaddress"},
    ]


def _op(field, value, oid="x", native=None, sendable=True):
    o = WriteOp(field, field, value, old_value="old",
                target_oid=(oid if sendable else None), native_wire=native)
    return o


def test_l1_length():
    r = validate_op(_op("name", "WAREHOUSE9"), _Prog())  # 10 > 8
    assert r and r[0]["severity"] == "error" and "at most 8" in r[0]["message"]


def test_l1_numeric():
    r = validate_op(_op("cos", "high", native="INTEGER"), _Prog())
    assert r and "numeric" in r[0]["message"]
    assert validate_op(_op("cos", "3", native="INTEGER"), _Prog()) == []


def test_l1_ipv4():
    bad = validate_op(_op("ip", "10.0.0"), _Prog())
    assert bad and "IPv4" in bad[0]["message"]
    assert validate_op(_op("ip", "10.0.0.1"), _Prog()) == []


def test_l1_skips_nonsendable_and_commit():
    assert validate_op(_op("name", "x" * 50, sendable=False), _Prog()) == []
    from toshiba_cix.write import commit_write_op
    assert validate_op(commit_write_op(), _Prog()) == []


def test_l2_same_oid_conflicting():
    ops = [_op("name", "A", oid="o1"), _op("name", "B", oid="o1")]
    res = validate_ops(ops, _Prog())
    assert any(f["level"] == "L2" for f in res["errors"])


def test_l2_duplicate_dn():
    ops = [WriteOp("dn", "dn", "2200", target_oid="o1"),
           WriteOp("dn", "dn", "2200", target_oid="o2")]
    res = validate_ops(ops, None)
    assert any("duplicate" in f["message"] for f in res["errors"])


def test_clean_batch_has_no_errors():
    ops = [_op("name", "DESK", oid="o1"), _op("cos", "3", oid="o2", native="INTEGER")]
    res = validate_ops(ops, _Prog())
    assert not has_errors(res) and res["error_count"] == 0


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
