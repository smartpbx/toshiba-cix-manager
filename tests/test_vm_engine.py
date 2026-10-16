#!/usr/bin/env python3
"""The read-only VM engine: sysparams, pbxdb, catalog, JSON backup, reports.

All offline against the FakeLVMU card image. Run: python3 -I tests/test_vm_engine.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from toshiba_cix import vm_link as L          # noqa: E402
from toshiba_cix import vm_sysparams as SP    # noqa: E402
from toshiba_cix import vm_pbxdb as PB        # noqa: E402
from toshiba_cix import vm_catalog as VC      # noqa: E402
from toshiba_cix import vm_backup as BK       # noqa: E402
from toshiba_cix import vm_reports as RP      # noqa: E402

INSTALL = (
    "#- Stratagy Configuration\r\n"
    "set pbx_type 'CIX100S'\r\n"
    "set password 'Stratagy'\r\n"
    "set hot_box 994\r\n"
    "set security_max_length 16\r\n"
    "set shutdown '2 130'\r\n"
    "#set admin_port 1\r\n"
)


def test_sysparams_parse_and_findings():
    parsed = SP.parse_install_cfg(INSTALL)
    names = {p["name"]: p for p in parsed["params"]}
    assert names["pbx_type"]["value"] == "CIX100S"
    assert names["hot_box"]["value"] == "994"
    assert names["admin_port"]["enabled"] is False  # #-disabled row
    assert names["hot_box"]["description"]          # help joined from Install.dhp subset
    # cleartext default password is flagged
    assert any(f["param"] == "password" for f in parsed["findings"])


def test_shutdown_decode():
    assert SP.decode_shutdown("2 130") == "weekly, Tuesday 01:30"
    assert SP.decode_shutdown("0 0") == "weekly, Sunday 00:00"


def test_sysparams_roundtrip_preserves_disabled_and_group():
    parsed = SP.parse_install_cfg(INSTALL)
    text = SP.render_install_cfg(parsed)
    assert "#- Stratagy Configuration" in text
    assert "set pbx_type 'CIX100S'" in text
    assert "#set admin_port 1" in text


def test_pbxdb_parse_and_compare_with_default():
    default = PB.default_for("CIX100S")
    assert default and default["pbx_name"].startswith("Strata CIX")
    assert any(d["code"] == "dl_connect" and d["value"] == "H"
               for d in default["dial_codes"])
    assert any("Axxxxxx" in i["pattern"] for i in default["integration"])
    # a live file that changed dl_connect and dropped a pattern
    live = PB.parse_pbx(
        "pbx_name 'Strata CIX 100 w/SMDI'\r\n"
        "dl_connect G # connect\r\n"
        "integration 30 'Axxxxxxrrrr0000000000'\r\n")
    cmp = PB.compare_with_default(live, "CIX100S")
    assert cmp["available"] is True
    assert any(c["code"] == "dl_connect" and c["kind"] == "changed"
               for c in cmp["dial_codes"])
    assert any(c["kind"] == "removed" for c in cmp["integration"])
    # an unknown model is honest about having no default
    assert PB.compare_with_default(live, "NOPE999")["available"] is False


def test_catalog_valid_and_read_only():
    errors = VC.validate()
    assert errors == [], errors
    cat = VC.load_vm_catalog()
    # header fields confirmed; flag fields not confirmed
    assert cat["by_name"]["security_code"]["status"] == "confirmed"
    assert cat["by_name"]["do_not_disturb"]["status"] != "confirmed"
    # P1: nothing is writable (writes disabled), regardless of status
    assert VC.VM_WRITES_ENABLED is False
    assert all(not VC.field_writable(f) for f in cat["fields"])
    # and even with writes on, only confirmed fields could be writable
    model = VC.editor_model(writes_enabled=True)
    for tab in model["tabs"]:
        for f in tab["fields"]:
            if f["writable"]:
                assert f["status"] == "confirmed"


def _model_over_fake():
    link = L.VMLink(L.FakeLVMU())
    link.connect()
    return BK.read_model(link)


def test_json_backup_over_fake():
    link = L.VMLink(L.FakeLVMU())
    link.connect()
    doc = BK.build_json_backup(link, site="demo")
    assert doc["meta"]["kind"] == BK.BACKUP_KIND
    assert doc["meta"]["box_count"] >= 10
    assert doc["sysparams"]["params"]
    assert doc["pbxdb"]["dial_codes"]
    assert "200" in doc["boxes"]
    assert doc["boxes"]["200"]["extension"] == "200H"


def test_mailbox_diff_decoded_and_raw_fallback():
    a = _model_over_fake()
    b = _model_over_fake()
    # change a decoded field (security code) on box 200
    import copy
    b = copy.deepcopy(b)
    from toshiba_cix import vm_records as R
    new_ua = R.build_ua_segment(security_code="1234")
    b["boxes"]["200"]["security_code"] = "1234"
    b["boxes"]["200"]["raw_ua_hex"] = new_ua.hex()
    d = BK.diff_backups(a, b)
    assert "200" in d["boxes"]
    chg = d["boxes"]["200"]
    assert any(c["field"] == "security_code" for c in chg["changes"])
    # the security code is masked in the diff
    assert all(c["new"] == "••••" for c in chg["changes"] if c["field"] == "security_code")
    # raw-bytes fallback also saw the UA segment change
    assert "raw_ua_hex" in chg["raw"]


def test_reports_run_client_side_and_mask_secret():
    model = _model_over_fake()
    tmpl = next(t for t in RP.default_templates() if t["id"] == "audit")
    report = RP.run_report(tmpl, model["boxes"])
    assert [c["name"] for c in report["columns"]] == ["box", "name", "security_code", "modified"]
    assert report["row_count"] >= 10
    # security code column is masked
    sec_idx = [c["name"] for c in report["columns"]].index("security_code")
    assert all(row[sec_idx] in ("", "••••") for row in report["rows"])
    csv = RP.to_csv(report)
    assert "User ID" in csv.splitlines()[0]


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
