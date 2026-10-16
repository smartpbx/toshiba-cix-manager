#!/usr/bin/env python3
"""Framing + the read-only VMLink driven against the FakeLVMU protocol twin.

Runs fully offline (no hardware, no committed customer capture). The framing
rule is also validated against the REAL on-site capture when its directory is
pointed to by $SWITCHROOM_VM_CAPTURE_DIR (see test_vm_records.py); here we prove
the frame layer and the end-to-end read path on synthetic bytes.

Run:  python3 -I tests/test_vm_link.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from toshiba_cix import vm_link as L  # noqa: E402
from toshiba_cix import vm_records as R  # noqa: E402


def test_checksum_and_known_frames():
    # whole frame sums to 0 mod 256
    assert L.build_login("Stratagy") == bytes.fromhex("010309537472617461677900a4")
    assert L.build_frame(L.T_ACK_HOST) == bytes.fromhex("011000ef")
    assert L.build_frame(L.T_POLL) == bytes.fromhex("010200fd")
    valid = L.build_frame(L.T_LOGIN_RESULT, b"VALID")
    assert valid == bytes.fromhex("010405" + b"VALID".hex() + "86")
    for f in (L.build_login("x"), L.build_frame(L.T_ACK_CARD), valid):
        assert (sum(f) & 0xFF) == 0 and L.frame_ok(f)


def test_iter_frames_roundtrips_encoders():
    stream = (b"ATZ\r" + L.build_frame(L.T_POLL)
              + L.build_get(L.OP_OPEN_FILE, 7, b"INSTALL.CFG\x00")
              + L.build_frame(L.T_ACK_HOST))
    units = list(L.iter_frames(stream))
    raws = [u for u in units if isinstance(u, L.Raw)]
    frames = [u for u in units if isinstance(u, L.Frame)]
    assert any(b"ATZ" in r.data for r in raws)
    assert all(f.cksum_ok for f in frames)
    req = [f for f in frames if f.ftype == L.T_REQ_HOST][0]
    assert req.opcode == L.OP_OPEN_FILE and req.seq == 7
    assert req.value.rstrip(b"\x00") == b"INSTALL.CFG"


def _connected_link():
    fake = L.FakeLVMU()
    link = L.VMLink(fake)
    link.connect()
    return link, fake


def test_connect_login_and_preamble():
    link, _ = _connected_link()
    assert link.connected
    assert "STRATAGY" in link.firmware.upper()
    assert link.admin_box == "997"
    assert link.log_name.upper().endswith(".LOG")


def test_read_install_cfg_over_link():
    link, _ = _connected_link()
    text = link.read_file("INSTALL.CFG").decode("latin-1")
    assert "set pbx_type 'CIX100S'" in text
    assert "set hot_box 994" in text
    assert "set security_max_length 16" in text
    assert "integration 30 'Axxxxxxrrrr0000000000'" in text


def test_read_directory_over_link():
    link, _ = _connected_link()
    directory = link.read_directory()
    # box list begins 200H, 201H, ...
    assert directory.get("200") == "Reception"
    assert "201" in directory and "205" in directory
    assert len(directory) >= 10


def test_read_mailbox_record_over_link():
    link, _ = _connected_link()
    mb = R.read_mailbox(link, "200")
    assert mb.box == "200"
    assert mb.extension == "200H"
    assert mb.name == "Reception"
    # security code round-trips through the UA segment
    assert mb.security_code == "20000"
    # the model is honest about what it does NOT decode
    assert any("Unknown A" in u for u in mb.unproven)


def test_bad_password_is_rejected():
    fake = L.FakeLVMU(password="Stratagy")
    link = L.VMLink(fake, password="wrong")
    link.wait_banner()
    failed = False
    try:
        link.login()
    except L.VMLinkError as exc:
        failed = "password" in str(exc).lower()
    assert failed, "a wrong password must raise the exe's password error"


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
