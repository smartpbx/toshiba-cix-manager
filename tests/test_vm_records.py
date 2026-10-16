#!/usr/bin/env python3
"""vm_records parses a Stratagy capture into the mailbox/config model.

Two layers:

1. **Always (offline, PII-free).** A synthetic card->host stream is encoded with
   the confirmed content-block shape (``vm_link.encode_block``) carrying an
   ``INSTALL.CFG`` and a box directory, exactly as the LVMU streams them, then
   parsed back: the box list (``200H``…), the ``set`` system parameters, the
   ``integration`` SMDI strings, a mailbox record (box number at offset 14,
   extension, name, comment) and its security code — plus the UNCONFIRMED
   patch-in-place rewrite reproducing a field change in place.

2. **When available, the REAL on-site capture.** If $SWITCHROOM_VM_CAPTURE_DIR
   holds ``session2.{app2card,card2app,log}`` (the real capture, deliberately
   NOT committed — see repo .gitignore "customer PBX data stays out of git"),
   the framing rule is validated against it: every frame checksum-valid, the
   .log reconstructs both raw streams byte-for-byte, and the directory +
   set-commands + integration strings parse out. Absent, this is a no-op so CI
   stays green with no customer data.

Run:  python3 -I tests/test_vm_records.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from toshiba_cix import vm_link as L  # noqa: E402
from toshiba_cix import vm_records as R  # noqa: E402

# A capture-shaped INSTALL.CFG: model-generic set-commands + SMDI integration
# pattern templates (these are NOT customer data — box numbers, pbx_type and the
# A/B/N/D/S pattern letters are generic to a CIX100S).
INSTALL_CFG = (
    "#- Stratagy Configuration\r\n"
    "set pbx_type 'CIX100S'\r\n"
    "set hot_box 994\r\n"
    "set error_box 999\r\n"
    "set defaults_box 997\r\n"
    "set security_max_length 16\r\n"
    "set baud1 9600\r\n"
    "set shutdown '2 130'\r\n"
    "#- SMDI/Serial Integration Definitions\r\n"
    "integration 30 'Axxxxxxrrrr0000000000'\r\n"
    "integration 30 'Bxxxxxxbbbb0000000000'\r\n"
    "integration 30 'Siiiiiiiiii'\r\n"
).encode("latin-1")

DIRECTORY = {str(b): n for b, n in [
    (200, "Reception"), (201, "BreakRoom"), (202, "Warehouse"),
    (203, "Shipping"), (204, "FrontDesk"), (205, "Service"),
    (221, "StationA"), (241, "ScratchBox"), (997, "Defaults"),
]}


def _synthetic_card_stream() -> bytes:
    """Build a card->host byte stream shaped like the real capture's content."""
    stream = bytearray()
    stream += b"ATZ\rAT&F&C1&D2L0Q0V0X0E0&K0\r"      # softmodem banner
    stream += L.build_frame(L.T_POLL)                  # idle poll
    stream += L.build_frame(L.T_LOGIN_RESULT, b"VALID")
    stream += L.encode_block(INSTALL_CFG, seq=0x10)    # the INSTALL.CFG read
    stream += L.encode_block(L.directory_blob(DIRECTORY), seq=0x20)
    return bytes(stream)


def test_framing_all_checksums_valid_on_synthetic():
    stream = _synthetic_card_stream()
    frames = [u for u in L.iter_frames(stream) if isinstance(u, L.Frame)]
    assert frames, "no frames parsed"
    assert all(f.cksum_ok for f in frames), "a frame failed the checksum rule"


def test_box_list_and_directory():
    blob = L.reassemble_content(_synthetic_card_stream())
    boxes = R.box_list(blob)
    assert boxes[:3] == ["200", "201", "202"], boxes[:3]
    d = R.parse_directory(blob)
    assert d.get("200") == "Reception"
    assert len(d) >= 8


def test_set_commands_parse_from_capture():
    text = L.reassemble_content(_synthetic_card_stream()).decode("latin-1")
    sets = dict(re.findall(r"set (\w+) '?([^'\r\n]*)'?", text))
    assert sets.get("pbx_type") == "CIX100S"
    assert sets.get("hot_box") == "994"
    assert sets.get("security_max_length") == "16"


def test_integration_strings_parse_from_capture():
    text = L.reassemble_content(_synthetic_card_stream()).decode("latin-1")
    patterns = re.findall(r"integration 30 '([^']+)'", text)
    assert len(patterns) == 3
    assert any(p.startswith("A") for p in patterns)
    assert any(p.startswith("S") for p in patterns)


def test_mailbox_record_decodes_to_model():
    props = R.build_props_segment("241", ext="241H", name="ScratchBox",
                                  comment="ShutDown Box#1")
    ua = R.build_ua_segment(security_code="241997")
    mb = R.decode_mailbox("241", props, ua)
    assert mb.box == "241"                                    # LE32 @ offset 14
    assert mb.extension == "241H"
    assert mb.name == "ScratchBox"
    assert mb.comment == "ShutDown Box#1"
    assert mb.security_code == "241997"
    assert mb.created is not None and mb.modified is not None  # LE32 timestamps
    d = mb.as_dict()
    assert d["raw_props_hex"] and d["raw_ua_hex"]              # kept for writes
    assert any("Unknown A" in u for u in d["unproven"])        # honest labelling


def test_patch_in_place_reproduces_field_change():
    # The UNCONFIRMED write helper edits a captured segment in place, length-
    # preserving — mirrors the captured 241997 -> 9876 transition.
    ua = R.build_ua_segment(security_code="241997")
    assert R.extract_security_code(ua) == "241997"
    rewritten = R.rewrite_security_code(ua, "9876")
    assert R.extract_security_code(rewritten) == "9876"
    assert len(rewritten) == len(ua)                           # NUL-padded


# --------------------------------------------------------------------------
# REAL capture validation (opt-in; no customer data committed)
# --------------------------------------------------------------------------
def _capture_dir():
    d = os.environ.get("SWITCHROOM_VM_CAPTURE_DIR")
    if d and os.path.isdir(d) and os.path.exists(os.path.join(d, "session2.card2app")):
        return d
    return None


def test_framing_against_real_capture_if_present():
    d = _capture_dir()
    if not d:
        print("  (skip: SWITCHROOM_VM_CAPTURE_DIR not set — real capture absent)")
        return
    app = open(os.path.join(d, "session2.app2card"), "rb").read()
    card = open(os.path.join(d, "session2.card2app"), "rb").read()
    cframes = [u for u in L.iter_frames(card) if isinstance(u, L.Frame)]
    aframes = [u for u in L.iter_frames(app) if isinstance(u, L.Frame)]
    assert len(cframes) > 1000 and all(f.cksum_ok for f in cframes)
    assert len(aframes) > 1000 and all(f.cksum_ok for f in aframes)
    log = os.path.join(d, "session2.log")
    if os.path.exists(log):
        a2, c2 = L.streams_from_log(log)
        assert a2 == app and c2 == card, "log reconstruction not byte-for-byte"
    blob = L.reassemble_content(card)
    assert len(R.parse_directory(blob)) >= 20
    text = blob.decode("latin-1")
    assert "set pbx_type 'CIX100S'" in text
    assert re.search(r"integration 30 '", text)


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
