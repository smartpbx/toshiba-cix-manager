"""P2 capture validation: encode_set_request == the real SNMP SET bytes.

The whole proven write path is four varbinds, captured on-site from a live
eManager <-> CIX session (emanager-re/WRITE_FORMAT.md, from
captures/emanager-session1-final.pcap):

    1.3.6.1.4.1.186.1.22.7.7.1.0            = INTEGER 2          (apply / commit)
    1.3.6.1.4.1.186.1.22.3.2.3.1.1.4.1      = OCTET STRING "/"
    1.3.6.1.4.1.186.1.22.3.2.3.1.1.2.1      = OCTET STRING "sysadmin"
    1.3.6.1.4.1.186.1.22.3.2.3.1.1.3.1      = OCTET STRING "wksi76dbga"

This locks ``write.py``'s BER SET encoder to those exact bytes so the wire
format can never silently drift. The INTEGER varbind (ASN.1 tag 0x02, value 2)
is the commit/apply SET; it is modelled by ``commit_write_op`` and labelled
unproven-persistence (no reboot in the capture) and unproven-row-create.

Run:  python3 tests/test_write_capture.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix.write import (WriteOp, commit_write_op,  # noqa: E402
                               encode_set_request)
from toshiba_cix.snmp import ber_integer, ber_octet  # noqa: E402

ROOT = "1.3.6.1.4.1.186.1.22"
COMMUNITY = "communityName"
RID = 6

# Ground truth, verified by hand against the BER structure.
# Frame 634: the three-field FTP-credential SET (OCTET STRINGs).
GOLDEN_FTP = (
    "3074020101040d636f6d6d756e6974794e616d65a36002010602010002010030553015"
    "06102b06010401813a01160302030101040104012f301c06102b06010401813a011603"
    "020301010201040873797361646d696e301e06102b06010401813a0116030203010103"
    "01040a776b7369373664626761"
)
# The apply/commit SET: 1.3.6.1.4.1.186.1.22.7.7.1.0 = INTEGER 2.
#   30 33                                 SEQUENCE
#     02 01 01                            version = 1 (v2c)
#     04 0d communityName                 community
#     a3 1f                               SetRequest PDU
#       02 01 06  02 01 00  02 01 00      request-id 6, err 0, idx 0
#       30 14                             varbind-list
#         30 12                           varbind
#           06 0d 2b06010401813a011607070100   OID …22.7.7.1.0
#           02 01 02                      INTEGER 2   <- proven integer write
GOLDEN_COMMIT = (
    "3033020101040d636f6d6d756e6974794e616d65a31f0201060201000201003014301206"
    "0d2b06010401813a011607070100020102"
)


def _ftp_ops():
    base = f"{ROOT}.3.2.3.1.1"
    return [
        WriteOp("ftp_path", "FTP path", "/", target_oid=f"{base}.4.1"),
        WriteOp("ftp_user", "FTP user", "sysadmin", target_oid=f"{base}.2.1"),
        WriteOp("ftp_pass", "FTP pass", "wksi76dbga", target_oid=f"{base}.3.1"),
    ]


def test_commit_op_is_the_proven_integer_set():
    op = commit_write_op()
    assert op.target_oid == f"{ROOT}.7.7.1.0"
    assert op.ber_type == "INTEGER" and op.native_wire == "INTEGER"
    assert op.wire_proven is True and op.op_class == "commit"
    assert op.encode_value() == ber_integer(2) == bytes.fromhex("020102")
    assert "UNPROVEN" in op.note  # persistence / row-create are unproven


def test_encode_set_request_commit_is_byte_identical():
    pkt = encode_set_request(COMMUNITY, [commit_write_op()], RID)
    assert pkt.hex() == GOLDEN_COMMIT
    # the value varbind is an ASN.1 INTEGER (tag 0x02), not an OCTET STRING.
    assert pkt.endswith(bytes.fromhex("020102"))


def test_encode_set_request_ftp_batch_is_byte_identical():
    pkt = encode_set_request(COMMUNITY, _ftp_ops(), RID)
    assert pkt.hex() == GOLDEN_FTP


def test_all_four_value_tlvs_match_capture():
    # The four value TLVs, isolated, are exactly the capture's.
    assert ber_integer(2).hex() == "020102"
    assert ber_octet("/").hex() == "04012f"
    assert ber_octet("sysadmin").hex() == "040873797361646d696e"
    assert ber_octet("wksi76dbga").hex() == "040a776b7369373664626761"


def test_four_varbinds_round_through_encode_set_request():
    # All four, driven through the WriteOp encoder (commit + 3 data), produce
    # the two capture PDUs — the complete proven write path, no bare OIDs.
    commit = encode_set_request(COMMUNITY, [commit_write_op()], RID)
    data = encode_set_request(COMMUNITY, _ftp_ops(), RID)
    assert (commit.hex(), data.hex()) == (GOLDEN_COMMIT, GOLDEN_FTP)


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
