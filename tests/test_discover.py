"""Offline tests for the LAN auto-discovery parsers and SNMP verify.

The OS-touching bits (ping sweep, reading the ARP table, enumerating
interfaces) are not exercised here; the *parsers* they feed are, against
captured command output from each platform, so discovery logic is verified
with no network.

Run:  python3 tests/test_discover.py   (or: python3 -m pytest tests/)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from toshiba_cix import discover as DISC  # noqa: E402
from toshiba_cix.snmp import Value, VarBind  # noqa: E402


# -- MAC / OUI --------------------------------------------------------------
def test_mac_normalize_and_oui():
    assert DISC.normalize_mac("E8-E0-B7-CC-58-F5") == "e8e0b7cc58f5"
    assert DISC.normalize_mac("e8:e0:b7:cc:58:f5") == "e8e0b7cc58f5"
    assert DISC.mac_oui("E8:E0:B7:00:11:22") == "e8e0b7"
    assert DISC.is_toshiba_mac("e8:9d:87:aa:bb:cc")
    assert DISC.is_toshiba_mac("E8-E0-B7-CC-58-F5")
    assert not DISC.is_toshiba_mac("00:11:22:33:44:55")


# -- ARP table parsing (three field shapes) --------------------------------
def test_parse_ip_neigh():
    out = (
        "192.168.254.253 dev eth0 lladdr e8:e0:b7:cc:58:f5 REACHABLE\n"
        "192.168.254.1 dev eth0 lladdr 00:0c:29:11:22:33 STALE\n"
        "192.168.254.99 dev eth0  FAILED\n"       # no MAC -> skipped
    )
    rows = DISC.parse_arp_table(out)
    assert {r["ip"] for r in rows} == {"192.168.254.253", "192.168.254.1"}
    byip = {r["ip"]: r["mac"] for r in rows}
    assert byip["192.168.254.253"] == "e8e0b7cc58f5"


def test_parse_unix_arp_a():
    out = ("cix (192.168.254.253) at e8:e0:b7:cc:58:f5 [ether] on eth0\n"
           "? (192.168.254.1) at 00:0c:29:11:22:33 [ether] on eth0\n")
    rows = DISC.parse_arp_table(out)
    cands = DISC.toshiba_candidates(rows)
    assert len(cands) == 1
    assert cands[0]["ip"] == "192.168.254.253"
    assert cands[0]["oui"] == "e8e0b7"
    assert cands[0]["via"] == "arp-oui"


def test_parse_windows_arp_a():
    out = ("Interface: 192.168.254.10 --- 0x5\n"
           "  Internet Address      Physical Address      Type\n"
           "  192.168.254.253       e8-9d-87-aa-bb-cc     dynamic\n"
           "  192.168.254.1         00-0c-29-11-22-33     dynamic\n")
    rows = DISC.parse_arp_table(out)
    byip = {r["ip"]: r["mac"] for r in rows}
    assert byip["192.168.254.253"] == "e89d87aabbcc"
    assert DISC.is_toshiba_mac(byip["192.168.254.253"])


# -- interface enumeration parsing -----------------------------------------
def test_parse_ip_addr_linux():
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
           "2: eth0    inet 192.168.254.10/24 brd 192.168.254.255 scope global eth0\n")
    nets = DISC.parse_ip_addr(out)
    assert {"iface": "eth0", "ip": "192.168.254.10", "prefixlen": 24} in nets


def test_parse_ifconfig_macos():
    out = ("en0: flags=8863<UP> mtu 1500\n"
           "\tinet 192.168.254.20 netmask 0xffffff00 broadcast 192.168.254.255\n")
    nets = DISC.parse_ifconfig(out)
    assert nets == [{"iface": "en0", "ip": "192.168.254.20", "prefixlen": 24}]


def test_parse_ipconfig_windows():
    out = ("Ethernet adapter Ethernet:\n"
           "   IPv4 Address. . . . . . . . . . . : 192.168.254.30\n"
           "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n")
    nets = DISC.parse_ipconfig(out)
    assert nets == [{"iface": "?", "ip": "192.168.254.30", "prefixlen": 24}]


# -- conventional .253 candidate -------------------------------------------
def test_conventional_candidate():
    nets = [{"iface": "eth0", "ip": "192.168.254.10", "prefixlen": 24}]
    cands = DISC.conventional_candidates(nets)
    assert cands[0]["ip"] == "192.168.254.253"
    assert cands[0]["via"] == "convention-.253"
    # A huge mask is skipped so a discovery can't try to sweep the internet.
    assert DISC.conventional_candidates(
        [{"iface": "x", "ip": "10.0.0.1", "prefixlen": 8}]) == []


# -- SNMP verify (fake client) ---------------------------------------------
class _FakeVerifyClient:
    def __init__(self, ip, community, *, port=161, timeout=1.5, retries=0):
        self.ip = ip
        self.community = community

    def get(self, oids):
        vals = {
            DISC.SOFTWARE_ID_OID: Value("octet", raw=b"NA520MT067PNDN2---EM.00"),
            DISC.CHASSIS_MAC_OID: Value("octet", raw=bytes.fromhex("e8e0b7cc58f5")),
        }
        return [VarBind(o, vals.get(o, Value("missing"))) for o in oids]


class _DeadClient:
    def __init__(self, *a, **k):
        pass

    def get(self, oids):
        from toshiba_cix.snmp import SnmpError
        raise SnmpError("no response")


def test_snmp_verify_ok():
    r = DISC.snmp_verify("192.168.254.253", client_factory=_FakeVerifyClient)
    assert r["verified"] is True
    assert r["software_id"] == "NA520MT067PNDN2---EM.00"
    assert r["chassis_mac"] == "e8:e0:b7:cc:58:f5"


def test_snmp_verify_dead():
    r = DISC.snmp_verify("192.168.254.9", client_factory=_DeadClient)
    assert r["verified"] is False
    assert "error" in r


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
