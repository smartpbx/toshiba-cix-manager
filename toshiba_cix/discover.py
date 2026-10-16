"""Auto-discover a Toshiba Strata CIX processor on the local LAN (pure stdlib).

A tech plugs a laptop straight into the PBX voice-LAN port and wants the CIX's
IP without knowing it. This module finds it three cheap ways and verifies by
SNMP:

1. **Toshiba MAC OUI.** CIX processors answer ARP with a Toshiba OUI —
   ``E8:E0:B7`` or ``E8:9D:87`` (``TOSHIBA_OUIS``). We populate the ARP cache
   with a short ping sweep of the local /24 and then read the system ARP /
   neighbour table, keeping entries with a Toshiba OUI.
2. **Convention.** The processor is conventionally at ``<subnet>.253`` — always
   offered as a candidate even if ARP missed it.
3. **SNMP verification.** Each candidate is probed with a single SNMPv1 GET of
   the software-id OID using the given community; only a real reply (an octet
   string) marks it ``verified`` and carries the software id + chassis MAC back.

The OS-touching bits (``subprocess`` ping / arp, interface enumeration) are
isolated from the **parsers**, which are pure string→data functions so they
unit-test offline against captured command output on every platform.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess

from .decode import ENTERPRISE_ROOT, decode_value
from .snmp import SnmpError, SnmpV1

# Toshiba OUIs seen on CIX processors (lower-case, no separators).
TOSHIBA_OUIS = frozenset({"e8e0b7", "e89d87"})

# The software-id scalar — a cheap, unambiguous "is this a CIX?" probe.
SOFTWARE_ID_OID = f"{ENTERPRISE_ROOT}.7.2.1.0"
CHASSIS_MAC_OID = f"{ENTERPRISE_ROOT}.7.9.1.0"

_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
_WIN_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# --------------------------------------------------------------------------
# pure parsers (unit-tested offline)
# --------------------------------------------------------------------------
def normalize_mac(mac: str) -> str:
    """``E8-E0-B7-CC-58-F5`` / ``e8:e0:b7:cc:58:f5`` -> ``e8e0b7cc58f5``."""
    return re.sub(r"[^0-9a-fA-F]", "", mac).lower()


def mac_oui(mac: str) -> str:
    """First three octets of a MAC, normalised (``e8e0b7``)."""
    return normalize_mac(mac)[:6]


def is_toshiba_mac(mac: str) -> bool:
    return mac_oui(mac) in TOSHIBA_OUIS


def parse_arp_table(output: str) -> list[dict]:
    """Parse ``arp -a`` / ``ip neigh`` output into ``[{ip, mac}]``.

    Handles the three shapes seen in the field:
      * Linux ``ip neigh``:  ``192.168.254.253 dev eth0 lladdr e8:e0:b7:.. REACHABLE``
      * Unix ``arp -a``:     ``cix (192.168.254.253) at e8:e0:b7:.. [ether] on eth0``
      * Windows ``arp -a``:  ``  192.168.254.253   e8-e0-b7-..   dynamic``
    Incomplete / MAC-less lines are skipped.
    """
    rows: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        ipm = _IP_RE.search(line)
        macm = _MAC_RE.search(line)
        if not ipm or not macm:
            continue
        rows.append({"ip": ipm.group(0), "mac": normalize_mac(macm.group(0))})
    return rows


def parse_ip_addr(output: str) -> list[dict]:
    """Parse ``ip -o -4 addr show`` into ``[{iface, ip, prefixlen}]`` (Linux)."""
    out: list[dict] = []
    for line in output.splitlines():
        # e.g.: "2: eth0    inet 192.168.254.10/24 brd ... scope global eth0"
        m = re.search(r"^\s*\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
                      line)
        if m:
            out.append({"iface": m.group(1), "ip": m.group(2),
                        "prefixlen": int(m.group(3))})
    return out


def parse_ifconfig(output: str) -> list[dict]:
    """Parse BSD/macOS ``ifconfig`` output into ``[{iface, ip, prefixlen}]``."""
    out: list[dict] = []
    iface = "?"
    for line in output.splitlines():
        head = re.match(r"^(\S+):\s", line)
        if head:
            iface = head.group(1)
            continue
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", line)
        if m:
            ip = m.group(1)
            mask = m.group(2)
            if mask.startswith("0x"):
                bits = bin(int(mask, 16)).count("1")
            else:
                bits = _mask_to_prefix(mask)
            out.append({"iface": iface, "ip": ip, "prefixlen": bits})
    return out


def parse_ipconfig(output: str) -> list[dict]:
    """Parse Windows ``ipconfig`` output into ``[{iface, ip, prefixlen}]``."""
    out: list[dict] = []
    ip = None
    for line in output.splitlines():
        m = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            ip = m.group(1)
            continue
        m = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m and ip:
            out.append({"iface": "?", "ip": ip,
                        "prefixlen": _mask_to_prefix(m.group(1))})
            ip = None
    return out


def _mask_to_prefix(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return 24


def toshiba_candidates(arp_rows: list[dict]) -> list[dict]:
    """Keep the ARP rows whose MAC is a Toshiba OUI."""
    return [{"ip": r["ip"], "mac": r["mac"], "oui": mac_oui(r["mac"]),
             "via": "arp-oui"}
            for r in arp_rows if is_toshiba_mac(r["mac"])]


def conventional_candidates(networks: list[dict]) -> list[dict]:
    """``<network>.253`` for each local /24-ish network (the CIX convention)."""
    out: list[dict] = []
    for net in networks:
        try:
            iface_net = ipaddress.ip_network(
                f"{net['ip']}/{net['prefixlen']}", strict=False)
        except ValueError:
            continue
        if iface_net.version != 4 or iface_net.prefixlen < 23:
            continue
        guess = str(iface_net.network_address + 253)
        if ipaddress.ip_address(guess) in iface_net:
            out.append({"ip": guess, "mac": None, "oui": None,
                        "via": "convention-.253"})
    return out


# --------------------------------------------------------------------------
# OS-touching helpers (not unit-tested against the live network)
# --------------------------------------------------------------------------
def primary_ipv4() -> str | None:
    """Best-effort local IPv4 via a connect-less UDP socket (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def local_networks() -> list[dict]:
    """Enumerate local IPv4 networks, best-effort and cross-platform."""
    system = platform.system().lower()
    nets: list[dict] = []
    try:
        if system == "windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=5).stdout
            nets = parse_ipconfig(out)
        elif system == "linux":
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                                 capture_output=True, text=True,
                                 timeout=5).stdout
            nets = parse_ip_addr(out)
        else:  # darwin / bsd
            out = subprocess.run(["ifconfig"], capture_output=True, text=True,
                                 timeout=5).stdout
            nets = parse_ifconfig(out)
    except (OSError, subprocess.SubprocessError):
        nets = []
    # Drop loopback / link-local and de-dup by (ip, prefixlen).
    seen = set()
    filtered = []
    for n in nets:
        if n["ip"].startswith(("127.", "169.254.")):
            continue
        key = (n["ip"], n["prefixlen"])
        if key in seen:
            continue
        seen.add(key)
        filtered.append(n)
    # Fallback: the connect-less primary IP as a /24 if enumeration found none.
    if not filtered:
        ip = primary_ipv4()
        if ip and not ip.startswith(("127.", "169.254.")):
            filtered.append({"iface": "?", "ip": ip, "prefixlen": 24})
    return filtered


def _ping_cmd(ip: str) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "500", ip]
    if system == "darwin":
        return ["ping", "-c", "1", "-W", "500", "-t", "1", ip]
    return ["ping", "-c", "1", "-W", "1", ip]  # linux


def _ping(ip: str) -> bool:
    try:
        r = subprocess.run(_ping_cmd(ip), capture_output=True, timeout=3)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ping_sweep(network: str, *, workers: int = 64, max_hosts: int = 512) -> int:
    """Ping every host in ``network`` to populate the ARP cache. Returns count
    of responders. Bounded to ``max_hosts`` so a wide mask can't melt the NIC."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return 0
    hosts = list(net.hosts())
    if len(hosts) > max_hosts:
        return 0
    alive = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for ok in pool.map(_ping, [str(h) for h in hosts]):
            alive += 1 if ok else 0
    return alive


def read_arp() -> list[dict]:
    """Read the system ARP / neighbour table (best-effort, cross-platform)."""
    system = platform.system().lower()
    cmds = (["ip", "neigh"], ["arp", "-a"]) if system == "linux" else \
           (["arp", "-a"],)
    for cmd in cmds:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        rows = parse_arp_table(out)
        if rows:
            return rows
    return []


def snmp_verify(ip: str, community: str = "communityName", *, port: int = 161,
                timeout: float = 1.5, client_factory=SnmpV1) -> dict:
    """Probe one IP with a single SNMP GET of the software id.

    ``client_factory`` is injectable so tests can pass a fake. Returns
    ``{ip, verified, software_id?, chassis_mac?, error?}``.
    """
    result = {"ip": ip, "verified": False}
    try:
        client = client_factory(ip, community, port=port, timeout=timeout,
                                retries=0)
        vbs = client.get([SOFTWARE_ID_OID, CHASSIS_MAC_OID])
    except SnmpError as exc:
        result["error"] = str(exc)
        return result
    except Exception as exc:  # noqa: BLE001 - never let discovery crash
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    by_oid = {vb.oid: vb.value for vb in vbs}
    sw = by_oid.get(SOFTWARE_ID_OID)
    if sw is not None and not sw.is_missing and sw.kind == "octet" and sw.raw:
        result["verified"] = True
        result["software_id"] = decode_value(sw)
        mac = by_oid.get(CHASSIS_MAC_OID)
        if mac is not None and mac.kind == "octet" and mac.raw:
            result["chassis_mac"] = decode_value(mac, as_mac=True)
    return result


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------
def discover_cix(community: str = "communityName", *, port: int = 161,
                 do_ping: bool = True, verify: bool = True,
                 timeout: float = 1.5, client_factory=SnmpV1,
                 logger=None) -> dict:
    """Find candidate CIX processors on the local LAN.

    Returns ``{networks, candidates, verified}`` where ``candidates`` is the
    union of Toshiba-OUI ARP hits and the ``.253`` convention, each optionally
    SNMP-verified. Never raises — a discovery failure degrades to an empty list.
    """
    networks = local_networks()
    if do_ping:
        for net in networks:
            try:
                cidr = str(ipaddress.ip_network(
                    f"{net['ip']}/{net['prefixlen']}", strict=False))
                ping_sweep(cidr)
            except ValueError:
                continue

    arp_rows = read_arp()
    candidates: dict[str, dict] = {}
    for c in toshiba_candidates(arp_rows):
        candidates[c["ip"]] = c
    for c in conventional_candidates(networks):
        candidates.setdefault(c["ip"], c)

    cand_list = list(candidates.values())
    verified: list[dict] = []
    if verify:
        for c in cand_list:
            v = snmp_verify(c["ip"], community, port=port, timeout=timeout,
                            client_factory=client_factory)
            c.update({k: val for k, val in v.items() if k != "ip"})
            if v.get("verified"):
                verified.append(c)
    return {
        "networks": networks,
        "candidates": cand_list,
        "verified": verified,
    }


__all__ = [
    "TOSHIBA_OUIS", "SOFTWARE_ID_OID", "CHASSIS_MAC_OID",
    "normalize_mac", "mac_oui", "is_toshiba_mac",
    "parse_arp_table", "parse_ip_addr", "parse_ifconfig", "parse_ipconfig",
    "toshiba_candidates", "conventional_candidates",
    "primary_ipv4", "local_networks", "ping_sweep", "read_arp",
    "snmp_verify", "discover_cix",
]
