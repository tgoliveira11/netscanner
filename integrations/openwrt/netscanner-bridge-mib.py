#!/usr/bin/env python3
"""
Expose BRIDGE-MIB FDB for OpenWrt DSA switches via snmpd pass_persist.

Typical DSA layout:
  bridge   br-lan
  VLANs    br-lan.<id>   (management IP often on one VLAN iface)
  members  eth0 .. ethN
  ignore   dsa, br-lan.*, wlan*

NetScanner (SnmpConnectionSource) walks:
  .1.3.6.1.2.1.17.4.3.1.1  dot1dTpFdbAddress
  .1.3.6.1.2.1.17.4.3.1.2  dot1dTpFdbPort
  .1.3.6.1.2.1.17.1.4.1.2  dot1dBasePortIfIndex

pass_persist types must be: integer | string | … (NOT "Hex-STRING").
MAC address column is returned as type "string" with "AA BB CC DD EE FF";
NetScanner also recovers the MAC from the OID index suffix.

Debug / dry-run (no snmpd):
  NETSCANNER_BRIDGE=br-lan /usr/bin/netscanner-bridge-mib --dump
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

BRIDGE = os.environ.get("NETSCANNER_BRIDGE", "br-lan")

OID_BASE = ".1.3.6.1.2.1.17"
OID_FDB_ADDR = OID_BASE + ".4.3.1.1"
OID_FDB_PORT = OID_BASE + ".4.3.1.2"
OID_BASE_PORT_IF = OID_BASE + ".1.4.1.2"
OID_BASE_PORT_IF_LEGACY = OID_BASE + ".4.1.1.2"  # typo some agents walk

CACHE_TTL_SEC = 5.0
# (monotonic_ts, sorted list of table items)
_cache: Optional[Tuple[float, List[Tuple[str, ...]]]] = None

MAC_RE = re.compile(
    r"^([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+dev\s+(\S+)(.*)$",
    re.I,
)


def log(msg: str) -> None:
    sys.stderr.write(f"netscanner-bridge-mib: {msg}\n")
    sys.stderr.flush()


def run(cmd: List[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=5)
    except Exception as exc:
        log(f"cmd failed {' '.join(cmd)}: {exc}")
        return ""


def ifindex(name: str) -> Optional[int]:
    try:
        with open(f"/sys/class/net/{name}/ifindex", "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def bridge_ports(bridge: str) -> List[str]:
    """Physical / DSA member ports of the LAN bridge (not VLAN subifs)."""
    lower = f"/sys/class/net/{bridge}/brif"
    ports: List[str] = []
    if not os.path.isdir(lower):
        return ports
    for name in sorted(os.listdir(lower)):
        if "." in name:  # br-lan.40 etc. if somehow present
            continue
        if name in ("dsa", "lo"):
            continue
        if name.startswith(("br-", "wlan", "phy", "veth", "bat")):
            continue
        # Keep eth*, lan*, wan*, switch* style DSA ports
        ports.append(name)
    return ports


def is_unicast(mac: str) -> bool:
    try:
        return (int(mac.split(":")[0], 16) & 0x01) == 0
    except Exception:
        return False


def parse_fdb(bridge: str) -> List[Tuple[str, str]]:
    """
    Return (mac, port_iface) from Linux bridge FDB.

    Typical DSA lines:
      aa:bb:cc:dd:ee:ff dev eth1 vlan 51 master br-lan
      aa:bb:cc:dd:ee:ff dev eth2 vlan 40 master br-lan offload master br-lan
      aa:bb:cc:dd:ee:ff dev br-lan vlan 40 master br-lan permanent   ← skip
      33:33:… dev br-lan self permanent                               ← skip
    """
    out = run(["bridge", "fdb", "show", "br", bridge])
    if not out.strip():
        out = run(["bridge", "fdb", "show"])

    members = set(bridge_ports(bridge))
    rows: List[Tuple[str, str]] = []

    for raw in out.splitlines():
        line = raw.strip()
        m = MAC_RE.match(line)
        if not m:
            continue
        mac = m.group(1).lower()
        dev = m.group(2)
        rest = m.group(3)

        if not is_unicast(mac):
            continue
        # Local / filter-entry junk
        if " self" in rest or rest.endswith(" self"):
            continue
        # Permanent bridge addresses (switch's own MAC on br-lan / VLANs)
        if "permanent" in rest and "offload" not in rest and "extern_learn" not in rest:
            continue
        # Must belong to our bridge when master is present
        if "master" in rest:
            mm = re.search(r"\bmaster\s+(\S+)", rest)
            if mm and mm.group(1) != bridge:
                continue
        elif members and (dev.split(".")[0] not in members and dev not in members):
            # No master tag and not a known member — ignore
            continue

        # Prefer physical ethN over br-lan / br-lan.N
        base = dev.split(".")[0]
        if base.startswith("br-") or base == "dsa":
            continue
        if members:
            if base in members:
                port = base
            elif dev in members:
                port = dev
            else:
                continue
        else:
            port = base

        rows.append((mac, port))
    return rows


def build_items() -> List[Tuple[str, ...]]:
    global _cache
    now = time.monotonic()
    if _cache and now - _cache[0] < CACHE_TTL_SEC:
        return _cache[1]

    ports = bridge_ports(BRIDGE)
    port_to_bp: Dict[str, int] = {}
    bp_to_ifindex: Dict[int, int] = {}
    for i, name in enumerate(ports, start=1):
        idx = ifindex(name)
        if idx is None:
            continue
        port_to_bp[name] = i
        bp_to_ifindex[i] = idx

    mac_port: Dict[str, int] = {}
    for mac, port_name in parse_fdb(BRIDGE):
        bp = port_to_bp.get(port_name)
        if bp is None:
            continue
        # First seen wins (stable); offload duplicates ignored
        mac_port.setdefault(mac, bp)

    items: List[Tuple[str, ...]] = []
    for mac in sorted(mac_port.keys()):
        bp = mac_port[mac]
        octets = mac.split(":")
        if len(octets) != 6:
            continue
        suffix = ".".join(str(int(o, 16)) for o in octets)
        # Space-separated hex — type "string" for pass_persist (not Hex-STRING)
        mac_str = " ".join(o.upper() for o in octets)
        items.append(("fdb", suffix, mac_str, str(bp)))
    for bp, idx in sorted(bp_to_ifindex.items()):
        items.append(("base", str(bp), str(idx)))

    _cache = (now, items)
    return items


def build_table() -> Dict[str, Tuple[str, str]]:
    table: Dict[str, Tuple[str, str]] = {}
    for item in build_items():
        if item[0] == "fdb":
            _, suffix, mac_str, bp = item
            table[f"{OID_FDB_ADDR}.{suffix}"] = ("string", mac_str)
            table[f"{OID_FDB_PORT}.{suffix}"] = ("integer", bp)
        else:
            _, bp, idx = item
            table[f"{OID_BASE_PORT_IF}.{bp}"] = ("integer", idx)
            table[f"{OID_BASE_PORT_IF_LEGACY}.{bp}"] = ("integer", idx)
    return table


def oid_key(oid: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in oid.lstrip(".").split(".") if x.isdigit())


def sorted_oids(table: Dict[str, Tuple[str, str]]) -> List[str]:
    return sorted(table.keys(), key=oid_key)


def write_result(oid: str, typ: str, val: str) -> None:
    sys.stdout.write(f"{oid}\n{typ}\n{val}\n")
    sys.stdout.flush()


def write_none() -> None:
    sys.stdout.write("NONE\n")
    sys.stdout.flush()


def normalize_oid(oid: str) -> str:
    oid = oid.strip()
    if not oid.startswith("."):
        oid = "." + oid
    return oid


def getnext(oid: str, table: Dict[str, Tuple[str, str]]) -> Optional[str]:
    oid = normalize_oid(oid)
    for candidate in sorted_oids(table):
        if oid_key(candidate) > oid_key(oid):
            return candidate
    return None


def dump() -> int:
    ports = bridge_ports(BRIDGE)
    print(f"bridge={BRIDGE}")
    print(f"ports={ports}")
    for name in ports:
        print(f"  {name} ifIndex={ifindex(name)}")
    print("fdb:")
    for mac, port in parse_fdb(BRIDGE):
        print(f"  {mac} -> {port}")
    print("snmp rows:")
    table = build_table()
    for oid in sorted_oids(table):
        typ, val = table[oid]
        print(f"  {oid} = {typ} {val}")
    print(f"total={len(table)}")
    return 0 if table else 1


def main_persist() -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        cmd = line.strip()
        if not cmd:
            continue
        if cmd == "PING":
            sys.stdout.write("PONG\n")
            sys.stdout.flush()
            continue
        if cmd == "set":
            sys.stdin.readline()
            sys.stdin.readline()
            write_none()
            continue
        if cmd not in ("get", "getnext"):
            continue

        oid_line = sys.stdin.readline()
        if not oid_line:
            break
        oid = normalize_oid(oid_line)

        if not (oid == OID_BASE or oid.startswith(OID_BASE + ".")):
            write_none()
            continue

        table = build_table()
        if cmd == "get":
            hit = table.get(oid)
            if not hit:
                write_none()
                continue
            write_result(oid, hit[0], hit[1])
        else:
            nxt = getnext(oid, table)
            if not nxt:
                write_none()
                continue
            typ, val = table[nxt]
            write_result(nxt, typ, val)


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] in ("--dump", "dump", "-d"):
            raise SystemExit(dump())
        main_persist()
    except Exception as exc:
        log(f"fatal: {exc}")
        raise SystemExit(1)
