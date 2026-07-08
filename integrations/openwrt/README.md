# OpenWrt switch: expose BRIDGE-MIB FDB for NetScanner

OpenWrt DSA switches often answer SNMP **IF-MIB**, but stock `snmpd` usually does
**not** fill **BRIDGE-MIB FDB** (`dot1dTpFdbTable`). NetScanner needs that table to
map MAC → physical port.

This helper publishes it via net-snmp `pass_persist`.

## Typical DSA layout

| Device | Role |
|--------|------|
| `br-lan` | VLAN-aware bridge |
| `br-lan.<id>` | VLAN interfaces (management IP often on one of these) |
| `eth0`…`ethN` | DSA switch ports — FDB targets |
| `dsa` | parent switch device — **ignored by the script** |

Default `NETSCANNER_BRIDGE=br-lan`. Point at the bridge, **not** a VLAN sub-interface.

## 1. Packages on the switch

```sh
opkg update
opkg install snmpd python3
opkg install ip-bridge || opkg install bridge || opkg install ip-full
```

Optional (GUI + local walks only — does **not** replace this helper):

```sh
opkg install luci-app-snmpd snmp-utils
```

Confirm:

```sh
which snmpd python3 bridge
bridge fdb show br br-lan | head
ls /sys/class/net/br-lan/brif   # expect eth0 eth1 …
```

## 2. Install the helper

From your workstation (replace `SWITCH` with the switch management IP or hostname):

```sh
cd /path/to/netscanner
scp integrations/openwrt/netscanner-bridge-mib.py \
    integrations/openwrt/install-bridge-mib.sh \
    root@SWITCH:/tmp/
ssh root@SWITCH 'sh /tmp/install-bridge-mib.sh'
```

Or manually:

```sh
scp integrations/openwrt/netscanner-bridge-mib.py \
  root@SWITCH:/usr/bin/netscanner-bridge-mib
ssh root@SWITCH 'chmod +x /usr/bin/netscanner-bridge-mib'
```

### Dry-run **before** touching snmpd

```sh
/usr/bin/netscanner-bridge-mib --dump
```

Expect:

- `ports=[eth0, eth1, …]`
- `fdb:` lines like `aa:bb:… -> eth2`
- `snmp rows:` under `.1.3.6.1.2.1.17.4.3…`

If `ports=[]` or `fdb` empty, stop and fix (wrong bridge name / no `bridge` binary).

## 3. Wire snmpd

Use a **read-only community** of your choosing (examples below use placeholders).
Restrict by source network when your build supports it.

```
rocommunity YOUR_RO_COMMUNITY default
# better: rocommunity YOUR_RO_COMMUNITY 192.168.0.0/16
pass_persist .1.3.6.1.2.1.17 /usr/bin/netscanner-bridge-mib
```

Or run `install-bridge-mib.sh`, then set the communities to match NetScanner
`SNMP_COMMUNITIES`. On many OpenWrt images UCI regenerates snmpd.conf — prefer a
`config pass` / durable drop-in (see script comments).

Then:

```sh
/etc/init.d/snmpd restart
```

## 4. Validate from your workstation

```sh
snmpwalk -v2c -c YOUR_RO_COMMUNITY SWITCH 1.3.6.1.2.1.17.4.3.1.1
snmpwalk -v2c -c YOUR_RO_COMMUNITY SWITCH 1.3.6.1.2.1.17.1.4.1.2
```

Success:

```text
…17.4.3.1.1.172… = STRING: "AC 8B A9 …"
…17.4.3.1.2.172… = INTEGER: 3
```

Still `No Such Object` → `pass_persist` not loaded / snmpd not restarted.

## 5. NetScanner

```env
SNMP_ENABLED=true
SNMP_SWITCH_HOST=<switch-mgmt-ip>
SNMP_COMMUNITIES=<same-ro-community>
```

After walks work, restart the agent. Devices should gain `connectionBasis` like
`SNMP BRIDGE-MIB port 2 (eth1)`.

## Notes on the exporter

| Topic | Behavior |
|-------|----------|
| pass_persist types | Uses `string` / `integer` (not `Hex-STRING`) |
| FDB filter | Keeps learned/offload entries; drops `self` / bare `permanent` |
| Device `dsa` | Ignored as a port |
| VLAN ifaces `br-lan.N` | Never used as FDB ports — map to `ethN` |
| Dry-run | `--dump` |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Community timeout | Community missing or ACL — fix via `luci-app-snmpd` / conf |
| `No Such Object` on `17.4.3` | Missing `pass_persist` / wrong path / no restart |
| `--dump` with empty fdb | Run `bridge fdb show br br-lan`; install `ip-bridge` |
| `--dump` with empty ports | Check `ls /sys/class/net/br-lan/brif` |
| conf wiped after reboot | UCI regenerates snmpd.conf — keep `pass_persist` in a durable drop-in |

## Files

| File | Role |
|------|------|
| `netscanner-bridge-mib.py` | pass_persist agent (`--dump` supported) |
| `install-bridge-mib.sh` | install + snmpd snippet |
| `snmpd.netscanner.conf` | reference snippet |
| `README.md` | this guide |
