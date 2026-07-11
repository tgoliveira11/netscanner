# Dedicated Linux agent (Raspberry Pi / mini-PC)

Root-required appliance install. Data directory: `/var/lib/netscanner`.

## Docker Compose

```bash
cd deploy/linux
cp env.dedicated.example .env
docker compose up -d
```

Binds `0.0.0.0:4000` (UI + API) and UDP `4010` (cluster beacon).

## systemd (bare metal)

1. Install Node 20+ and clone/build the monorepo (or install the `.deb`).
2. Copy `netscanner.service` to `/etc/systemd/system/`.
3. `systemctl enable --now netscanner`.

## .deb skeleton

```bash
./scripts/build-deb.sh
sudo dpkg -i dist/netscanner_*.deb
```

## Profiles

| Env | Effect |
|-----|--------|
| `CLUSTER_DEDICATED=true` | Strong election preference |
| `CLUSTER_PREFER_LEADER=true` | Prefer as leader |
| `GATEWAY_HOST=0.0.0.0` | LAN-wide UI |
| `MDNS_ENABLED=true` | Claim `netscanner.local` when leader |
| `AGENT_PROFILE=scan-only` | Scan worker without control/UI weight |
| `UI_ONLY=true` | Mac-style UI peer (no elevated probes) |

## Discovery packages (bare metal)

Install once on the box so elevated probes can run:

```bash
sudo apt update
sudo apt install -y masscan snmp snmp-mibs-downloader fping arping avahi-utils \
  nbtscan tshark lldpd netdiscover
sudo systemctl enable --now lldpd
```

Recommended env (see `env.dedicated.example`): `MASSCAN_ENABLED`, `TSHARK_DEEP_ENABLED`,
`LLDPD_ENABLED`, `NETDISCOVER_ENABLED`, `CVE_NVD_SYNC=false` (offline CVE seed; turn on later
for NVD subset refresh).

## HTTPS (`netscanner.local`)

NetScanner keeps plain HTTP on `:80` / `:4000`. Optional **Caddy** terminates TLS on `:443`
with an internal CA (leaf certs renew automatically; Let’s Encrypt cannot issue for `.local`).

```bash
sudo apt install -y caddy   # or Cloudsmith package — see caddyserver.com/docs/install
sudo cp /opt/netscanner/deploy/linux/Caddyfile /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
# after first start:
sudo cp /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt \
  /var/lib/netscanner/caddy-root.crt
sudo chmod 644 /var/lib/netscanner/caddy-root.crt
```

- UI: `https://netscanner.local/` (or `https://192.168.40.110/`)
- CA for clients: `https://netscanner.local/netscanner-ca.crt` (install once in the OS trust store)
- HTTP URLs continue to work unchanged

See [docs/multi-agent.md](../../docs/multi-agent.md).
