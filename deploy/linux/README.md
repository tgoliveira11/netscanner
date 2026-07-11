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

See [docs/multi-agent.md](../../docs/multi-agent.md).
