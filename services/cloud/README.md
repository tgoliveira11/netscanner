# NetScanner Cloud (self-host)

Minimal near-realtime sync + remote command queue for dedicated agents.

```bash
CLOUD_SITE_TOKEN=secret CLOUD_PORT=8080 pnpm --filter @netscanner/cloud start
```

Agent config:

```
CLOUD_SYNC_ENABLED=true
CLOUD_SYNC_URL=http://cloud-host:8080
CLOUD_SYNC_TOKEN=secret
CLOUD_PII_CONSENT=true
```

API:

- `POST /api/v1/events` — inventory event batch from leader
- `GET /api/v1/events/recent` — read-mostly results UI
- `POST /api/v1/commands` — enqueue remote command
- `GET /api/v1/commands/pending` — control leader pulls commands

Postgres can replace JSONL persistence in a later iteration.
