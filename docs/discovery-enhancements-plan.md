# Implementation Plan — DNS Intelligence · CVE/Vulnerabilities · Per-device Traffic

> Three enhancements that turn NetScanner from *"what is this device"* into
> *"what is it / what does it do / how exposed is it"*. All three plug into the
> **existing** architecture (ports + adapters, composite sources, `IPassiveSignalStore`,
> `device-enrichment.service`, `background-worker`) and reuse patterns already in the
> codebase. Ordered by recommended sequence.

## Cross-cutting design

- Each feature is a **source behind a port** (DIP) with adapter(s) + optional
  **composite** aggregator — same shape as `IRouterLeaseSource` / `IDhcpFingerprintSource`.
- Per-device results land as **`signals`** (audit trail) + a small typed summary on
  `Device` (contracts). Heavy/temporal data lives in a dedicated store, not on `Device`.
- Enrichment happens in **`services/gateway/src/application/device-enrichment.service.ts`**
  (already the orchestration seam), not in `run-scan`.
- New classification/security inference goes into **classification** as pure rules/analyzers.
- Periodic/background work (feed refresh, traffic polling) uses **`background-worker.ts`**.
- **Synergy**: the three combine into one per-device *risk narrative* — e.g. "this Tuya
  plug is vulnerable (CVE), phones home to a non-vendor cloud (DNS), and sends 500 MB/day
  (traffic)". Reserve a unified **`riskScore` + `insights[]`** on `Device` for that.

---

## 1) DNS Query Intelligence  🥇 (do first — lowest effort, capture exists)

**Goal:** per device, know *which domains it talks to* → identify vendor/app, flag
"phones home" / trackers / suspicious endpoints. Excellent for IoT (Tuya/Espressif/etc.).

### Data sources (reuse first)
- **Local:** `DnsPassiveListener` already sniffs `tcpdump :53` and records query names as
  passive signals keyed by client IP. Today it only *avoids* hostname promotion — we will
  *consume* those queries.
- **Cross-VLAN (recommended):** add `RemoteDnsListener` mirroring `RemoteDhcpSniffer`
  (SSH + `tcpdump -i br-lan udp port 53` on the OpenWrt/pfSense bridge) so guest/IoT VLANs
  are covered. Same SSH/persist/hydrate options struct.
- **Alt:** pfSense Unbound query log (enable logging → read via SSH/file). Keep as a
  secondary adapter behind the same port.

### Architecture
- Port `IDnsObservationSource` → `{ clientIp, mac?, domain, at }` stream (adapters:
  local listener, remote listener, unbound-log). `CompositeDnsSource` merges them.
- `packages/kernel` (or classification domain): **`DomainCatalog`** — pattern→
  `{ vendor, service, category }`, e.g. `*.tuya(eu|us)?.com`→{Tuya, IoT cloud, iot},
  `*.ring.com`→{Ring, camera, security-cam}, `*.plex.tv`→{Plex, media, nas},
  `*.icloud.com`→{Apple, apple-services}, plus categories: `ads`, `telemetry`, `cdn`,
  `ntp`, `update`. Ship a curated seed table + `merge()` for extension (mirror `OuiLookup`).
- **`DnsIntelStore`** (in-memory + optional persist): per device → top domains (count,
  first/last seen), distinct-domain count, category tallies, external-endpoint set.
  Reuse/extend `IPassiveSignalStore`.

### Integration
- `device-enrichment.service`: for each device, read its DNS profile → set signals
  `dnsTopDomains`, `dnsCategories`, `dnsVendorHints`, `dnsExternalCount`.
- New **`DnsClassificationRule`** (classification): domain→vendor/deviceType votes
  (e.g. queries `*.tuya.com` ⇒ vendor Tuya, type smart-home). Weighted below Fingerbank,
  above pure heuristics.
- New security flags (SecurityAnalyzer): IoT device contacting many external endpoints /
  known-tracker categories → info/low findings.

### Data model (contracts)
```ts
DeviceSchema.dns = z.object({
  topDomains: z.array(z.object({ domain: z.string(), count: z.number(),
    category: z.string().optional(), vendor: z.string().optional() })),
  categories: z.array(z.string()),
  externalEndpoints: z.number(),
}).nullable().optional();
```

### UI
- Drawer → **"Network activity"** section: top domains (with vendor/category chips),
  external-endpoint count, "phones home to …".
- Optional dashboard panel: "Chattiest devices / unexpected external contacts".

### Config
`DNS_INTEL` (bool), reuse remote-listener creds (host/user/key), `DNS_INTEL_TOP_N`.

### Testing
- Pure unit: `DomainCatalog` matching; DNS line parser; `DnsIntelStore` aggregation;
  `DnsClassificationRule`. (Sniffer I/O stays thin, like existing listeners.)

### Effort: **Low-Med.** Capture + store patterns exist; work is catalog + aggregation +
rule + UI.

---

## 2) CVE / Vulnerability Enrichment  🥈 (highest value — "inventory → security")

**Goal:** turn resolved **model + firmware/OS version** into known-CVE findings and a
per-device risk score. Nothing else in the consumer space does this well.

### Inputs (already resolved)
Vendor/brand/model (`device-identity`, Fingerbank, UPnP), OS/version (nmap `-O`, SMB
`smbOs`, inferred), service `product`+`version` (nmap `-sV` banners), SNMP `sysDescr`.

### Data source
- **Recommended:** local **NVD** mirror queried by **CPE 2.3**. Ingest the NVD JSON feed
  once, refresh via `background-worker` (daily). Offline-friendly (fits a local agent),
  no per-scan API calls, no data leaving the network.
- **Alt/supplement:** NVD 2.0 REST API on-demand (needs `NVD_API_KEY` for rate limit);
  or `OSV`/`vulners`. Keep behind the same port.

### Architecture (new `services/security` or under classification)
- `CpeBuilder` (pure): device identity → candidate CPE strings
  (`cpe:2.3:o:apple:iphone_os:17.*`, `cpe:2.3:h:tuya:*`, `cpe:2.3:a:openssh:openssh:8.4`).
- Port `ICveResolver.match(cpes) → CveFinding[]`; adapter `NvdCveResolver` (indexed local
  feed: map product→CVEs, filter by version range / CVSS).
- `RiskScorer` (pure): aggregate CVEs + existing open-port `SecurityFlag`s + exposure →
  0–100 + severity band.

### Integration
- `device-enrichment.service`: build CPEs → `resolver.match` → attach findings.
- Extend `SecurityFlag` model (or add `vulnerabilities`) — see below.

### Data model (contracts)
```ts
CveFindingSchema = z.object({ cveId: z.string(), cvss: z.number().nullable(),
  severity: z.enum(['low','medium','high','critical']), summary: z.string(),
  url: z.string(), cpe: z.string(), confidence: z.enum(['exact','fuzzy']) });
DeviceSchema.vulnerabilities = z.array(CveFindingSchema).default([]);
DeviceSchema.riskScore = z.number().min(0).max(100).nullable().optional();
```

### UI
- Drawer **Security** section (exists) → CVE list (id, CVSS, summary, link, confidence).
- New dashboard **"Security posture"** panel: devices ranked by risk; counts by severity.
- Export: include CVEs in JSON/CSV.

### Honest caveats (bake into UX)
- CPE/version matching is **fuzzy** → mark findings `confidence: fuzzy` and word as
  "potentially affected". Randomized-MAC/unknown-model devices get no CVEs.
- Feed size: ship an **indexed subset** (by observed vendors) or lazy-load; document the
  refresh job and offline mode.

### Testing
- `CpeBuilder` (identity→CPE), `NvdCveResolver.match` against a fixture feed, `RiskScorer`.

### Effort: **Med.** Feed ingestion + CPE building + matching + UI. Reuses SecurityAnalyzer
pattern, `background-worker`, and already-resolved identity.

---

## 3) Per-device Traffic / Bandwidth  🥉 (completes "is / does / consumes")

**Goal:** bytes in/out, rate, active connections, top peers per device → top-talkers,
behavioral baseline, anomaly input.

### Data sources (pfSense; behind one port, composite)
- **Best:** **ntopng** (pfSense package) — per-host traffic + flows + DNS, has an API.
  Adapter `NtopngTrafficAdapter` if installed.
- **Fallback (no install):** **pf states table** — REST (`/api/v2/diagnostics/...` if
  exposed) or SSH `pfctl -vvs state`, aggregate bytes per source IP. Snapshot → derive
  rates by diffing polls.
- **Coarse:** SNMP/`vnstat` per-interface (not per-host) — only for totals.

### Architecture
- Port `ITrafficSource.sample() → { ip, mac?, bytesIn, bytesOut, conns, topPeers? }[]`;
  adapters above; `CompositeTrafficSource` merges.
- `background-worker` polls every N s → **`TrafficStore`**: per device rolling counters +
  a small ring-buffer time-series (in-memory; optional persist) for sparklines.
- `RateCalculator` (pure): diff consecutive samples → bps.

### Integration
- Enrichment sets signals `trafficBytesIn/Out`, `trafficRateBps`, `activeConnections`,
  `trafficTopPeers`. Feeds future anomaly detection (sudden spike / new peer).

### Data model (contracts)
```ts
DeviceSchema.traffic = z.object({ bytesIn: z.number(), bytesOut: z.number(),
  rateBps: z.number(), connections: z.number(),
  topPeers: z.array(z.object({ ip: z.string(), bytes: z.number() })).optional()
}).nullable().optional();
```
Time-series for graphs stays in `TrafficStore` (queried via a `/api/devices/:id/traffic`).

### UI
- Device row: tiny **sparkline**; drawer **"Traffic"** chart (in/out over time) + top peers.
- Dashboard **"Top talkers"** panel.

### Config
`TRAFFIC_SOURCE=ntopng|pfstates|off`, endpoint/creds, `TRAFFIC_POLL_MS`.

### Testing
- `RateCalculator` (sample diffing), states/ntopng response normalizers (fixture-based,
  like `pfsense-lease-normalize`).

### Effort: **Med** (best case needs ntopng installed; pf-states fallback is more parsing).

---

## Suggested sequencing

1. **DNS Intelligence** — fastest to value; capture exists; big IoT payoff. (~1 focused pass)
2. **CVE** — highest differentiation; depends only on identity we already resolve.
3. **Traffic** — completes the triad; gated by the pfSense data source you enable (ntopng ≫ pf-states).

Then a **unified Insight/Risk layer**: combine CVE + DNS categories + traffic anomalies
into `Device.riskScore` + `insights[]`, and a dashboard "Attention needed" view — the
natural capstone that makes the three worth more together than apart.

## Reuse map (don't rebuild)
- Sniff-via-SSH: `RemoteDhcpSniffer` → clone for DNS/traffic capture.
- Passive store: `IPassiveSignalStore` / `in-memory-passive-signal.store`.
- Catalog table pattern: `OuiLookup` / `oui-db.json` → `DomainCatalog`.
- Composite aggregation: `composite-lease-source` / `composite-connection-source`.
- Orchestration seam: `device-enrichment.service.ts`.
- Periodic jobs: `background-worker.ts`.
- Security findings: `SecurityAnalyzer` + `SecurityFlag`.
- Router adapter/auth patterns: `pfsense-rest.adapter.ts`, `luci-client.ts`.
- Normalizer + fixture test pattern: `pfsense-lease-normalize.ts` (+ its test).
