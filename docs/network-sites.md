# Network Sites — isolamento multi-ambiente

NetScanner hoje assume **um inventário global por agente**. Escanear em casa e depois no escritório mistura devices, marca offline errado e sobrescreve dados. Este doc descreve a camada **NetworkSite**: identificar *onde* o agente está, isolar dados por site e fazer **update incremental** ao voltar a locais conhecidos.

## Problema atual

| Comportamento | Impacto |
|---------------|---------|
| `DeviceRecord.mac @unique` global | Mesmo laptop em dois locais colide |
| `findByIp` global | `192.168.1.x` em redes diferentes se funde |
| `markOfflineExcept(seenIds)` global | Scan no hotel marca casa inteira offline |
| Background/presence iteram todo o repo | Ping em IPs que não existem na rede atual |
| Integrações singleton (`PFSENSE_URL`, SNMP…) | Config de casa aplicada em qualquer Wi‑Fi |
| ScanSession só em memória | Sem histórico por local |

## Conceito: NetworkSite

Um **site** é um ambiente de rede reconhecível — casa, escritório, hotel, lab — com inventário **completamente isolado**:

- Devices, DHCP fingerprints, passive signals, speed tests, scan history → escopados por `siteId`
- Ao reconhecer um site existente → **upsert** (atualiza `lastSeen`, presença, serviços)
- Ao estar em site desconhecido → **novo site** (não toca nos outros)
- `markOfflineExcept` → **só devices daquele site**

## Identidade de rede: fingerprint composto (não só geo)

Geolocalização é **um sinal entre vários**, nunca o único. Redes com VPN (como a do lab) podem aparecer em locais físicos diferentes — geo deve ser **desligado ou muito penalizado** quando VPN estiver ativa.

### Sinais coletados (`NetworkObservation`)

Coletados no boot e antes de cada scan:

| Sinal | Fonte | Peso (normal) | Peso (VPN ativa) |
|-------|-------|---------------|------------------|
| **Gateway MAC** | ARP/default route | ★★★★★ | ★★★★★ |
| **Gateway IP** | rota default | ★★★★ | ★★★★ |
| **Primary CIDR(s)** | interfaces locais | ★★★★ | ★★★★ |
| **DNS servers** | DHCP/resolv.conf | ★★★ | ★★★ |
| **Router identity** | pfSense API id, SNMP sysObjectID, LuCI hostname | ★★★★★ | ★★★★★ |
| **Public egress IP** | `GET https://api.ipify.org` ou similar | ★★★ | ★ (VPN muda) |
| **Geolocation** | IP geolocation API ou OS location (opcional) | ★★ | **0** |
| **SSID set** | scan Wi‑Fi local (futuro) | ★★★ | ★★ |
| **VPN detected** | utun/wg/tun, CIDRs overlay (`10.8.*`, `10.14.*`) | flag | flag |

### Detecção de VPN

Marcar `vpnDetected: true` quando **qualquer** condição:

- Interface `utun*`, `tun*`, `wg*` com rota default ou tráfego
- CIDR primário em `isIgnoredScanCidr()` (overlay VPN)
- Gateway interno RFC1918 mas public IP geolocalizado longe (>500 km) **e** latência típica de túnel

Quando VPN ativa:

1. **Não usar geo** para match ou criação de site
2. **Não usar public IP** como identificador primário
3. Confiar em **LAN fingerprint** (gateway MAC, CIDR, router scrape)
4. Se LAN fingerprint ambíguo → pedir confirmação manual na UI

### Algoritmo de match (`ResolveActiveSiteUseCase`)

```
observation = collectNetworkObservation()
candidates = siteRepo.list()

for site in candidates:
  score = weightedScore(observation, site.fingerprint, vpnWeights)

best = max(candidates by score)

if best.score >= MATCH_THRESHOLD (e.g. 0.85):
  return { site: best, action: 'match', confidence: best.score }

if best.score >= AMBIGUOUS_THRESHOLD (e.g. 0.60):
  return { site: null, action: 'confirm', candidates: top3 }

return { site: null, action: 'create', suggestedName: inferName(observation) }
```

**`inferName`**: label do usuário > reverse-geocode do public IP (sem VPN) > `"Network <gateway-ip>"`.

**Atualização de fingerprint**: ao fim de scan bem-sucedido, merge non-destructive no site (novos CIDRs, SSIDs; geo só se `!vpnDetected`).

### Exemplo: casa com VPN

- Em casa **sem VPN**: match por gateway MAC `aa:bb:…` + CIDR `192.168.51.0/24` + pfSense host → site **Casa**
- Em casa **com VPN** para lab: geo pode ser São Paulo ou outro; gateway MAC local ainda é o pfSense → **mesmo site Casa**
- No hotel: gateway MAC diferente, CIDR `192.168.0.0/24`, sem pfSense → **novo site Hotel** (não altera Casa)

## Modelo de dados

### `NetworkSite`

```prisma
model NetworkSite {
  id          String   @id
  name        String
  slug        String   @unique
  createdAt   DateTime @default(now())
  lastSeenAt  DateTime
  // JSON: NetworkFingerprint (gatewayMac, gatewayIp, cidrs[], dns[], routerId, publicIp?, geo?, ssids[])
  fingerprintJson String @default("{}")
  // JSON: per-site integration overrides (pfSense URL, SNMP, scrape targets…)
  integrationsJson String @default("{}")
  isDefault   Boolean  @default(false)

  devices     DeviceRecord[]
  scanSessions ScanSessionRecord[]
  speedTests  SpeedTestRecord[]
}
```

### Escopo em tabelas existentes

```prisma
model DeviceRecord {
  siteId   String
  site     NetworkSite @relation(...)
  // trocar mac @unique por:
  @@unique([siteId, mac])
  @@index([siteId, ip])
  @@index([siteId, isOnline])
}

model DhcpFingerprintRecord {
  siteId String
  @@id([siteId, mac])
}

model PassiveSignalRecord {
  siteId String
  @@id([siteId, ip])
}

model SpeedTestRecord {
  siteId String
  @@index([siteId, measuredAt])
}
```

### Scan sessions persistidos

```prisma
model ScanSessionRecord {
  id         String
  siteId     String
  cidr       String
  scanType   String
  status     String
  startedAt  DateTime
  finishedAt DateTime?
  deviceCount Int?
}
```

## Fluxo de scan (alterado)

```
1. activeSite = resolveActiveSite()     // boot + pre-scan
2. session = createSession(siteId, cidrs)
3. for host in discover(site.cidrs):
     upsertDevice(siteId, host)         // findByMac(siteId, mac)
4. markOfflineExcept(seenIds, siteId)  // só deste site
5. mergeFingerprint(site, observation)
6. persistSession(session)
```

### Background worker

- Resolve site ativo no início de cada ciclo
- `repo.list({ siteId })` para enrich/presence
- Light scan só nos CIDRs do site ativo (ou `listScanCidrs` filtrado)
- Integrações: carregar `site.integrationsJson` merged com env global

### API

| Endpoint | Mudança |
|----------|---------|
| `GET /api/devices` | `?site=<id>` ou site ativo default |
| `GET /api/sites` | lista sites + lastSeen |
| `GET /api/sites/active` | site resolvido + confidence + vpnDetected |
| `POST /api/sites/switch` | override manual (lock site até reboot ou unlock) |
| `POST /api/sites/confirm` | confirma match ambíguo |
| `POST /api/scans` | implicitamente no site ativo |
| `GET /api/topology` | scoped ao site |

Header opcional: `X-NetScanner-Site: <id>` para override em scripts.

## Migração

1. Criar site `default` (`isDefault: true`, name: "Default")
2. `UPDATE DeviceRecord SET siteId = 'default'`
3. Trocar índice `mac @unique` → `@@unique([siteId, mac])`
4. Sites existentes no mesmo DB continuam visíveis; novos locais criam novos sites

## UI

- **Site switcher** no nav: "Casa ▾" / auto-detect badge
- Banner quando `action: confirm` (dois sites parecidos)
- Banner quando VPN: "Geo ignorada — identificação por rede local"
- Admin: editar nome, ver fingerprint, forçar re-match, apagar site

## Config

```env
# Auto-create site when no match (vs prompt only)
SITE_AUTO_CREATE=true

# Match thresholds 0–1
SITE_MATCH_THRESHOLD=0.85
SITE_AMBIGUOUS_THRESHOLD=0.60

# Geolocation provider: ip-api | ipinfo | off
SITE_GEO_PROVIDER=ip-api

# Penalize geo when any utun/tun route exists
SITE_VPN_IGNORE_GEO=true
```

## Fases de implementação

### Fase 1 — Isolamento (MVP)
- Schema `NetworkSite` + `siteId` em DeviceRecord
- `findByMac(siteId, mac)`, `markOfflineExcept(ids, siteId)`
- Match simples: gateway IP + primary CIDR (+ gateway MAC quando disponível)
- Migração default site
- API `GET /api/sites/active`, devices filtrados

### Fase 2 — Fingerprint robusto
- Coleta gateway MAC via ARP
- Router identity (pfSense REST `/api/v2/system/version`)
- Persist scan sessions
- VPN detection + pesos dinâmicos

### Fase 3 — Geolocalização
- Public IP + geo API
- Merge geo no fingerprint (só sem VPN)
- Nome sugerido por reverse geocode

### Fase 4 — Integrações por site
- `integrationsJson` por site
- Container carrega overrides quando site ativo
- Per-site topology config

### Fase 5 — UX travel
- Site switcher, confirmação ambígua
- Export/import site
- SSID fingerprint (mobile)

## O que NÃO fazer

- **Não** identificar site só por geolocalização
- **Não** usar public IP como chave única (CGNAT, VPN, hotspot)
- **Não** marcar offline devices de outros sites
- **Não** apagar site automaticamente (só manual)

## Referências no código (touchpoints)

| Área | Arquivo |
|------|---------|
| Upsert | `services/inventory/src/application/upsert-device.use-case.ts` |
| Offline | `services/inventory/src/infrastructure/prisma-device.repository.ts` |
| Scan | `services/gateway/src/application/run-scan.use-case.ts` |
| Background | `services/gateway/src/application/background-worker.ts` |
| Presence | `services/gateway/src/application/presence-monitor.ts` |
| CIDR | `packages/os-abstraction/src/local-network.ts` |
| Container | `services/gateway/src/container.ts` |
