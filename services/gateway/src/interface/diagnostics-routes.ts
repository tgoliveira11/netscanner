import type { FastifyInstance } from 'fastify';
import {
  CameraScanRequestSchema,
  DnsLookupRequestSchema,
  PingRequestSchema,
  PortScanRequestSchema,
  TracerouteRequestSchema,
  type WifiAp,
} from '@netscanner/contracts';
import { mergeRouterScrapeTargets } from '@netscanner/config';
import { probeOpenWrtWireless, probeOpenWrtWifiNeighbors } from '@netscanner/discovery';
import type { Container } from '../container.js';
import {
  analyzeWifi,
  computeChannelCollisions,
  inferBandFromRadio,
  type OwnNetworkInput,
} from '../application/wifi-analysis.service.js';

function hostFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function registerDiagnosticsRoutes(app: FastifyInstance, c: Container): void {
  app.post('/api/diagnostics/ping', async (request, reply) => {
    const parsed = PingRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    if (c.sessions.activeScan()) return reply.status(409).send({ error: 'scan in progress' });
    return c.diagnostics.ping(parsed.data.ip, parsed.data.count);
  });

  app.post('/api/diagnostics/traceroute', async (request, reply) => {
    const parsed = TracerouteRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    return c.diagnostics.traceroute(parsed.data.ip, parsed.data.maxHops);
  });

  app.post('/api/diagnostics/dns', async (request, reply) => {
    const parsed = DnsLookupRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    return c.diagnostics.dnsLookup(parsed.data.name, parsed.data.type, parsed.data.server);
  });

  app.post('/api/diagnostics/port-scan', async (request, reply) => {
    const parsed = PortScanRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    if (c.sessions.activeScan()) return reply.status(409).send({ error: 'scan in progress' });
    return c.diagnostics.portScan(parsed.data.ip, parsed.data.depth);
  });

  /** Local RF only — used by cluster peers; must not be reverse-proxied to the leader. */
  app.get('/api/diagnostics/wifi-rf', async () => c.diagnostics.wifiScan());

  app.get('/api/diagnostics/wifi', async () => {
    let local = await c.diagnostics.wifiScan();
    const peerRfNotes: string[] = [];

    // Dedicated Linux leaders have no Wi‑Fi radio — pull CoreWLAN scans from Mac helpers.
    const localUseful = local.aps.some((a) => a.source === 'local' || a.source == null);
    if (!localUseful) {
      const peers = c.cluster.listWifiRfPeers();
      for (const peer of peers) {
        try {
          const url = `${c.cluster.peerBaseUrl(peer)}/api/diagnostics/wifi-rf`;
          const res = await fetch(url, { signal: AbortSignal.timeout(55_000) });
          if (!res.ok) {
            peerRfNotes.push(`${peer.hostname}: HTTP ${res.status}`);
            continue;
          }
          const body = (await res.json()) as Awaited<ReturnType<typeof c.diagnostics.wifiScan>>;
          const peerAps = (body.aps ?? []).map((a) => ({
            ...a,
            source: (a.source === 'router' ? 'router' : 'nearby') as WifiAp['source'],
          }));
          if (!peerAps.length) {
            peerRfNotes.push(`${peer.hostname}: empty scan`);
            continue;
          }
          local = {
            ...local,
            currentSsid: local.currentSsid ?? body.currentSsid ?? null,
            currentChannel: local.currentChannel ?? body.currentChannel,
            currentBand: local.currentBand ?? body.currentBand,
            connectedInferred: local.connectedInferred ?? body.connectedInferred,
            aps: [...local.aps, ...peerAps],
            note: body.note ?? local.note,
          };
          peerRfNotes.push(`${peer.hostname}: ${peerAps.length} AP(s)`);
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          peerRfNotes.push(`${peer.hostname}: ${msg}`);
          c.logger.warn({ peer: peer.hostname, error: msg }, 'peer Wi‑Fi RF scan failed');
        }
      }
    }

    const creds = await c.repo.listRouterScrapeCredentials(c.activeSite.getActiveSiteId() ?? '00000000-0000-4000-8000-000000000001');
    const targets = mergeRouterScrapeTargets(
      c.config,
      creds.map((row) => ({
        ip: row.ip,
        mac: row.mac,
        deviceType: row.deviceType,
        brand: row.brand,
        hostname: row.hostname,
        isOnline: row.isOnline,
        routerScrapeUser: row.routerScrapeUser,
        routerScrapePassword: row.routerScrapePassword,
      })),
    );

    if (!targets.length) {
      const analysis = analyzeWifi({ currentSsid: local.currentSsid, aps: local.aps });
      return {
        ...local,
        channelCollisions: computeChannelCollisions(local.aps),
        analysis,
        note:
          local.note ??
          (peerRfNotes.length
            ? `RF via peer: ${peerRfNotes.join('; ')}`
            : undefined),
      };
    }

    const routerTargets = targets.map((t) => ({
      baseUrl: t.baseUrl,
      kind: t.kind,
      username: t.username,
      password: t.password,
    }));

    const routers = await probeOpenWrtWireless(routerTargets, c.logger);
    const ownNetworks: OwnNetworkInput[] = [];
    const routerAps: WifiAp[] = [];

    for (const r of routers) {
      const routerHost = hostFromUrl(r.url);
      for (const s of r.ssids.filter((row) => row.ssid)) {
        const channel = typeof s.channel === 'number' ? s.channel : Number(s.channel) || undefined;
        const band = inferBandFromRadio(s.device ?? s.ifname, channel);
        ownNetworks.push({
          ssid: s.ssid,
          channel,
          mode: s.mode,
          device: s.device,
          ifname: s.ifname,
          up: s.up,
          routerHost,
          clients: s.clients?.map((cl) => ({ mac: cl.mac, signal: cl.signal })),
        });
        routerAps.push({
          ssid: s.ssid,
          channel,
          security: s.mode ?? undefined,
          source: 'router',
          band,
          radioDevice: s.device ?? s.ifname,
          isOwnNetwork: true,
          routerHost,
        });
      }
    }

    const neighborScans = await probeOpenWrtWifiNeighbors(routerTargets, c.logger);
    const ownSsids = new Set(routerAps.map((a) => a.ssid.toLowerCase()));
    const neighborAps: WifiAp[] = neighborScans.flatMap((r) =>
      r.neighbors
        .filter((n) => n.ssid && !ownSsids.has(n.ssid.toLowerCase()))
        .map((n) => ({
          ssid: n.ssid,
          bssid: n.bssid,
          channel: n.channel,
          rssi: n.rssi,
          security: n.security,
          source: 'nearby' as const,
          band: inferBandFromRadio(n.device, n.channel),
          radioDevice: n.device,
        })),
    );

    const seen = new Set(local.aps.map((a) => `${a.ssid}|${a.bssid ?? ''}|${a.channel ?? ''}|${a.source ?? 'local'}`));
    const merged = [...local.aps];
    for (const ap of [...routerAps, ...neighborAps]) {
      const key = `${ap.ssid}|${ap.bssid ?? ''}|${ap.channel ?? ''}|${ap.source}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(ap);
    }

    const hasNearby = neighborAps.length > 0 || merged.some((a) => a.source === 'nearby' || a.source === 'local');
    const hasHiddenLocal = merged.some((a) => a.ssid.startsWith('(SSID hidden'));
    const noteParts: string[] = [];
    if (local.note) noteParts.push(local.note);
    if (peerRfNotes.length) noteParts.push(`RF peer: ${peerRfNotes.join('; ')}`);
    if (hasNearby && !local.note) {
      noteParts.push('Vizinhos via scan do Mac/AP + SSIDs configurados nos seus APs.');
    } else if (routerAps.length && !hasNearby) {
      noteParts.push(
        hasHiddenLocal
          ? 'SSIDs do modem/AP via scrape. macOS oculta nomes — habilite Location Services para /usr/bin/swift.'
          : 'Só SSIDs dos seus APs (scrape). Scan iwinfo no Compal bloqueado (403); use um Mac no cluster para RF.',
      );
    }

    const analysis = analyzeWifi({
      currentSsid: local.currentSsid,
      aps: merged,
      ownNetworks,
    });

    return {
      ...local,
      aps: merged,
      channelCollisions: computeChannelCollisions(merged),
      note: noteParts.filter(Boolean).join(' ') || undefined,
      analysis,
    };
  });

  app.post('/api/diagnostics/camera-scan', async (request) => {
    const parsed = CameraScanRequestSchema.safeParse(request.body ?? {});
    const body = parsed.success ? parsed.data : {};
    return c.diagnostics.cameraScan({
      cidr: body.cidr,
      travelMode: body.travelMode,
    });
  });
}
