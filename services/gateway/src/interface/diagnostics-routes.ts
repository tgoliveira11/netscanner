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

  app.get('/api/diagnostics/wifi', async () => {
    const local = await c.diagnostics.wifiScan();
    const creds = await c.repo.listRouterScrapeCredentials(c.activeSite.getActiveSiteId() ?? '00000000-0000-4000-8000-000000000001');
    const targets = mergeRouterScrapeTargets(
      c.config,
      creds.map((row) => ({
        ip: row.ip,
        deviceType: row.deviceType,
        brand: row.brand,
        hostname: row.hostname,
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

    const seen = new Set(local.aps.map((a) => `${a.ssid}|${a.bssid ?? ''}|${a.source ?? 'local'}`));
    const merged = [...local.aps];
    for (const ap of [...routerAps, ...neighborAps]) {
      const key = `${ap.ssid}|${ap.bssid ?? ''}|${ap.source}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(ap);
    }

    const hasNearby = neighborAps.length > 0;
    const hasHiddenLocal = local.aps.some((a) => a.ssid.startsWith('(SSID hidden'));
    const note =
      local.note ??
      (hasNearby
        ? 'Vizinhos via scan iwinfo do AP + SSIDs configurados + visão deste Mac.'
        : routerAps.length
          ? hasHiddenLocal
            ? 'SSIDs do modem/AP via scrape. macOS oculta vizinhos — habilite Location Services ou use AP com iwinfo scan.'
            : 'Inclui rádios dos seus APs/modems (scrape) e redes vistas por este Mac quando disponível.'
          : undefined);

    const analysis = analyzeWifi({
      currentSsid: local.currentSsid,
      aps: merged,
      ownNetworks,
    });

    return {
      ...local,
      aps: merged,
      channelCollisions: computeChannelCollisions(merged),
      note,
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
