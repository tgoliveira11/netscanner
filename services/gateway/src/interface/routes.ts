import type { FastifyInstance } from 'fastify';
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  StartScanRequestSchema,
  UpdateDeviceRequestSchema,
  ExportFormat,
  type HealthResponse,
} from '@netscanner/contracts';
import type { Container } from '../container.js';
import { RunScanUseCase } from '../application/run-scan.use-case.js';
import { authorizeAgentControl } from './agent-control.js';
import { registerAdminRoutes } from './admin-routes.js';

const VERSION = '0.1.0';

/**
 * REST surface for the dashboard. Controllers stay thin: validate input (zod),
 * delegate to a use case, map the result to a DTO. No business logic here (SRP).
 */
export function registerRoutes(app: FastifyInstance<any, any, any, any>, c: Container): void {
  registerAdminRoutes(app, c);
  app.get('/api/health', async (_request, reply): Promise<HealthResponse> => {
    // Health is non-sensitive and is polled cross-origin by the onboarding site
    // (hosted anywhere) to detect the agent, so it is intentionally CORS-open.
    // All other endpoints remain restricted to the allow-listed origins.
    reply.header('access-control-allow-origin', '*');
    return {
      status: 'ok',
      capabilities: { nmap: c.capabilities.nmap, elevated: c.capabilities.elevated },
      version: VERSION,
    };
  });

  app.get('/api/network/interfaces', async () => {
    return {
      interfaces: c.listInterfaces(),
      primaryCidr: c.detectPrimaryCidr(),
      scanCidrs: c.listScanCidrs(),
    };
  });

  // Diagnostic endpoint: verify the pfSense integration and preview its leases.
  app.get('/api/router/leases', async (_request, reply) => {
    if (!c.leaseSource) return { configured: false, leases: [] };
    try {
      const leases = await c.leaseSource.getLeases();
      return { configured: true, source: c.leaseSource.name, count: leases.length, leases };
    } catch (error) {
      return reply
        .status(502)
        .send({ configured: true, error: error instanceof Error ? error.message : String(error) });
    }
  });

  // Diagnostic endpoint: passive DHCP fingerprints captured by the root sniffer (:67).
  app.get('/api/dhcp/fingerprints', async (request) => {
    const q = request.query as { mac?: string };
    if (!c.dhcpSource) {
      return { configured: false, listening: false, count: 0, fingerprints: [] };
    }
    const all = c.dhcpSource.list();
    const mac = q.mac?.trim().toLowerCase();
    const fingerprints = mac ? all.filter((fp) => fp.mac === mac) : all;
    return {
      configured: true,
      listening: c.dhcpSource.isListening(),
      count: fingerprints.length,
      fingerprints,
    };
  });

  app.get('/api/background/status', async () => {
    const active = c.sessions.activeScan();
    let persistedDhcp = 0;
    let persistedPassive = 0;
    try {
      persistedDhcp = (await c.dhcpStore?.loadAll())?.length ?? 0;
      persistedPassive = (await c.passiveStore?.list())?.length ?? 0;
    } catch {
      /* ignore */
    }
    return {
      enrichIntervalMs: c.config.BACKGROUND_ENRICH_INTERVAL_MS,
      scanIntervalMs: c.config.BACKGROUND_SCAN_INTERVAL_MS,
      scanEnabled: c.config.BACKGROUND_SCAN_ENABLED,
      passiveListeners: c.config.PASSIVE_LISTENERS_ENABLED,
      lldpPassive: c.config.LLDP_PASSIVE_ENABLED,
      lldpStream: c.config.LLDP_STREAM_ENABLED,
      dnsPassive: c.config.PASSIVE_DNS_ENABLED,
      igmpPassive: c.config.PASSIVE_IGMP_ENABLED,
      dhcpv6Passive: c.config.PASSIVE_DHCPV6_ENABLED,
      snmpEnabled: c.config.SNMP_ENABLED,
      snmpSwitch: c.config.SNMP_SWITCH_HOST ?? null,
      scanCidrs: c.listScanCidrs(),
      adaptiveScan: c.config.ADAPTIVE_SCAN_ENABLED,
      masscan: c.config.MASSCAN_ENABLED,
      dhcpSniffer: Boolean(c.dhcpSource),
      dhcpListening: c.dhcpSource?.isListening() ?? false,
      dhcpMode: c.dhcpSource?.mode() ?? null,
      dhcpInMemory: c.dhcpSource?.size() ?? 0,
      dhcpPersisted: persistedDhcp,
      passiveSignals: persistedPassive,
      activeScan: active ? { id: active.id, status: active.status, cidr: active.cidr } : null,
    };
  });

  /** Graceful exit; LaunchDaemon KeepAlive restarts the process (no sudo). */
  app.post('/api/agent/restart', async (request, reply) => {
    if (!authorizeAgentControl(request, c.config)) {
      return reply.status(401).send({ error: 'unauthorized' });
    }
    c.logger.info('agent restart requested via API');
    void reply.send({ ok: true, restarting: true });
    setImmediate(() => process.exit(0));
  });

  app.post('/api/scans', async (request, reply) => {
    const parsed = StartScanRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });

    const cidrRaw = parsed.data.cidr ?? c.detectPrimaryCidr();
    if (!cidrRaw) return reply.status(400).send({ error: 'Could not determine a subnet to scan.' });

    const cidr = RunScanUseCase.parseCidr(cidrRaw);
    if (!cidr) return reply.status(400).send({ error: `Invalid CIDR: ${cidrRaw}` });

    const session = c.sessions.create(cidr.toString(), parsed.data.scanType);
    // Fire-and-forget: progress is streamed over WebSocket.
    void c.runScan.execute(session.id, cidr, parsed.data.scanType);
    return reply.status(202).send({ scan: session });
  });

  app.get('/api/scans/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const session = c.sessions.get(id);
    if (!session) return reply.status(404).send({ error: 'scan not found' });
    return { scan: session };
  });

  app.get('/api/scans', async () => ({ scan: c.sessions.latest() ?? null }));

  app.get('/api/devices', async (request) => {
    const q = request.query as Record<string, string | undefined>;
    const devices = await c.listDevices.execute({
      search: q.search,
      deviceType: q.type,
      onlineOnly: q.online === 'true',
    });
    return { devices, total: devices.length };
  });

  app.get('/api/devices/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const device = await c.getDevice.execute(id);
    if (!device) return reply.status(404).send({ error: 'device not found' });
    return { device };
  });

  app.patch('/api/devices/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = UpdateDeviceRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    const device = await c.updateMeta.execute({ id, ...parsed.data });
    if (!device) return reply.status(404).send({ error: 'device not found' });
    return { device };
  });

  app.get('/api/export', async (request, reply) => {
    const format = ExportFormat.catch('json').parse((request.query as { format?: string }).format);
    const { body, contentType, filename } = await c.exportDevices.execute(format);
    return reply
      .header('content-type', contentType)
      .header('content-disposition', `attachment; filename="${filename}"`)
      .send(body);
  });
}
