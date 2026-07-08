import type { FastifyInstance } from 'fastify';
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  StartScanRequestSchema,
  UpdateDeviceRequestSchema,
  ExportFormat,
  type HealthResponse,
} from '@netscanner/contracts';
import type { Container } from '../container.js';
import { resolvePfSenseTelemetry } from '@netscanner/discovery';
import { RunScanUseCase } from '../application/run-scan.use-case.js';
import { authorizeAgentControl } from './agent-control.js';
import { registerAdminRoutes } from './admin-routes.js';

const VERSION = '0.1.0';

function hostFromUrl(baseUrl: string): string {
  if (!baseUrl) return '';
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return baseUrl.replace(/^https?:\/\//, '').split('/')[0] ?? '';
  }
}

/**
 * REST surface for the dashboard. Controllers stay thin: validate input (zod),
 * delegate to a use case, map the result to a DTO. No business logic here (SRP).
 */
export function registerRoutes(app: FastifyInstance<any, any, any, any>, c: Container): void {
  registerAdminRoutes(app, c);
  app.get('/api/health', async (_request, reply): Promise<HealthResponse> => {
    reply.header('access-control-allow-origin', '*');
    return {
      status: 'ok',
      capabilities: {
        nmap: c.capabilities.nmap,
        elevated: c.capabilities.elevated,
        nmapOffReason: c.capabilities.nmapOffReason,
      },
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
      const telemetry = resolvePfSenseTelemetry(c.leaseSource);
      return {
        configured: true,
        source: c.leaseSource.name,
        count: leases.length,
        leases,
        pfsense: telemetry
          ? {
              version: telemetry.version,
              hostname: telemetry.hostname,
              gateways: telemetry.gateways.length,
              interfaces: telemetry.interfaces.length,
              fetchedAt: telemetry.fetchedAt,
            }
          : null,
      };
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
      dhcpSniffIfaces: c.dhcpSniffIfaces(),
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
    await reply.send({ ok: true, restarting: true });
    setTimeout(() => process.exit(0), 500);
  });

  app.post('/api/scans', async (request, reply) => {
    const parsed = StartScanRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });

    if (c.sessions.activeScan()) {
      return reply.status(409).send({ error: 'A scan is already running.' });
    }

    const scanType = parsed.data.scanType;
    let cidrList: string[] = [];

    if (parsed.data.allCidrs) {
      cidrList = c.listScanCidrs();
      if (!cidrList.length) {
        return reply.status(400).send({ error: 'No configured CIDRs to scan. Set Extra scan CIDRs or connect to a LAN.' });
      }
    } else {
      const cidrRaw = parsed.data.cidr ?? c.detectPrimaryCidr();
      if (!cidrRaw) return reply.status(400).send({ error: 'Could not determine a subnet to scan.' });
      cidrList = [cidrRaw];
    }

    const cidrs = [];
    for (const raw of cidrList) {
      const cidr = RunScanUseCase.parseCidr(raw);
      if (!cidr) return reply.status(400).send({ error: `Invalid CIDR: ${raw}` });
      cidrs.push(cidr);
    }

    const label = cidrs.map((entry) => entry.toString()).join(',');
    const session = c.sessions.create(label, scanType);
    void c.runScan.executeMany(session.id, cidrs, scanType);
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
    const preferredInfrastructureIp =
      hostFromUrl(c.config.PFSENSE_URL ?? '') || c.config.ROUTER_SNMP_HOST || null;
    const devices = await c.listDevices.execute({
      search: q.search,
      deviceType: q.type,
      onlineOnly: q.online === 'true',
      collapseInfrastructureAliases: q.aliases !== 'true',
      preferredInfrastructureIp,
    });
    return { devices, total: devices.length };
  });

  app.get('/api/devices/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const device = await c.getDevice.execute(id);
    if (!device) return reply.status(404).send({ error: 'device not found' });
    return { device };
  });

  app.get('/api/topology', async (request) => {
    const since = (request.query as { since?: string }).since;
    return c.buildTopology.execute(since ? { since } : undefined);
  });

  app.get('/api/relations', async () => {
    let devices = await c.listDevices.execute({ collapseInfrastructureAliases: true });
    if (c.trafficMonitor) {
      devices = devices.map((d) => {
        const live = c.trafficMonitor!.get(d.ip);
        if (!live) return d;
        return { ...d, signals: { ...d.signals, traffic: live } };
      });
    }
    const { buildDeviceRelations } = await import('../application/build-relations.use-case.js');
    const passiveDnsByIp = (ip: string): string[] => {
      const raw = c.passiveStore?.get(ip)?.dnsRecentQueries;
      return Array.isArray(raw) ? raw.map(String) : [];
    };
    return buildDeviceRelations(devices, {
      passiveDnsByIp,
      dnsLog: c.dnsActivityLog.list(),
    });
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
    const preferredInfrastructureIp =
      hostFromUrl(c.config.PFSENSE_URL ?? '') || c.config.ROUTER_SNMP_HOST || null;
    const { body, contentType, filename } = await c.exportDevices.execute(format, {
      preferredInfrastructureIp,
    });
    return reply
      .header('content-type', contentType)
      .header('content-disposition', `attachment; filename="${filename}"`)
      .send(body);
  });
}
