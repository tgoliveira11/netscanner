import type { FastifyInstance } from 'fastify';
import { mergeRouterScrapeTargets } from '@netscanner/config';
import { probeOpenWrtWireless } from '@netscanner/discovery';
import type { Container } from '../container.js';
import { tailAgentLogFile } from '../infrastructure/log-ring-buffer.js';

const VERSION = '0.1.0';

/** Admin diagnostics and runtime configuration (no auth yet — localhost only). */
export function registerAdminRoutes(app: FastifyInstance, c: Container): void {
  app.get('/api/admin/observability', async () => {
    const active = c.sessions.activeScan();
    const latest = c.sessions.latest();
    let deviceCount = 0;
    let persistedDhcp = 0;
    let persistedPassive = 0;
    try {
      deviceCount = (await c.listDevices.execute({})).length;
      persistedDhcp = (await c.dhcpStore?.loadAll())?.length ?? 0;
      persistedPassive = (await c.passiveStore?.list())?.length ?? 0;
    } catch {
      /* ignore */
    }

    return {
      version: VERSION,
      uptimeSec: Math.floor(process.uptime()),
      pid: process.pid,
      nodeVersion: process.version,
      cwd: process.cwd(),
      configPath: c.runtimeSettings.configPath,
      capabilities: c.capabilities,
      background: {
        enrichIntervalMs: c.config.BACKGROUND_ENRICH_INTERVAL_MS,
        scanIntervalMs: c.config.BACKGROUND_SCAN_INTERVAL_MS,
        scanEnabled: c.config.BACKGROUND_SCAN_ENABLED,
        passiveListeners: c.config.PASSIVE_LISTENERS_ENABLED,
        lldpPassive: c.config.LLDP_PASSIVE_ENABLED,
        snmpEnabled: c.config.SNMP_ENABLED,
        dhcpSniffer: Boolean(c.dhcpSource),
        dhcpListening: c.dhcpSource?.isListening() ?? false,
        dhcpMode: c.dhcpSource?.mode?.() ?? null,
        dhcpSniffIfaces: c.dhcpSniffIfaces(),
        dhcpInMemory: c.dhcpSource?.size() ?? 0,
        dhcpPersisted: persistedDhcp,
        passiveSignals: persistedPassive,
        activeScan: active ? { id: active.id, status: active.status, cidr: active.cidr } : null,
      },
      inventory: { deviceCount },
      scans: { latest: latest ?? null, active: active ?? null },
      interfaces: c.listInterfaces(),
      primaryCidr: c.detectPrimaryCidr(),
      dhcpFingerprints: c.dhcpSource?.list().slice(-20) ?? [],
      passiveSample: (await c.passiveStore?.list())?.slice(-15) ?? [],
      router: c.leaseSource
        ? { configured: true, source: c.leaseSource.name }
        : { configured: false },
    };
  });

  app.get('/api/admin/logs', async (request) => {
    const q = request.query as { tail?: string; source?: string };
    const tail = Math.min(500, Math.max(10, Number(q.tail) || 200));
    const mem = c.logBuffer.tail(tail);
    const file = tailAgentLogFile(c.agentLogPath, tail);
    return {
      memory: mem,
      file: file.map((line) => ({ at: null, levelLabel: 'file', msg: line, raw: { line } })),
    };
  });

  app.get('/api/admin/config', async () => ({
    schema: c.runtimeSettings.getSchema(),
    values: c.runtimeSettings.getConfig(),
    configPath: c.runtimeSettings.configPath,
  }));

  /** OpenWrt LuCI wireless/SSID probe for all configured ROUTER_SCRAPE targets. */
  app.get('/api/admin/wireless', async () => {
    const creds = await c.repo.listRouterScrapeCredentials();
    const targets = mergeRouterScrapeTargets(
      c.config,
      creds.map((row) => ({
        ip: row.ip,
        deviceType: row.deviceType,
        brand: row.brand,
        routerScrapeUser: row.routerScrapeUser,
        routerScrapePassword: row.routerScrapePassword,
      })),
    );
    if (!targets.length) {
      return { configured: false, routers: [] };
    }
    const routers = await probeOpenWrtWireless(
      targets.map((t) => ({
        baseUrl: t.baseUrl,
        kind: t.kind,
        username: t.username,
        password: t.password,
      })),
      c.logger,
    );
    return {
      configured: true,
      count: routers.length,
      transmitting: routers.filter((r) => r.ok && r.ssids.some((s) => s.up && s.ssid)).length,
      routers,
    };
  });

  app.patch('/api/admin/config', async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    try {
      const result = await c.runtimeSettings.applyPatch(body);
      c.logger.info({ applied: result.applied, restartRequired: result.restartRequired }, 'admin config updated');
      return {
        ok: true,
        values: c.runtimeSettings.getConfig(),
        restartRequired: result.restartRequired,
        applied: result.applied,
      };
    } catch (error) {
      return reply.status(400).send({
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  /** Same as POST /api/agent/restart but without Bearer token (admin UI is localhost-only). */
  app.post('/api/admin/restart', async (_request, reply) => {
    c.logger.info('agent restart requested via admin');
    await reply.send({ ok: true, restarting: true });
    setTimeout(() => process.exit(0), 500);
  });
}
