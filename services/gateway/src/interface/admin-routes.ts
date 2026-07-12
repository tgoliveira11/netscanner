import type { FastifyInstance, FastifyReply } from 'fastify';
import { mergeRouterScrapeTargets } from '@netscanner/config';
import {
  CompalMeshRequestSchema,
  CompalRebootRequestSchema,
  CpeAccessOpenRequestSchema,
  type CompalStreamEvent,
} from '@netscanner/contracts';
import {
  buildCompalOpenUiHtml,
  probeCompalAdmin,
  probeOpenWrtWireless,
  rebootCompalTarget,
  resolvePfSenseTelemetry,
  setCompalMeshForTarget,
  type OpenWrtScrapeTarget,
} from '@netscanner/discovery';
import type { Container } from '../container.js';
import { tailAgentLogFile } from '../infrastructure/log-ring-buffer.js';

const VERSION = '0.2.1';

/** Admin diagnostics and runtime configuration (no auth yet — localhost only). */
export async function registerAdminRoutes(app: FastifyInstance, c: Container): Promise<void> {
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
        wanSpeedTestConfigured: Boolean(
          c.config.PFSENSE_URL?.trim() && c.config.PFSENSE_SSH_PASSWORD?.trim(),
        ),
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
    ).filter((t) => t.kind !== 'compal');
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

  /** Compal AP status (mesh toggle, SSIDs) for kind=compal scrape targets. */
  app.get('/api/admin/compal', async () => {
    const targets = await listCompalTargets(c);
    if (!targets.length) return { configured: false, devices: [] };
    const devices = await probeCompalAdmin(targets, c.logger);
    return { configured: true, devices };
  });

  /**
   * Same-network SSO bounce into Compal LuCI (no proxy).
   * Prepares RSA login fields; the browser POSTs to the AP so the session cookie sticks there.
   */
  app.get('/api/admin/compal/open-ui', async (request, reply) => {
    const baseUrl = String((request.query as { baseUrl?: string }).baseUrl ?? '').trim();
    if (!baseUrl) return reply.status(400).send({ error: 'baseUrl required' });
    const target = findCompalTarget(await listCompalTargets(c), baseUrl);
    if (!target) return reply.status(404).send({ error: 'Compal target not found' });
    if (!target.username || !target.password) {
      return reply.status(400).send({ error: 'Compal credentials missing' });
    }
    try {
      const html = await buildCompalOpenUiHtml(target);
      return reply
        .header('Cache-Control', 'no-store')
        .type('text/html; charset=utf-8')
        .send(html);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      c.logger.warn({ url: target.baseUrl, error: msg }, 'Compal open-ui SSO failed');
      const host = (() => {
        try {
          return new URL(target.baseUrl).hostname;
        } catch {
          return target.baseUrl;
        }
      })();
      const direct = target.baseUrl.replace(/\/+$/, '') || target.baseUrl;
      const esc = (s: string) =>
        s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      return reply
        .status(502)
        .header('Cache-Control', 'no-store')
        .type('text/html; charset=utf-8')
        .send(`<!DOCTYPE html><html><body style="font:14px system-ui;background:#0f172a;color:#e2e8f0;padding:2rem">
<p>Could not prepare login for <strong>${esc(host)}</strong>: ${esc(msg)}</p>
<p><a style="color:#7dd3fc" href="${esc(direct)}" target="_blank" rel="noopener">Open ${esc(host)} without SSO</a></p>
</body></html>`);
    }
  });

  /** pfSense dashboard: system, gateways, VPN, egress inference. */
  app.get('/api/admin/pfsense/gateways', async (request) => {
    if (!c.leaseSource) return { configured: false };
    const force = String((request.query as { refresh?: string }).refresh ?? '') === '1';
    let telemetry = resolvePfSenseTelemetry(c.leaseSource);
    // Serve cache when fresh enough; full refresh can hang when pfSense HTTPS is down.
    const ageMs = telemetry?.fetchedAt ? Date.now() - Date.parse(telemetry.fetchedAt) : Number.POSITIVE_INFINITY;
    const stale = !Number.isFinite(ageMs) || ageMs > 45_000;
    const refresh = async () => {
      try {
        await c.leaseSource!.getLeases();
      } catch {
        /* keep last cached snapshot */
      }
    };
    if (force || !telemetry || stale) {
      if (telemetry && !force) {
        // Stale-but-present: never block the UI on pfSense; refresh in background.
        void refresh();
      } else {
        // No cache or explicit refresh: wait briefly, then return whatever we have.
        await Promise.race([refresh(), new Promise<void>((r) => setTimeout(r, 2_500))]);
        telemetry = resolvePfSenseTelemetry(c.leaseSource);
      }
    }
    if (!telemetry) return { configured: false };
    return {
      configured: true,
      fetchedAt: telemetry.fetchedAt,
      version: telemetry.version,
      hostname: telemetry.hostname,
      system: telemetry.system,
      defaultGateway: telemetry.defaultGateway,
      gatewayGroups: telemetry.gatewayGroups,
      gatewayGroupInsights: telemetry.gatewayGroupInsights,
      gateways: telemetry.gateways,
      interfaces: telemetry.interfaces,
      vpnClients: telemetry.vpnClients,
      egress: telemetry.egress,
      stateCount: telemetry.stateCount,
    };
  });

  app.post('/api/admin/compal/mesh', async (request, reply) => {
    const parsed = CompalMeshRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    const target = findCompalTarget(await listCompalTargets(c), parsed.data.baseUrl);
    if (!target) return reply.status(404).send({ error: 'Compal target not found' });
    return streamCompalAction(reply, target.baseUrl, async (emit) => {
      const result = await setCompalMeshForTarget(target, parsed.data.enabled, c.logger, emit);
      return {
        type: 'done' as const,
        ok: true,
        url: target.baseUrl,
        meshEnabled: result.meshEnabled,
        uptimeSec: result.uptimeSec,
        message: parsed.data.enabled ? 'Mesh enabled' : 'Mesh disabled',
      };
    });
  });

  app.post('/api/admin/compal/reboot', async (request, reply) => {
    const parsed = CompalRebootRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    const target = findCompalTarget(await listCompalTargets(c), parsed.data.baseUrl);
    if (!target) return reply.status(404).send({ error: 'Compal target not found' });
    return streamCompalAction(reply, target.baseUrl, async (emit) => {
      const result = await rebootCompalTarget(target, c.logger, emit);
      return {
        type: 'done' as const,
        ok: true,
        url: target.baseUrl,
        uptimeSec: result.uptimeSec,
        message: 'Reboot concluído — AP voltou online',
      };
    });
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

  // --- Generic CPE / modem admin access (reachability broker + reverse proxy) ---
  app.get('/api/admin/cpe', async () => c.cpeAccess.list());

  app.post('/api/admin/cpe/open', async (request, reply) => {
    const parsed = CpeAccessOpenRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ ok: false, error: parsed.error.message });
    }
    const result = await c.cpeAccess.open(parsed.data);
    return reply.status(result.ok ? 200 : 502).send(result);
  });

  app.delete('/api/admin/cpe/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await c.cpeAccess.close(id);
    return reply.status(ok ? 200 : 404).send({ ok });
  });

  app.post('/api/admin/cpe/:id/rearm-login', async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await c.cpeAccess.rearmAutoLogin(id);
    return reply.status(ok ? 200 : 404).send({ ok });
  });

  // Scoped parsers so POST login bodies are not consumed before we pipe to the CPE.
  await app.register(async (scope) => {
    scope.removeAllContentTypeParsers();
    scope.addContentTypeParser('*', (_request, _payload, done) => {
      done(null);
    });

    scope.all('/api/admin/cpe/proxy/:id', async (request, reply) => {
      const { id } = request.params as { id: string };
      reply.hijack();
      await c.cpeAccess.proxyHttp(id, request.raw, reply.raw, '/');
    });

    scope.all('/api/admin/cpe/proxy/:id/*', async (request, reply) => {
      const { id } = request.params as { id: string };
      const wildcard = (request.params as { '*': string })['*'] ?? '';
      const suffix = wildcard ? `/${wildcard}` : '/';
      const q = request.url.includes('?') ? request.url.slice(request.url.indexOf('?')) : '';
      reply.hijack();
      await c.cpeAccess.proxyHttp(id, request.raw, reply.raw, `${suffix}${q}`);
    });
  });
}

async function listCompalTargets(c: Container): Promise<OpenWrtScrapeTarget[]> {
  const creds = await c.repo.listRouterScrapeCredentials(c.activeSite.getActiveSiteId() ?? '00000000-0000-4000-8000-000000000001');
  return mergeRouterScrapeTargets(
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
  )
    .filter((t) => t.kind === 'compal')
    .map((t) => ({
      baseUrl: t.baseUrl,
      kind: 'compal' as const,
      username: t.username,
      password: t.password,
    }));
}

function findCompalTarget(targets: OpenWrtScrapeTarget[], baseUrl: string): OpenWrtScrapeTarget | undefined {
  const norm = baseUrl.replace(/\/+$/, '');
  return targets.find((t) => t.baseUrl.replace(/\/+$/, '') === norm);
}

async function streamCompalAction(
  reply: FastifyReply,
  url: string,
  run: (emit: (step: { level: 'info' | 'warn' | 'success' | 'error'; message: string; at: string }) => void) => Promise<Extract<CompalStreamEvent, { type: 'done' }>>,
): Promise<void> {
  reply.hijack();
  reply.raw.writeHead(200, {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  const write = (event: CompalStreamEvent) => {
    reply.raw.write(`${JSON.stringify(event)}\n`);
  };
  try {
    const done = await run((step) => write({ type: 'step', ...step }));
    write(done);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    write({ type: 'done', ok: false, url, message });
    reply.raw.statusCode = 502;
  } finally {
    reply.raw.end();
  }
}
