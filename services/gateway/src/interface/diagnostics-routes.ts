import type { FastifyInstance } from 'fastify';
import {
  CameraScanRequestSchema,
  DnsLookupRequestSchema,
  PingRequestSchema,
  PortScanRequestSchema,
  TracerouteRequestSchema,
} from '@netscanner/contracts';
import type { Container } from '../container.js';

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

  app.get('/api/diagnostics/wifi', async () => c.diagnostics.wifiScan());

  app.post('/api/diagnostics/camera-scan', async (request) => {
    const parsed = CameraScanRequestSchema.safeParse(request.body ?? {});
    const cidr = parsed.success ? parsed.data.cidr : undefined;
    return c.diagnostics.cameraScan(cidr);
  });
}
