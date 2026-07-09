import type { FastifyInstance, FastifyReply } from 'fastify';
import {
  BandwidthLimitRequestSchema,
  BlockRequestSchema,
  DhcpReservationRequestSchema,
  ParentalScheduleRequestSchema,
  PauseRequestSchema,
} from '@netscanner/contracts';
import type { Container } from '../container.js';
import { authorizeControl } from './control-auth.js';

function controlError(reply: FastifyReply, error: unknown) {
  const msg = error instanceof Error ? error.message : String(error);
  if (/not found/i.test(msg)) return reply.status(404).send({ error: msg });
  if (/not configured|control disabled/i.test(msg)) return reply.status(503).send({ error: msg });
  return reply.status(502).send({ error: msg });
}

export function registerControlRoutes(app: FastifyInstance, c: Container): void {
  app.get('/api/control/bootstrap', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    return c.networkControl.checkBootstrap();
  });

  app.get('/api/control/verify', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    return c.networkControl.verify();
  });

  app.post('/api/control/bootstrap', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    if (!c.networkControl.enabled()) return reply.status(503).send({ error: 'control disabled' });
    return c.networkControl.bootstrap();
  });

  app.get('/api/control/audit', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    const limit = Number((request.query as { limit?: string }).limit ?? 100);
    return { entries: await c.networkControl.listAudit(limit) };
  });

  app.get('/api/control/status/:deviceId', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    const { deviceId } = request.params as { deviceId: string };
    try {
      return await c.networkControl.status(deviceId);
    } catch (error) {
      return reply.status(404).send({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post('/api/control/block', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    if (!c.networkControl.enabled()) return reply.status(503).send({ error: 'control disabled' });
    const parsed = BlockRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    try {
      return { entry: await c.networkControl.block(parsed.data.deviceId, parsed.data.ip, parsed.data.mac, parsed.data.reason) };
    } catch (error) {
      return controlError(reply, error);
    }
  });

  app.post('/api/control/unblock', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    if (!c.networkControl.enabled()) return reply.status(503).send({ error: 'control disabled' });
    const parsed = BlockRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    try {
      return { entry: await c.networkControl.unblock(parsed.data.deviceId, parsed.data.ip, parsed.data.mac) };
    } catch (error) {
      return controlError(reply, error);
    }
  });

  app.post('/api/control/pause', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    if (!c.networkControl.enabled()) return reply.status(503).send({ error: 'control disabled' });
    const parsed = PauseRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    try {
      return {
        entry: await c.networkControl.pause(
          parsed.data.deviceId,
          parsed.data.ip,
          parsed.data.mac,
          parsed.data.durationMs,
        ),
      };
    } catch (error) {
      return controlError(reply, error);
    }
  });

  app.post('/api/control/dhcp/reserve', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    const parsed = DhcpReservationRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    return { entry: await c.networkControl.createDhcpReservation(parsed.data) };
  });

  app.post('/api/control/bandwidth', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    const parsed = BandwidthLimitRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    return { entry: await c.networkControl.setBandwidth(parsed.data) };
  });

  app.get('/api/control/parental', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    return { schedules: c.networkControl.listParentalSchedules() };
  });

  app.post('/api/control/parental', async (request, reply) => {
    if (!authorizeControl(request, c.config)) return reply.status(401).send({ error: 'unauthorized' });
    const parsed = ParentalScheduleRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    return { schedule: await c.networkControl.createParentalSchedule(parsed.data) };
  });
}
