import type { FastifyInstance } from 'fastify';
import {
  ConfirmSiteRequestSchema,
  LockSiteRequestSchema,
  UpdateSiteRequestSchema,
} from '@netscanner/contracts';
import type { Container } from '../container.js';

/** Network site management — multi-location inventory isolation. */
export function registerSiteRoutes(app: FastifyInstance, c: Container): void {
  app.get('/api/sites', async () => ({
    sites: await c.activeSite.listSites(),
  }));

  app.get('/api/sites/active', async () => c.activeSite.state());

  app.post('/api/sites/refresh', async () => {
    await c.activeSite.refresh();
    return c.activeSite.state();
  });

  app.post('/api/sites/confirm', async (request, reply) => {
    const parsed = ConfirmSiteRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    const site = await c.activeSite.confirmSite(parsed.data.siteId);
    if (!site) return reply.status(404).send({ error: 'site not found' });
    return c.activeSite.state();
  });

  app.post('/api/sites/lock', async (request, reply) => {
    const parsed = LockSiteRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    await c.activeSite.lockSite(parsed.data.siteId);
    return c.activeSite.state();
  });

  app.patch('/api/sites/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = UpdateSiteRequestSchema.safeParse(request.body ?? {});
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
    const site = await c.activeSite.updateSite(id, parsed.data);
    if (!site) return reply.status(404).send({ error: 'site not found' });
    return { site };
  });

  app.delete('/api/sites/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const ok = await c.activeSite.deleteSite(id);
      if (!ok) return reply.status(404).send({ error: 'site not found' });
      return { ok: true };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(400).send({ error: message });
    }
  });
}
