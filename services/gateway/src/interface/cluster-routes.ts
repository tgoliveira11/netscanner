import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.js';

/** Cluster status, peers, and worker task result ingestion. */
export function registerClusterRoutes(app: FastifyInstance, c: Container): void {
  app.get('/api/cluster/status', async () => c.cluster.status());

  app.get('/api/cluster/peers', async () => ({
    peers: c.cluster.status().peers,
    selfId: c.agentIdentity.id,
  }));

  app.post('/api/cluster/tasks/result', async (request, reply) => {
    const token = c.config.AGENT_CONTROL_TOKEN?.trim();
    if (token) {
      const auth = request.headers.authorization ?? '';
      if (auth !== `Bearer ${token}`) {
        return reply.code(401).send({ error: 'unauthorized' });
      }
    }
    if (!c.cluster.isInventoryLeader()) {
      return reply.code(409).send({ error: 'not inventory leader — forward to leader' });
    }
    const body = request.body as { taskId?: string; type?: string; payload?: unknown };
    c.logger.info({ taskId: body.taskId, type: body.type }, 'cluster task result received');
    c.cloudSync.enqueue({
      siteId: 'default',
      type: 'audit',
      payload: { kind: 'task-result', taskId: body.taskId, type: body.type, payload: body.payload },
    });
    return { ok: true };
  });
}
