import type { Server as HttpServer } from 'node:http';
import { Server as IoServer } from 'socket.io';
import type { Container } from '../container.js';

/**
 * WebSocket hub: bridges the in-process event bus to connected dashboards.
 * Every DomainEvent is forwarded verbatim, so the UI is a pure projection of the
 * backend's event stream (no polling).
 */
export function attachSocket(httpServer: HttpServer, c: Container): IoServer {
  const io = new IoServer(httpServer, {
    cors: { origin: c.config.WEB_ORIGIN, methods: ['GET', 'POST'] },
    path: '/socket.io',
  });

  c.events.on((event) => {
    io.emit('domain-event', event);
  });

  io.on('connection', (socket) => {
    c.logger.debug({ id: socket.id }, 'dashboard connected');
    const latest = c.sessions.latest();
    if (latest) socket.emit('domain-event', { type: 'scan.progress', payload: latest });
  });

  return io;
}
