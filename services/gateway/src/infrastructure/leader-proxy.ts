import http from 'node:http';
import type { Socket } from 'node:net';
import type { FastifyRequest, FastifyReply } from 'fastify';
import type { AppConfig } from '@netscanner/config';
import type { ClusterService } from '../application/cluster-service.js';

type AppLike = {
  addHook: (name: string, handler: (...args: never[]) => unknown) => unknown;
  server: http.Server;
};

/**
 * Reverse-proxy helper traffic to the inventory leader so http://netscanner.local/
 * stays in the address bar (macOS ignores mDNS A records that point at another host).
 */
export function registerLeaderProxy(
  app: AppLike,
  cluster: ClusterService,
  config: AppConfig,
): void {
  app.addHook('onRequest', (async (request: FastifyRequest, reply: FastifyReply) => {
    if (cluster.isInventoryLeader()) return;
    if (!config.MDNS_ENABLED) return;
    const targetBase = cluster.inventoryLeaderProxyUrl();
    if (!targetBase) return;
    await proxyHttp(request, reply, targetBase);
  }) as (...args: never[]) => unknown);
}

/** Call after Socket.IO is attached so we can wrap its upgrade listener. */
export function wrapUpgradeForLeaderProxy(
  app: AppLike,
  cluster: ClusterService,
  config: AppConfig,
): void {
  const server = app.server;
  const priorListeners = server.listeners('upgrade').slice();
  server.removeAllListeners('upgrade');
  server.on('upgrade', (req, socket, head) => {
    if (cluster.isInventoryLeader() || !config.MDNS_ENABLED) {
      for (const listener of priorListeners) {
        (listener as (req: http.IncomingMessage, socket: Socket, head: Buffer) => void)(
          req,
          socket as Socket,
          head,
        );
      }
      return;
    }
    const targetBase = cluster.inventoryLeaderProxyUrl();
    if (!targetBase) {
      socket.destroy();
      return;
    }
    proxyUpgrade(req, socket as Socket, head, targetBase);
  });
}

/** Non-MDNS fallback: redirect HTML to the leader (URL becomes the leader IP). */
export async function maybeRedirectToLeader(
  request: FastifyRequest,
  reply: FastifyReply,
  cluster: ClusterService,
  config: AppConfig,
): Promise<boolean> {
  if (!config.CLUSTER_UI_REDIRECT) return false;
  if (config.MDNS_ENABLED) return false; // proxied instead
  if (request.url.startsWith('/api') || request.url.startsWith('/socket.io')) return false;
  if (cluster.isInventoryLeader()) return false;
  const accept = String(request.headers.accept ?? '');
  if (request.method !== 'GET') return false;
  if (accept && !accept.includes('text/html') && accept !== '*/*') return false;
  const leader = cluster.inventoryLeaderBaseUrl();
  if (!leader) return false;
  await reply.redirect(`${leader}${request.url}`);
  return true;
}

async function proxyHttp(
  request: FastifyRequest,
  reply: FastifyReply,
  targetBase: string,
): Promise<void> {
  const target = new URL(request.url, targetBase);
  reply.hijack();
  const headers: http.OutgoingHttpHeaders = { ...request.headers };
  headers.host = target.host;
  delete headers['accept-encoding'];

  await new Promise<void>((resolve) => {
    const proxyReq = http.request(
      target,
      { method: request.method, headers },
      (proxyRes) => {
        reply.raw.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(reply.raw);
        proxyRes.on('end', resolve);
        proxyRes.on('error', resolve);
      },
    );
    proxyReq.on('error', (error) => {
      if (!reply.raw.headersSent) {
        reply.raw.writeHead(502, { 'content-type': 'text/plain' });
        reply.raw.end(`leader proxy error: ${error.message}`);
      }
      resolve();
    });
    request.raw.pipe(proxyReq);
  });
}

function proxyUpgrade(
  req: http.IncomingMessage,
  socket: Socket,
  head: Buffer,
  targetBase: string,
): void {
  const target = new URL(req.url ?? '/', targetBase);
  const headers: http.OutgoingHttpHeaders = { ...req.headers, host: target.host };
  const proxyReq = http.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || 80,
    path: target.pathname + target.search,
    method: 'GET',
    headers,
  });
  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\n` +
        Object.entries(proxyRes.headers)
          .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
          .join('\r\n') +
        '\r\n\r\n',
    );
    if (proxyHead.length) socket.write(proxyHead);
    if (head.length) proxySocket.write(head);
    proxySocket.pipe(socket);
    socket.pipe(proxySocket);
  });
  proxyReq.on('error', () => socket.destroy());
  proxyReq.end();
}
