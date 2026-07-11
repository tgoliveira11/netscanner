import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import type { Container } from './container.js';
import { registerRoutes } from './interface/routes.js';
import { attachSocket } from './interface/socket.js';
import { maybeRedirectToLeader, registerLeaderProxy, wrapUpgradeForLeaderProxy } from './infrastructure/leader-proxy.js';

/** Map a browser path to an exported HTML file (Next static export uses flat `admin.html`). */
function resolveStaticHtml(webOut: string, url: string): string {
  const pathname = url.split('?')[0]?.split('#')[0] ?? '/';
  const normalized = pathname.endsWith('/') && pathname.length > 1 ? pathname.slice(0, -1) : pathname;
  if (normalized === '/' || normalized === '') return 'index.html';

  const segment = normalized.slice(1).replace(/\//g, path.sep);
  const flatHtml = path.join(webOut, `${segment}.html`);
  if (existsSync(flatHtml)) return `${segment}.html`;

  const indexHtml = path.join(webOut, segment, 'index.html');
  if (existsSync(indexHtml)) return path.join(segment, 'index.html').replace(/\\/g, '/');

  return 'index.html';
}

/** Locate the exported dashboard (apps/web/out) built with BUILD_STATIC=1. */
function findWebOut(): string | null {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  while (dir !== path.dirname(dir) && !existsSync(path.join(dir, 'pnpm-workspace.yaml'))) {
    dir = path.dirname(dir);
  }
  const out = path.join(dir, 'apps/web/out');
  return existsSync(path.join(out, 'index.html')) ? out : null;
}

/** Origins permitted to make browser requests to the agent. */
function allowedOrigins(c: Container): string[] {
  const port = c.config.GATEWAY_PORT;
  const base = [
    c.config.WEB_ORIGIN,
    c.config.ONBOARDING_ORIGIN,
    `http://localhost:${port}`,
    `http://127.0.0.1:${port}`,
    `http://netscanner.local:${port}`,
    `http://netscanner.local`,
  ].filter((o): o is string => Boolean(o));
  // LAN-wide UI: reflect any private-network Origin (trust model documented in multi-agent.md).
  return base;
}

function isPrivateLanOrigin(origin: string): boolean {
  try {
    const u = new URL(origin);
    const h = u.hostname;
    if (h === 'localhost' || h === 'netscanner.local' || h.endsWith('.local')) return true;
    if (/^127\./.test(h)) return true;
    if (/^10\./.test(h)) return true;
    if (/^192\.168\./.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) return true;
    return false;
  } catch {
    return false;
  }
}

/** Builds the Fastify app + Socket.IO hub from an assembled container. */
export async function buildServer(c: Container) {
  const app = Fastify({ loggerInstance: c.logger });
  const origins = new Set(allowedOrigins(c));

  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (origins.has(origin) || isPrivateLanOrigin(origin)) return cb(null, true);
      return cb(null, false);
    },
  });

  // CSRF-style guard: a malicious page can still *send* a cross-origin POST even
  // though CORS hides the response. Reject state-changing requests whose Origin
  // is present and not allow-listed, so no third-party site can trigger scans.
  app.addHook('onRequest', (request, reply, done) => {
    const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(request.method);
    const origin = request.headers.origin;
    if (mutating && origin && !origins.has(origin) && !isPrivateLanOrigin(origin)) {
      reply.code(403).send({ error: 'origin not allowed' });
      return;
    }
    done();
  });

  // Non-leaders: keep http://netscanner.local/ via reverse-proxy (MDNS), or redirect (no MDNS).
  registerLeaderProxy(app as never, c.cluster, c.config);
  app.addHook('onRequest', async (request, reply) => {
    await maybeRedirectToLeader(request, reply, c.cluster, c.config);
  });

  await registerRoutes(app, c);

  // Serve the exported dashboard so the agent is a single localhost app.
  const webOut = findWebOut();
  if (webOut) {
    await app.register(fastifyStatic, { root: webOut, prefix: '/' });
    app.setNotFoundHandler((request, reply) => {
      if (request.url.startsWith('/api') || request.url.startsWith('/socket.io')) {
        return reply.code(404).send({ error: 'not found' });
      }
      const file = resolveStaticHtml(webOut, request.url);
      return reply.sendFile(file);
    });
    c.logger.info({ webOut }, 'serving bundled dashboard');
  } else {
    c.logger.info('no bundled dashboard found (dev mode: run the web app on :3000)');
  }

  app.addHook('onReady', async () => {
    attachSocket(app.server, c);
    wrapUpgradeForLeaderProxy(app as never, c.cluster, c.config);
  });

  return app;
}
