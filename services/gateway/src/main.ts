import { createServer, type Server as HttpServer } from 'node:http';
import { buildContainer } from './container.js';
import { buildServer } from './server.js';

/**
 * Fastify only allows one listen() per instance. Share the same request/upgrade
 * handlers on an extra HTTP server (e.g. :80 for http://netscanner.local/).
 */
function listenSharedPort(
  primary: HttpServer,
  port: number,
  host: string,
): Promise<HttpServer> {
  const extra = createServer((req, res) => {
    primary.emit('request', req, res);
  });
  extra.on('upgrade', (req, socket, head) => {
    primary.emit('upgrade', req, socket, head);
  });
  return new Promise((resolve, reject) => {
    extra.once('error', reject);
    extra.listen(port, host, () => resolve(extra));
  });
}

/** Process entry point: assemble the graph, start HTTP + WebSocket. */
async function main(): Promise<void> {
  const container = await buildContainer();
  await container.dhcpSource?.start();
  container.passiveListeners?.start();
  container.backgroundWorker.start();
  container.presenceMonitor.start();
  container.speedTestWorker.start();
  const app = await buildServer(container);

  const { GATEWAY_PORT, GATEWAY_HOST } = container.config;
  await app.listen({ port: GATEWAY_PORT, host: GATEWAY_HOST });

  // Convenience for http://netscanner.local/ (no :4000). Any MDNS-enabled agent
  // may bind :80 so helpers can answer on their VLAN and redirect to the leader.
  if (container.config.MDNS_ENABLED) {
    try {
      await listenSharedPort(app.server, 80, GATEWAY_HOST);
      container.logger.info({ host: GATEWAY_HOST, port: 80 }, 'also listening on :80 for mDNS URL');
    } catch (error) {
      container.logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'could not bind :80 — use http://netscanner.local:4000 or grant privilege',
      );
    }
  }
  if (!container.capabilities.nmap) {
    const reason =
      container.capabilities.nmapOffReason === 'disabled-by-config'
        ? 'DISABLE_NMAP=true in config — set to false in /admin or config.env'
        : container.capabilities.nmapOffReason === 'not-in-path'
          ? 'nmap binary not found in PATH — install nmap (e.g. brew install nmap)'
          : 'nmap unavailable';
    container.logger.warn({ reason, nmapOffReason: container.capabilities.nmapOffReason }, reason);
  }
  if (!container.capabilities.elevated) {
    container.logger.warn('not elevated — OS detection (nmap -O) unavailable. Run with sudo for it.');
  }
}

main().catch((error) => {
  console.error('fatal: failed to start gateway', error);
  process.exit(1);
});
