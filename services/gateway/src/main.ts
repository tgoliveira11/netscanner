import { buildContainer } from './container.js';
import { buildServer } from './server.js';

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
