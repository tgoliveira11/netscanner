import { buildContainer } from './container.js';
import { buildServer } from './server.js';

/** Process entry point: assemble the graph, start HTTP + WebSocket. */
async function main(): Promise<void> {
  const container = await buildContainer();
  await container.dhcpSource?.start();
  container.passiveListeners?.start();
  container.backgroundWorker.start();
  const app = await buildServer(container);

  const { GATEWAY_PORT, GATEWAY_HOST } = container.config;
  await app.listen({ port: GATEWAY_PORT, host: GATEWAY_HOST });

  if (!container.capabilities.nmap) {
    container.logger.warn(
      'nmap not found — deep OS/service fingerprinting disabled. Install nmap for full detail.',
    );
  }
  if (!container.capabilities.elevated) {
    container.logger.warn('not elevated — OS detection (nmap -O) unavailable. Run with sudo for it.');
  }
}

main().catch((error) => {
  console.error('fatal: failed to start gateway', error);
  process.exit(1);
});
