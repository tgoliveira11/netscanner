import type { AppConfig } from '@netscanner/config';
import type { SpeedTestResult, SpeedTestTrigger } from '@netscanner/contracts';
import type { IRouterLeaseSource } from '@netscanner/discovery';
import { resolvePfSenseTelemetry } from '@netscanner/discovery';
import type { Logger } from '@netscanner/logger';
import type { RecordSpeedTestUseCase } from '@netscanner/inventory';
import { PfSshWanSpeedTester, resolvePfSenseSshHost } from '@netscanner/scanner';
import type { ScanSessionStore } from './scan-session.js';
import { listPhysicalWanTargets } from './wan-gateway-list.js';

export interface RunWanSpeedTestsDeps {
  config: AppConfig;
  logger: Logger;
  record: RecordSpeedTestUseCase;
  sessions: ScanSessionStore;
  leaseSource?: IRouterLeaseSource;
}

export class RunWanSpeedTestsUseCase {
  private running = false;
  private readonly wanTester: PfSshWanSpeedTester;

  constructor(private readonly deps: RunWanSpeedTestsDeps) {
    this.wanTester = new PfSshWanSpeedTester(deps.logger);
  }

  isRunning(): boolean {
    return this.running;
  }

  async execute(trigger: SpeedTestTrigger = 'manual'): Promise<SpeedTestResult[]> {
    if (this.running) throw new Error('speed test already running');
    if (this.deps.sessions.activeScan()) throw new Error('scan in progress — try again later');

    const { config, logger, record, leaseSource } = this.deps;
    const host = resolvePfSenseSshHost(config.PFSENSE_URL);
    const password = config.PFSENSE_SSH_PASSWORD?.trim();
    if (!host || !password) {
      throw new Error('Configure PFSENSE_URL + PFSENSE_SSH_PASSWORD for per-WAN tests');
    }

    // Prefer cached telemetry — a full pfSense refresh can take 30s+ and made WAN tests look broken.
    let telemetry = resolvePfSenseTelemetry(leaseSource);
    let targets = telemetry
      ? listPhysicalWanTargets(telemetry.gateways, telemetry.interfaces)
      : [];
    if (!targets.length && leaseSource) {
      try {
        await leaseSource.getLeases();
      } catch {
        /* use whatever cache we have */
      }
      telemetry = resolvePfSenseTelemetry(leaseSource);
      targets = telemetry
        ? listPhysicalWanTargets(telemetry.gateways, telemetry.interfaces)
        : [];
    }
    if (!telemetry) throw new Error('pfSense telemetry unavailable — check PFSENSE_URL/API key');
    if (!targets.length) throw new Error('No physical WAN gateways found in pfSense telemetry');

    this.running = true;
    const results: SpeedTestResult[] = [];
    try {
      for (const wan of targets) {
        logger.info({ gateway: wan.name, hwif: wan.hwif }, 'wan speed test starting');
        const measurement = await this.wanTester.run({
          host,
          port: config.PFSENSE_SSH_PORT,
          username: config.PFSENSE_SSH_USER,
          password,
          hwif: wan.hwif,
          baseUrl: config.SPEED_TEST_URL,
          downloadBytes: config.SPEED_TEST_DOWNLOAD_BYTES,
          uploadBytes: config.SPEED_TEST_UPLOAD_BYTES,
        });
        const row = await record.execute({
          ...measurement,
          trigger,
          testKind: 'wan',
          wanGateway: wan.name,
          wanInterface: wan.hwif,
        });
        results.push(row);
      }
      return results;
    } finally {
      this.running = false;
    }
  }
}
