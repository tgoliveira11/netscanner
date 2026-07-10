import type { AppConfig } from '@netscanner/config';
import type { SpeedTestTrigger } from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import type { ISpeedTester } from '@netscanner/scanner';
import type { RecordSpeedTestUseCase } from '@netscanner/inventory';
import type { IRouterLeaseSource } from '@netscanner/discovery';
import { resolvePfSenseTelemetry } from '@netscanner/discovery';
import type { ScanSessionStore } from './scan-session.js';
import { resolveAgentEgress } from './resolve-agent-egress.js';

export interface RunSpeedTestDeps {
  config: AppConfig;
  logger: Logger;
  tester: ISpeedTester;
  record: RecordSpeedTestUseCase;
  sessions: ScanSessionStore;
  leaseSource?: IRouterLeaseSource;
}

export class RunSpeedTestUseCase {
  private running = false;

  constructor(private readonly deps: RunSpeedTestDeps) {}

  isRunning(): boolean {
    return this.running;
  }

  async execute(trigger: SpeedTestTrigger = 'manual'): Promise<import('@netscanner/contracts').SpeedTestResult> {
    if (this.running) throw new Error('speed test already running');
    if (this.deps.sessions.activeScan()) throw new Error('scan in progress — try again later');

    this.running = true;
    const { config, logger, tester, record, leaseSource } = this.deps;
    try {
      const telemetry = leaseSource ? resolvePfSenseTelemetry(leaseSource) : null;
      const egress = resolveAgentEgress(telemetry);
      logger.info({ trigger, egress }, 'speed test starting');
      const measurement = await tester.run({
        baseUrl: config.SPEED_TEST_URL,
        downloadBytes: config.SPEED_TEST_DOWNLOAD_BYTES,
        uploadBytes: config.SPEED_TEST_UPLOAD_BYTES,
      });
      return await record.execute({
        ...measurement,
        trigger,
        testKind: 'agent',
        egressGateway: egress.egressGateway,
        egressRoute: egress.egressRoute,
      });
    } finally {
      this.running = false;
    }
  }
}
