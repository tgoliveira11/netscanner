import type { AppConfig } from '@netscanner/config';
import type { Logger } from '@netscanner/logger';
import type { RunSpeedTestUseCase } from './run-speed-test.use-case.js';

export interface SpeedTestWorkerDeps {
  config: AppConfig;
  logger: Logger;
  runSpeedTest: RunSpeedTestUseCase;
}

/** Periodic WAN speed sampling for historical reporting. */
export class SpeedTestWorker {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly deps: SpeedTestWorkerDeps) {}

  start(): void {
    if (!this.deps.config.SPEED_TEST_ENABLED) return;
    const ms = this.deps.config.SPEED_TEST_INTERVAL_MS;
    this.timer = setInterval(() => void this.run(), ms);
    setTimeout(() => void this.run(), 60_000);
    this.deps.logger.info({ intervalMs: ms }, 'speed test worker started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  reconfigure(): void {
    this.stop();
    this.start();
  }

  private async run(): Promise<void> {
    if (this.deps.runSpeedTest.isRunning()) return;
    try {
      await this.deps.runSpeedTest.execute('background');
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'background speed test failed',
      );
    }
  }
}
