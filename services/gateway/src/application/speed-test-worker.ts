import type { AppConfig } from '@netscanner/config';
import type { Logger } from '@netscanner/logger';
import type { RunSpeedTestUseCase } from './run-speed-test.use-case.js';
import type { ISpeedTestRepository } from '@netscanner/inventory';

export interface SpeedTestWorkerDeps {
  config: AppConfig;
  logger: Logger;
  runSpeedTest: RunSpeedTestUseCase;
  speedTestRepo: ISpeedTestRepository;
}

/** Periodic WAN speed sampling for historical reporting. */
export class SpeedTestWorker {
  private timer: ReturnType<typeof setInterval> | null = null;
  private purgeTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly deps: SpeedTestWorkerDeps) {}

  start(): void {
    if (!this.deps.config.SPEED_TEST_ENABLED) return;
    const ms = this.deps.config.SPEED_TEST_INTERVAL_MS;
    this.timer = setInterval(() => void this.run(), ms);
    setTimeout(() => void this.run(), 60_000);
    void this.purge();
    this.purgeTimer = setInterval(() => void this.purge(), 86_400_000);
    this.deps.logger.info({ intervalMs: ms }, 'speed test worker started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    if (this.purgeTimer) clearInterval(this.purgeTimer);
    this.timer = null;
    this.purgeTimer = null;
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

  private async purge(): Promise<void> {
    const days = this.deps.config.SPEED_TEST_RETENTION_DAYS;
    const before = new Date(Date.now() - days * 86_400_000);
    try {
      const removed = await this.deps.speedTestRepo.deleteOlderThan(before);
      if (removed > 0) {
        this.deps.logger.info({ removed, retentionDays: days }, 'speed test history pruned');
      }
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'speed test purge failed',
      );
    }
  }
}
