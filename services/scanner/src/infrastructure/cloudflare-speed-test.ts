import type { Logger } from '@netscanner/logger';
import type { ISpeedTester, SpeedTestMeasurement, SpeedTestOptions } from '../domain/speed-test.js';

const DEFAULT_TIMEOUT_MS = 120_000;

function mbps(bytes: number, seconds: number): number {
  if (seconds <= 0 || bytes <= 0) return 0;
  return (bytes * 8) / seconds / 1_000_000;
}

/**
 * Uses Cloudflare's public speed endpoints (same as speed.cloudflare.com).
 * No API key; suitable for periodic background sampling from the agent host.
 */
export class CloudflareSpeedTester implements ISpeedTester {
  readonly name = 'cloudflare';

  constructor(private readonly logger: Logger) {}

  async run(options: SpeedTestOptions): Promise<SpeedTestMeasurement> {
    const base = options.baseUrl.replace(/\/$/, '');
    let latencyMs: number | null = null;
    let downloadMbps: number | null = null;
    let uploadMbps: number | null = null;
    let downloadBytes: number | null = null;
    let uploadBytes: number | null = null;
    const errors: string[] = [];

    try {
      latencyMs = await this.measureLatency(base);
    } catch (error) {
      errors.push(`latency: ${formatErr(error)}`);
    }

    if (options.downloadBytes > 0) {
      try {
        const dl = await this.measureDownload(base, options.downloadBytes);
        downloadMbps = dl.mbps;
        downloadBytes = dl.bytes;
      } catch (error) {
        errors.push(`download: ${formatErr(error)}`);
      }
    }

    if (options.uploadBytes > 0) {
      try {
        const ul = await this.measureUpload(base, options.uploadBytes);
        uploadMbps = ul.mbps;
        uploadBytes = ul.bytes;
      } catch (error) {
        errors.push(`upload: ${formatErr(error)}`);
      }
    }

    const error = errors.length ? errors.join('; ') : null;
    if (error) {
      this.logger.warn({ error, base }, 'speed test partial failure');
    } else {
      this.logger.info({ downloadMbps, uploadMbps, latencyMs }, 'speed test completed');
    }

    return {
      downloadMbps,
      uploadMbps,
      latencyMs,
      downloadBytes,
      uploadBytes,
      server: 'cloudflare',
      error,
    };
  }

  private async measureLatency(baseUrl: string): Promise<number> {
    const url = `${baseUrl}/__down?bytes=0`;
    const start = performance.now();
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await res.arrayBuffer();
    return Math.round(performance.now() - start);
  }

  private async measureDownload(baseUrl: string, bytes: number): Promise<{ mbps: number; bytes: number }> {
    const url = `${baseUrl}/__down?bytes=${bytes}`;
    const start = performance.now();
    const res = await fetch(url, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.arrayBuffer();
    const seconds = (performance.now() - start) / 1000;
    return { mbps: Math.round(mbps(data.byteLength, seconds) * 10) / 10, bytes: data.byteLength };
  }

  private async measureUpload(baseUrl: string, bytes: number): Promise<{ mbps: number; bytes: number }> {
    const url = `${baseUrl}/__up`;
    const body = new Uint8Array(bytes);
    const start = performance.now();
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body,
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await res.arrayBuffer();
    const seconds = (performance.now() - start) / 1000;
    return { mbps: Math.round(mbps(bytes, seconds) * 10) / 10, bytes };
  }
}

function formatErr(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
