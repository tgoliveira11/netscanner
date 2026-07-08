export interface SpeedTestMeasurement {
  downloadMbps: number | null;
  uploadMbps: number | null;
  latencyMs: number | null;
  downloadBytes: number | null;
  uploadBytes: number | null;
  server: string;
  error: string | null;
}

export interface SpeedTestOptions {
  baseUrl: string;
  downloadBytes: number;
  uploadBytes: number;
}

/** Measures WAN throughput (download/upload/latency). */
export interface ISpeedTester {
  readonly name: string;
  run(options: SpeedTestOptions): Promise<SpeedTestMeasurement>;
}
