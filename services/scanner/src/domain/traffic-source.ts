/** A point-in-time per-device traffic sample (cumulative byte counters). */
export interface TrafficSample {
  ip: string;
  bytesIn: number;
  bytesOut: number;
  connections: number;
  topPeers?: { ip: string; bytes: number }[];
}

/**
 * Port for a per-device traffic source (DIP). Adapters: pfSense REST firewall states,
 * pfctl over SSH (legacy), or ntopng API. Returns cumulative counters;
 * the RateCalculator derives bps by diffing successive samples.
 */
export interface ITrafficSource {
  readonly name: string;
  sample(): Promise<TrafficSample[]>;
}

interface Prev {
  bytes: number;
  at: number;
}

/**
 * Derives a bytes/second rate from successive cumulative samples, per IP.
 * Handles counter resets (current < previous → rate 0). Pure state machine.
 */
export class RateCalculator {
  private readonly prev = new Map<string, Prev>();

  /** Returns rate in bits/s for `ip` given the new cumulative total. */
  update(ip: string, cumulativeBytes: number, now = Date.now()): number {
    const prev = this.prev.get(ip);
    this.prev.set(ip, { bytes: cumulativeBytes, at: now });
    if (!prev) return 0;
    const dt = (now - prev.at) / 1000;
    if (dt <= 0) return 0;
    const delta = cumulativeBytes - prev.bytes;
    if (delta < 0) return 0; // counter reset
    return Math.round((delta * 8) / dt);
  }
}
