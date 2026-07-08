export interface DnsActivityEntry {
  at: string;
  deviceId: string;
  deviceLabel: string;
  message: string;
}

/** Ring buffer for external DNS discoveries — shown on Relations, not in Alerts. */
export class DnsActivityLog {
  private entries: DnsActivityEntry[] = [];

  constructor(private readonly max = 200) {}

  push(entry: DnsActivityEntry): void {
    this.entries.unshift(entry);
    if (this.entries.length > this.max) this.entries.length = this.max;
  }

  list(): DnsActivityEntry[] {
    return [...this.entries];
  }
}
