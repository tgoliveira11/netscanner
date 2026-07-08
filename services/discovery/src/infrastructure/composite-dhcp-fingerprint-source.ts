import type {
  DhcpFingerprint,
  IDhcpFingerprintSource,
} from '../domain/dhcp-fingerprint.js';

/** Optional iface reporting for status APIs. */
export interface DhcpSniffIfaceReporter {
  sniffIfaces(): string[];
}

/**
 * Merges local + remote DHCP fingerprint sources. First-seen fingerprint per MAC
 * wins for get/list; listeners fan in; start/stop run on all children.
 */
export class CompositeDhcpFingerprintSource implements IDhcpFingerprintSource, DhcpSniffIfaceReporter {
  private readonly unsubs: Array<() => void> = [];
  private readonly capturedHandlers = new Set<(fp: DhcpFingerprint) => void>();

  constructor(private readonly sources: IDhcpFingerprintSource[]) {}

  async start(): Promise<void> {
    for (const source of this.sources) {
      this.unsubs.push(
        source.onCaptured((fp) => {
          for (const handler of this.capturedHandlers) {
            try {
              handler(fp);
            } catch {
              /* ignore */
            }
          }
        }),
      );
      try {
        await source.start();
      } catch {
        /* child logs its own failure; continue */
      }
    }
  }

  stop(): void {
    for (const unsub of this.unsubs) unsub();
    this.unsubs.length = 0;
    for (const source of this.sources) {
      try {
        source.stop();
      } catch {
        /* ignore */
      }
    }
  }

  get(mac: string): DhcpFingerprint | undefined {
    for (const source of this.sources) {
      const fp = source.get(mac);
      if (fp) return fp;
    }
    return undefined;
  }

  list(): DhcpFingerprint[] {
    const byMac = new Map<string, DhcpFingerprint>();
    for (const source of this.sources) {
      for (const fp of source.list()) {
        const key = fp.mac.toLowerCase();
        if (!byMac.has(key)) byMac.set(key, fp);
      }
    }
    return [...byMac.values()];
  }

  size(): number {
    return this.list().length;
  }

  isListening(): boolean {
    return this.sources.some((s) => s.isListening());
  }

  mode(): string | null {
    const modes = this.sources.map((s) => s.mode()).filter((m): m is string => Boolean(m));
    if (!modes.length) return null;
    if (modes.length === 1) return modes[0]!;
    return `composite:${modes.join('+')}`;
  }

  sniffIfaces(): string[] {
    const out: string[] = [];
    for (const source of this.sources) {
      const reporter = source as IDhcpFingerprintSource & Partial<DhcpSniffIfaceReporter>;
      if (typeof reporter.sniffIfaces === 'function') {
        out.push(...reporter.sniffIfaces());
      }
    }
    return out;
  }

  onCaptured(handler: (fp: DhcpFingerprint) => void): () => void {
    this.capturedHandlers.add(handler);
    return () => this.capturedHandlers.delete(handler);
  }
}
