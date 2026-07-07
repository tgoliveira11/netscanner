import type { IConnectionSource, ConnectionLookup } from '@netscanner/contracts';

/** Try multiple connection sources; first authoritative hit wins. */
export class CompositeConnectionSource implements IConnectionSource {
  readonly name = 'composite';

  constructor(private readonly sources: IConnectionSource[]) {}

  async refresh(): Promise<void> {
    await Promise.allSettled(this.sources.map((s) => s.refresh()));
  }

  lookupByMac(mac: string): ConnectionLookup | null {
    for (const s of this.sources) {
      const hit = s.lookupByMac(mac);
      if (hit) return hit;
    }
    return null;
  }
}
