import { describe, it, expect } from 'vitest';
import { mergePassiveSignals } from './domain/passive-signal-store.js';

describe('mergePassiveSignals', () => {
  it('merges mdns service lists without duplicates', () => {
    const merged = mergePassiveSignals(
      { mdnsServices: ['airplay:Living Room'], mdnsType: 'airplay' },
      { mdnsServices: ['airplay:Living Room', 'raop:Speaker'], mdnsPassive: true },
    );
    expect(merged.mdnsServices).toEqual(['airplay:Living Room', 'raop:Speaker']);
    expect(merged.mdnsPassive).toBe(true);
  });
});
