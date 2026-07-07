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

  it('merges mdns TXT records', () => {
    const merged = mergePassiveSignals(
      { mdnsTxt: { model: 'AppleTV' } },
      { mdnsTxt: { osxvers: '17.0' }, mdnsModel: 'AppleTV6,2' },
    );
    expect(merged.mdnsTxt).toEqual({ model: 'AppleTV', osxvers: '17.0' });
    expect(merged.mdnsModel).toBe('AppleTV6,2');
  });

  it('merges igmp group lists', () => {
    const merged = mergePassiveSignals(
      { igmpGroups: ['239.255.255.250'] },
      { igmpGroups: ['224.0.0.251'], igmpPassive: true },
    );
    expect(merged.igmpGroups).toEqual(['239.255.255.250', '224.0.0.251']);
  });
});
