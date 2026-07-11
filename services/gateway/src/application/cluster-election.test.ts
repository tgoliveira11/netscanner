import { describe, expect, it } from 'vitest';
import {
  electionScore,
  pickClusterLeaders,
  type ElectionCandidate,
} from './cluster-election.js';

function cand(partial: Partial<ElectionCandidate> & { agentId: string }): ElectionCandidate {
  return {
    dedicated: false,
    preferLeader: false,
    elevated: true,
    uptimeSec: 100,
    canInventory: true,
    canControl: false,
    ...partial,
  };
}

describe('pickClusterLeaders', () => {
  it('portable Mac yields to dedicated box when both are present', () => {
    const mac = cand({ agentId: 'mac-1', uptimeSec: 999_999, elevated: true });
    const box = cand({
      agentId: 'box-1',
      dedicated: true,
      preferLeader: true,
      canControl: true,
      uptimeSec: 10,
    });
    const { inventoryLeaderId, controlLeaderId } = pickClusterLeaders([mac, box]);
    expect(inventoryLeaderId).toBe('box-1');
    expect(controlLeaderId).toBe('box-1');
  });

  it('portable Mac becomes inventory leader when alone (other network)', () => {
    const mac = cand({ agentId: 'mac-1', canControl: false });
    const { inventoryLeaderId, controlLeaderId } = pickClusterLeaders([mac]);
    expect(inventoryLeaderId).toBe('mac-1');
    expect(controlLeaderId).toBeNull();
  });

  it('portable Mac takes over after preferred peer disappears from the candidate set', () => {
    const mac = cand({ agentId: 'mac-1' });
    expect(pickClusterLeaders([mac]).inventoryLeaderId).toBe('mac-1');
  });

  it('preferLeader without dedicated still beats a portable helper', () => {
    const mac = cand({ agentId: 'mac-1', uptimeSec: 50_000 });
    const box = cand({ agentId: 'box-1', preferLeader: true, uptimeSec: 1 });
    expect(pickClusterLeaders([mac, box]).inventoryLeaderId).toBe('box-1');
  });

  it('among two preferred peers, higher election score wins', () => {
    const a = cand({ agentId: 'a', dedicated: true, preferLeader: true, uptimeSec: 10 });
    const b = cand({ agentId: 'b', dedicated: true, preferLeader: true, uptimeSec: 500 });
    expect(electionScore(b)).toBeGreaterThan(electionScore(a));
    expect(pickClusterLeaders([a, b]).inventoryLeaderId).toBe('b');
  });
});
