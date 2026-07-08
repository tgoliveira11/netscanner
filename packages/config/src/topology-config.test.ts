import { describe, expect, it } from 'vitest';
import {
  parseTopologyVlanOrder,
  resolveTopologyConfig,
  sortTopologyVlans,
} from './topology-config.js';

describe('topology-config', () => {
  it('defaults to simple mode', () => {
    const cfg = resolveTopologyConfig({} as never);
    expect(cfg.mode).toBe('simple');
    expect(cfg.vlanOrder).toEqual([]);
    expect(cfg.wiredVlan).toBeNull();
  });

  it('parses vlan order and wired segment', () => {
    const cfg = resolveTopologyConfig({
      TOPOLOGY_MODE: 'vlan',
      TOPOLOGY_VLAN_ORDER: 'VLAN40, VLAN10 ,VLAN30',
      TOPOLOGY_WIRED_VLAN: 'VLAN40',
      TOPOLOGY_MAC_SHARING_PREFIX: '192.168.64.',
    } as never);
    expect(cfg.mode).toBe('vlan');
    expect(cfg.vlanOrder).toEqual(['VLAN40', 'VLAN10', 'VLAN30']);
    expect(cfg.wiredVlan).toBe('VLAN40');
  });

  it('sorts configured VLANs first', () => {
    const sorted = sortTopologyVlans(
      [
        { id: 'VLAN20', label: 'VLAN20' },
        { id: 'VLAN10', label: 'VLAN10' },
        { id: 'VLAN40', label: 'VLAN40' },
      ],
      parseTopologyVlanOrder('VLAN40,VLAN10,VLAN30,VLAN20'),
    );
    expect(sorted.map((v) => v.id)).toEqual(['VLAN40', 'VLAN10', 'VLAN20']);
  });
});
