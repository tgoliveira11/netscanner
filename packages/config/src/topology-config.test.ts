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
      TOPOLOGY_VLAN_ORDER: 'LAN_INFRA, LAN_MAIN ,LAN_GUEST',
      TOPOLOGY_WIRED_VLAN: 'LAN_INFRA',
      TOPOLOGY_MAC_SHARING_PREFIX: '192.168.64.',
    } as never);
    expect(cfg.mode).toBe('vlan');
    expect(cfg.vlanOrder).toEqual(['LAN_INFRA', 'LAN_MAIN', 'LAN_GUEST']);
    expect(cfg.wiredVlan).toBe('LAN_INFRA');
  });

  it('sorts configured VLANs first', () => {
    const sorted = sortTopologyVlans(
      [
        { id: 'LAN_IOT', label: 'LAN_IOT' },
        { id: 'LAN_MAIN', label: 'LAN_MAIN' },
        { id: 'LAN_INFRA', label: 'LAN_INFRA' },
      ],
      parseTopologyVlanOrder('LAN_INFRA,LAN_MAIN,LAN_GUEST,LAN_IOT'),
    );
    expect(sorted.map((v) => v.id)).toEqual(['LAN_INFRA', 'LAN_MAIN', 'LAN_IOT']);
  });
});
