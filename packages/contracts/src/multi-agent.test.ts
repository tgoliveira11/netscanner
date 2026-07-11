import { describe, expect, it } from 'vitest';
import {
  AgentCapabilitiesSchema,
  listEnabledCapabilities,
  normalizeAgentCapabilities,
  peerCanRunTask,
  requiredCapabilityForTask,
  shardCidrs,
  TASK_REQUIRED_CAPABILITY,
} from './multi-agent.js';

describe('shardCidrs', () => {
  it('round-robins cidrs across workers', () => {
    const shards = shardCidrs(['a', 'b', 'c', 'd', 'e'], 3);
    expect(shards).toEqual([['a', 'd'], ['b', 'e'], ['c']]);
  });

  it('handles single worker', () => {
    expect(shardCidrs(['a', 'b'], 1)).toEqual([['a', 'b']]);
  });
});

describe('capability normalization', () => {
  it('maps legacy scan/wifi/inventory onto fine-grained flags', () => {
    const caps = normalizeAgentCapabilities({ scan: true, wifi: true, inventory: true });
    expect(caps.inventoryScan).toBe(true);
    expect(caps.wifiRf).toBe(true);
    expect(caps.inventory).toBe(true);
    expect(caps.scan).toBe(true);
    expect(caps.wifi).toBe(true);
  });

  it('parses mixed beacons via AgentCapabilitiesSchema', () => {
    const caps = AgentCapabilitiesSchema.parse({ scan: true, elevated: true });
    expect(caps.inventoryScan).toBe(true);
    expect(caps.elevated).toBe(true);
    expect(listEnabledCapabilities(caps)).toContain('inventory-scan');
    expect(listEnabledCapabilities(caps)).toContain('elevated');
  });
});

describe('task → capability map', () => {
  it('requires inventory-scan for scan-cidr', () => {
    expect(requiredCapabilityForTask('scan-cidr')).toBe('inventory-scan');
    expect(TASK_REQUIRED_CAPABILITY['wifi-analyze']).toBe('wifi-rf');
    expect(TASK_REQUIRED_CAPABILITY['speed-wan']).toBe('speed-wan');
  });

  it('peerCanRunTask checks advertised caps', () => {
    const worker = normalizeAgentCapabilities({ inventoryScan: true, wifiRf: true });
    expect(peerCanRunTask(worker, 'scan-cidr')).toBe(true);
    expect(peerCanRunTask(worker, 'wifi-analyze')).toBe(true);
    expect(peerCanRunTask(worker, 'speed-wan')).toBe(false);
  });
});
