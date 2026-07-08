import type { AppConfig } from './env-schema.js';

export type TopologyMode = 'simple' | 'vlan';

export interface TopologyConfig {
  mode: TopologyMode;
  /** Display order for VLAN tabs/labels (vlan mode). Empty = alphabetical. */
  vlanOrder: string[];
  /** pfSense interface label that marks the wired switch/AP uplink segment (vlan mode). */
  wiredVlan: string | null;
  /** Prefix for Mac Internet Sharing clients (optional branch). */
  macSharingPrefix: string;
}

export function parseTopologyVlanOrder(raw: string | undefined): string[] {
  if (!raw?.trim()) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolveTopologyConfig(config: AppConfig): TopologyConfig {
  const mode = config.TOPOLOGY_MODE === 'vlan' ? 'vlan' : 'simple';
  const vlanOrder = parseTopologyVlanOrder(config.TOPOLOGY_VLAN_ORDER);
  const wiredVlan = config.TOPOLOGY_WIRED_VLAN?.trim() || null;
  const macSharingPrefix = config.TOPOLOGY_MAC_SHARING_PREFIX?.trim() || '192.168.64.';
  return { mode, vlanOrder, wiredVlan, macSharingPrefix };
}

/** Sort VLAN rows for topology UI — configured order first, then alphabetical. */
export function sortTopologyVlans(
  vlans: { id: string; label: string }[],
  vlanOrder: string[],
): { id: string; label: string }[] {
  if (!vlanOrder.length) {
    return [...vlans].sort((a, b) => a.label.localeCompare(b.label));
  }
  return [...vlans].sort((a, b) => {
    const ai = vlanOrder.indexOf(a.id);
    const bi = vlanOrder.indexOf(b.id);
    if (ai >= 0 || bi >= 0) return (ai >= 0 ? ai : 99) - (bi >= 0 ? bi : 99);
    return a.label.localeCompare(b.label);
  });
}
