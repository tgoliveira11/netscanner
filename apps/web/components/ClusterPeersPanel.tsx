'use client';

import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';

type ClusterStatus = {
  role: string;
  term: number;
  isInventoryLeader: boolean;
  isControlLeader: boolean;
  inventoryLeaderId: string | null;
  controlLeaderId: string | null;
  beaconPort: number;
  mdnsName: string | null;
  self: {
    agentId: string;
    hostname: string;
    profile: string;
    dedicated: boolean;
    preferLeader: boolean;
    capabilities: Record<string, boolean>;
  };
  peers: Array<{
    agentId: string;
    hostname: string;
    address: string;
    role: string;
    profile: string;
    dedicated: boolean;
    stale: boolean;
    lastSeenAt: string;
    capabilities: Record<string, boolean>;
  }>;
};

export function ClusterPeersPanel() {
  const [status, setStatus] = useState<ClusterStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const s = (await api.getClusterStatus()) as ClusterStatus;
      setStatus(s);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 5_000);
    return () => clearInterval(t);
  }, [load]);

  if (error) {
    return <p className="text-sm text-bad">Cluster: {error}</p>;
  }
  if (!status) {
    return <p className="text-sm text-muted">Loading cluster…</p>;
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
          <div className="text-[10px] uppercase text-muted">Role</div>
          <div className="text-sm font-medium text-slate-100">{status.role}</div>
        </div>
        <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
          <div className="text-[10px] uppercase text-muted">Inventory leader</div>
          <div className="truncate text-sm text-slate-100">
            {status.isInventoryLeader ? 'this agent' : status.inventoryLeaderId ?? '—'}
          </div>
        </div>
        <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
          <div className="text-[10px] uppercase text-muted">Control leader</div>
          <div className="truncate text-sm text-slate-100">
            {status.isControlLeader ? 'this agent' : status.controlLeaderId ?? '—'}
          </div>
        </div>
        <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
          <div className="text-[10px] uppercase text-muted">mDNS</div>
          <div className="text-sm text-slate-100">{status.mdnsName ?? 'off'}</div>
        </div>
      </div>

      <div className="rounded-lg border border-edge bg-panelup p-3 text-xs text-slate-300">
        <div>
          <span className="text-muted">Self:</span> {status.self.hostname}{' '}
          <span className="font-mono text-[10px] text-muted">{status.self.agentId.slice(0, 8)}…</span>
        </div>
        <div className="mt-1">
          profile={status.self.profile} dedicated={String(status.self.dedicated)} preferLeader=
          {String(status.self.preferLeader)} term={status.term} beacon={status.beaconPort}
        </div>
      </div>

      <div className="overflow-x-auto rounded-lg border border-edge">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-edge bg-panelup text-[10px] uppercase text-muted">
            <tr>
              <th className="px-2 py-1.5">Host</th>
              <th className="px-2 py-1.5">Role</th>
              <th className="px-2 py-1.5">Address</th>
              <th className="px-2 py-1.5">Profile</th>
              <th className="px-2 py-1.5">Caps</th>
              <th className="px-2 py-1.5">Seen</th>
            </tr>
          </thead>
          <tbody>
            {status.peers.length === 0 && (
              <tr>
                <td colSpan={6} className="px-2 py-4 text-center text-muted">
                  No peers yet — start another agent on the LAN with CLUSTER_ENABLED=true.
                </td>
              </tr>
            )}
            {status.peers.map((p) => (
              <tr key={p.agentId} className="border-b border-edge/50">
                <td className="px-2 py-1.5 text-slate-100">
                  {p.hostname}
                  {p.dedicated ? ' · dedicated' : ''}
                  {p.stale ? ' · stale' : ''}
                </td>
                <td className="px-2 py-1.5">{p.role}</td>
                <td className="px-2 py-1.5 font-mono">{p.address}</td>
                <td className="px-2 py-1.5">{p.profile}</td>
                <td className="px-2 py-1.5 text-muted">
                  {Object.entries(p.capabilities)
                    .filter(([, v]) => v)
                    .map(([k]) => k)
                    .join(', ') || '—'}
                </td>
                <td className="px-2 py-1.5 text-muted">
                  {new Date(p.lastSeenAt).toLocaleTimeString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
