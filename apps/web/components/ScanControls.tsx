'use client';

import { useEffect, useState } from 'react';
import type { ScanType } from '@netscanner/contracts';
import { api } from '../lib/api';
import { useStore } from '../lib/store';

/** Subnet + scan-depth controls that kick off a scan (progress arrives via WS). */
export function ScanControls() {
  const scan = useStore((s) => s.scan);
  const [cidr, setCidr] = useState('');
  const [scanType, setScanType] = useState<ScanType>('standard');
  const [busy, setBusy] = useState(false);
  const running = scan?.status === 'discovering' || scan?.status === 'fingerprinting';

  useEffect(() => {
    api
      .interfaces()
      .then((r) => r.primaryCidr && setCidr(r.primaryCidr))
      .catch(() => undefined);
  }, []);

  const start = async () => {
    setBusy(true);
    try {
      await api.startScan({ cidr: cidr || undefined, scanType });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card flex flex-wrap items-end gap-3 p-4">
      <label className="flex flex-col gap-1 text-xs text-muted">
        Subnet (CIDR)
        <input
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
          placeholder="192.168.1.0/24"
          className="w-48 rounded-lg border border-edge bg-panelup px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Depth
        <select
          value={scanType}
          onChange={(e) => setScanType(e.target.value as ScanType)}
          className="rounded-lg border border-edge bg-panelup px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent"
        >
          <option value="quick">Quick (top ports)</option>
          <option value="standard">Standard (1000 ports)</option>
          <option value="deep">Deep (all ports + OS)</option>
        </select>
      </label>
      <button onClick={start} disabled={busy || running} className="btn btn-primary">
        {running ? 'Scanning…' : busy ? 'Starting…' : 'Start scan'}
      </button>
    </div>
  );
}
