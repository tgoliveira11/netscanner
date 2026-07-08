'use client';

import { useEffect, useState } from 'react';
import type { ScanType } from '@netscanner/contracts';
import { api } from '../lib/api';
import { useStore } from '../lib/store';

const ALL = '__all__';

/** Scope + depth controls. CIDR list comes from local interfaces + Admin Extra scan CIDRs. */
export function ScanControls() {
  const scan = useStore((s) => s.scan);
  const [target, setTarget] = useState(ALL);
  const [scanCidrs, setScanCidrs] = useState<string[]>([]);
  const [scanType, setScanType] = useState<ScanType>('standard');
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const running = scan?.status === 'discovering' || scan?.status === 'fingerprinting';
  const scanAll = target === ALL;

  useEffect(() => {
    api
      .interfaces()
      .then((r) => {
        const cidrs = r.scanCidrs ?? [];
        setScanCidrs(cidrs);
        setLoadError(false);
        // Keep "All" as default; if only one CIDR exists, still allow All (= that one).
        if (cidrs.length && target !== ALL && !cidrs.includes(target)) {
          setTarget(ALL);
        }
      })
      .catch(() => setLoadError(true));
    // Intentionally once on mount — target is only reset when list no longer contains it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    setBusy(true);
    try {
      if (scanAll) {
        await api.startScan({ allCidrs: true, scanType });
      } else {
        await api.startScan({ cidr: target, scanType });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card space-y-3 p-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex min-w-[16rem] flex-col gap-1 text-xs text-muted">
          CIDR
          <select
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={!scanCidrs.length && !loadError}
            className="rounded-lg border border-edge bg-panelup px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent"
          >
            <option value={ALL}>
              All configured CIDRs{scanCidrs.length ? ` (${scanCidrs.length})` : ''}
            </option>
            {scanCidrs.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
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
        <button
          onClick={start}
          disabled={busy || running || (!scanAll && !target) || (scanAll && !scanCidrs.length)}
          className="btn btn-primary"
        >
          {running ? 'Scanning…' : busy ? 'Starting…' : scanAll ? 'Scan all CIDRs' : 'Start scan'}
        </button>
      </div>
      {scanAll && scanCidrs.length > 0 && (
        <p className="text-xs text-muted">
          Will scan: <span className="font-mono text-slate-300">{scanCidrs.join(', ')}</span>
        </p>
      )}
      {!scanCidrs.length && (
        <p className="text-xs text-amber-400/90">
          {loadError
            ? 'Could not load CIDRs from the agent.'
            : 'No CIDRs yet — set Extra scan CIDRs in Admin, or connect to a LAN.'}
        </p>
      )}
    </div>
  );
}
