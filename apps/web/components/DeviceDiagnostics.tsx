'use client';

import { useState } from 'react';
import type { Device } from '@netscanner/contracts';
import { api } from '../lib/api';

export function DeviceDiagnostics({ device }: { device: Device }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [output, setOutput] = useState<string | null>(null);
  const [dnsName, setDnsName] = useState(device.hostname ?? device.ip);
  const [portDepth, setPortDepth] = useState<'quick' | 'standard'>('quick');

  const run = async (label: string, fn: () => Promise<{ output?: string } & Record<string, unknown>>) => {
    setBusy(label);
    setError(null);
    try {
      const res = await fn();
      const text =
        typeof res.output === 'string'
          ? res.output
          : JSON.stringify(res, null, 2);
      setOutput(text);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setOutput(null);
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="mt-5 space-y-2">
      <h3 className="text-sm font-semibold text-slate-200">Diagnostics</h3>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={!!busy}
          className="btn btn-ghost text-xs"
          onClick={() => void run('ping', () => api.diagnosticsPing(device.ip))}
        >
          {busy === 'ping' ? 'Pinging…' : 'Ping'}
        </button>
        <button
          type="button"
          disabled={!!busy}
          className="btn btn-ghost text-xs"
          onClick={() => void run('trace', () => api.diagnosticsTraceroute(device.ip))}
        >
          {busy === 'trace' ? 'Tracing…' : 'Traceroute'}
        </button>
        <button
          type="button"
          disabled={!!busy}
          className="btn btn-ghost text-xs"
          onClick={() =>
            void run('port', () => api.diagnosticsPortScan(device.ip, portDepth))
          }
        >
          {busy === 'port' ? 'Scanning…' : 'Port scan'}
        </button>
        <select
          value={portDepth}
          onChange={(e) => setPortDepth(e.target.value as 'quick' | 'standard')}
          className="rounded-lg border border-edge bg-panelup px-2 py-1 text-xs"
        >
          <option value="quick">Quick</option>
          <option value="standard">Standard</option>
        </select>
      </div>
      <div className="flex gap-2">
        <input
          value={dnsName}
          onChange={(e) => setDnsName(e.target.value)}
          placeholder="hostname or IP"
          className="min-w-0 flex-1 rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs font-mono outline-none focus:border-accent"
        />
        <button
          type="button"
          disabled={!!busy}
          className="btn btn-ghost text-xs"
          onClick={() => void run('dns', () => api.diagnosticsDns(dnsName))}
        >
          {busy === 'dns' ? '…' : 'DNS'}
        </button>
      </div>
      {error && <p className="text-xs text-bad">{error}</p>}
      {output && (
        <pre className="max-h-48 overflow-auto rounded-lg border border-edge bg-panelup p-3 text-[10px] leading-relaxed text-slate-300">
          {output}
        </pre>
      )}
    </section>
  );
}
