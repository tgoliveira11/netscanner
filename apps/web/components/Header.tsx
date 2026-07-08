'use client';

import { api } from '../lib/api';
import { useStore } from '../lib/store';
import { AlertsBell } from './AlertsBell';

/** Top bar: brand, live status, alerts, export, admin link. */
export function Header() {
  const connected = useStore((s) => s.connected);
  const caps = useStore((s) => s.capabilities);

  return (
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-edge pb-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">
          Net<span className="text-accent">Scanner</span>
        </h1>
        <p className="text-xs text-muted">Discover & classify every device on your network — scan only networks you own.</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`badge ${connected ? 'bg-good/15 text-good' : 'bg-bad/15 text-bad'}`}>
          {connected ? '● live' : '○ offline'}
        </span>
        <span
          className={`badge ${caps?.nmap ? 'bg-good/15 text-good' : 'bg-edge text-muted'}`}
          title={
            caps?.nmap
              ? undefined
              : caps?.nmapOffReason === 'disabled-by-config'
                ? 'DISABLE_NMAP=true in config'
                : caps?.nmapOffReason === 'not-in-path'
                  ? 'nmap not in PATH'
                  : 'nmap off'
          }
        >
          nmap {caps?.nmap ? 'on' : 'off'}
        </span>
        <span className={`badge ${caps?.elevated ? 'bg-good/15 text-good' : 'bg-edge text-muted'}`}>
          {caps?.elevated ? 'elevated' : 'unprivileged'}
        </span>
        <AlertsBell />
        <a href="/admin/" className="btn btn-ghost">
          Admin
        </a>
        <a href={api.exportUrl('json')} className="btn btn-ghost">
          Export JSON
        </a>
        <a href={api.exportUrl('csv')} className="btn btn-ghost">
          Export CSV
        </a>
      </div>
    </header>
  );
}
