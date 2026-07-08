'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { AppNav } from '../../components/AppNav';
import { api, type AdminConfigResponse, type AdminObservability, type AdminLogLine, type AdminWirelessResponse, type ConfigFieldSchema } from '../../lib/api';

function LogViewer({ lines }: { lines: AdminLogLine[] }) {
  return (
    <div className="max-h-96 overflow-auto rounded-lg border border-edge bg-panelup p-2 font-mono text-[11px] leading-relaxed">
      {lines.map((l, i) => (
        <div key={i} className="border-b border-edge/40 py-0.5 last:border-0">
          <span className="text-muted">{l.at ? new Date(l.at).toLocaleTimeString() : '—'} </span>
          <span
            className={
              l.levelLabel === 'error' || l.levelLabel === 'fatal'
                ? 'text-bad'
                : l.levelLabel === 'warn'
                  ? 'text-warn'
                  : 'text-accent'
            }
          >
            [{l.levelLabel}]
          </span>{' '}
          <span className="text-slate-200">{l.msg || String((l.raw as { line?: string }).line ?? '')}</span>
        </div>
      ))}
      {lines.length === 0 && <p className="py-4 text-center text-muted">No log lines.</p>}
    </div>
  );
}

function StatusCard({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-0.5 text-sm font-medium text-slate-100">{value}</div>
    </div>
  );
}

function ConfigField({
  field,
  value,
  draft,
  onChange,
}: {
  field: ConfigFieldSchema;
  value: string | number | boolean | null;
  draft: string;
  onChange: (key: string, v: string | number | boolean) => void;
}) {
  const id = `cfg-${field.key}`;
  if (field.type === 'boolean') {
    return (
      <label htmlFor={id} className="flex cursor-pointer items-start gap-3 rounded-lg border border-edge bg-panelup p-3">
        <input
          id={id}
          type="checkbox"
          checked={Boolean(draft !== '' ? draft === 'true' : value)}
          onChange={(e) => onChange(field.key, e.target.checked)}
          className="mt-1"
        />
        <span>
          <span className="block text-sm font-medium text-slate-200">{field.label}</span>
          <span className="text-xs text-muted">{field.description}</span>
          {field.restartRequired && <span className="ml-1 text-[10px] text-warn">· restart</span>}
        </span>
      </label>
    );
  }

  return (
    <div className="rounded-lg border border-edge bg-panelup p-3">
      <label htmlFor={id} className="block text-sm font-medium text-slate-200">
        {field.label}
        {field.restartRequired && <span className="ml-1 text-[10px] font-normal text-warn">· restart</span>}
      </label>
      <p className="mb-2 text-xs text-muted">{field.description}</p>
      <input
        id={id}
        type={field.type === 'secret' ? 'password' : field.type === 'number' ? 'number' : 'text'}
        value={draft}
        placeholder={field.type === 'secret' && value ? '••••••••' : ''}
        onChange={(e) => onChange(field.key, field.type === 'number' ? Number(e.target.value) : e.target.value)}
        className="w-full rounded-lg border border-edge bg-base px-3 py-2 text-sm outline-none focus:border-accent"
      />
    </div>
  );
}

export default function AdminPage() {
  const [obs, setObs] = useState<AdminObservability | null>(null);
  const [config, setConfig] = useState<AdminConfigResponse | null>(null);
  const [logs, setLogs] = useState<AdminLogLine[]>([]);
  const [wireless, setWireless] = useState<AdminWirelessResponse | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const restartingRef = useRef(false);

  const refreshWireless = useCallback(async () => {
    try {
      setWireless(await api.adminWireless());
    } catch {
      /* wireless probe is slow — don't block the rest of admin */
    }
  }, []);

  const refresh = useCallback(async (opts?: { skipWireless?: boolean }) => {
    try {
      const [o, c, l] = await Promise.all([
        api.adminObservability(),
        api.adminConfig(),
        api.adminLogs(250),
      ]);
      setObs(o);
      setConfig(c);
      setLogs([...l.memory, ...l.file].slice(-300));
      setError(null);
      if (!opts?.skipWireless) void refreshWireless();
    } catch (e) {
      if (restartingRef.current) return;
      const msg = e instanceof Error ? e.message : 'Failed to load admin data';
      if (msg === 'Failed to fetch') {
        setError('Agent indisponível — verifique se está rodando em http://127.0.0.1:4000');
      } else {
        setError(msg);
      }
    }
  }, [refreshWireless]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 15_000);
    return () => clearInterval(t);
  }, [refresh]);

  const grouped = useMemo(() => {
    if (!config) return new Map<string, ConfigFieldSchema[]>();
    const m = new Map<string, ConfigFieldSchema[]>();
    for (const f of config.schema) {
      const list = m.get(f.group) ?? [];
      list.push(f);
      m.set(f.group, list);
    }
    return m;
  }, [config]);

  const onFieldChange = (key: string, v: string | number | boolean) => {
    setDraft((d) => ({ ...d, [key]: String(v) }));
  };

  const save = async () => {
    if (!config) return;
    setSaving(true);
    setMessage(null);
    try {
      const body: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(draft)) {
        const field = config.schema.find((f) => f.key === k);
        if (!field) continue;
        if (field.type === 'boolean') body[k] = v === 'true';
        else if (field.type === 'number') body[k] = Number(v);
        else body[k] = v;
      }
      const res = await api.adminUpdateConfig(body);
      setConfig((c) => (c ? { ...c, values: res.values } : c));
      setDraft({});
      setMessage(
        res.restartRequired
          ? 'Saved. Some changes require an agent restart.'
          : 'Configuration saved and applied.',
      );
      void refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const restart = async () => {
    setError(null);
    setMessage('Reiniciando agente…');
    restartingRef.current = true;
    try {
      await api.agentRestart();
      setMessage('Agente reiniciado.');
      await refresh({ skipWireless: true });
      void refreshWireless();
    } catch (e) {
      setMessage(null);
      const msg = e instanceof Error ? e.message : 'Restart failed';
      setError(msg === 'Failed to fetch' ? 'Não foi possível contactar o agente durante o restart.' : msg);
    } finally {
      restartingRef.current = false;
    }
  };

  const bg = obs?.background as Record<string, unknown> | undefined;

  return (
    <main className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-edge pb-4">
        <div className="flex min-w-0 flex-1 flex-col gap-2 sm:flex-row sm:items-center sm:gap-6">
          <div>
            <h1 className="text-xl font-bold text-slate-100">
              Net<span className="text-accent">Scanner</span>{' '}
              <span className="text-base font-normal text-muted">Admin</span>
            </h1>
            <p className="text-xs text-muted">Observability and runtime configuration (localhost only, no auth yet).</p>
          </div>
          <AppNav />
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void refresh()} className="btn btn-ghost">
            Refresh
          </button>
          <button type="button" onClick={() => void restart()} className="btn btn-ghost">
            Restart agent
          </button>
        </div>
      </header>

      {error && <div className="rounded-lg border border-bad/40 bg-bad/10 px-4 py-2 text-sm text-bad">{error}</div>}
      {message && (
        <div className="rounded-lg border border-good/40 bg-good/10 px-4 py-2 text-sm text-good">{message}</div>
      )}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-200">Runtime status</h2>
        {obs && (
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <StatusCard label="Version" value={obs.version} />
            <StatusCard label="Uptime" value={`${obs.uptimeSec}s · pid ${obs.pid}`} />
            <StatusCard label="Devices" value={obs.inventory.deviceCount} />
            <StatusCard label="Primary CIDR" value={obs.primaryCidr ?? '—'} />
            <StatusCard
              label="nmap"
              value={
                obs.capabilities.nmap
                  ? 'yes'
                  : obs.capabilities.nmapOffReason === 'disabled-by-config'
                    ? 'no (DISABLE_NMAP)'
                    : obs.capabilities.nmapOffReason === 'not-in-path'
                      ? 'no (not in PATH)'
                      : 'no'
              }
            />
            <StatusCard label="Elevated" value={obs.capabilities.elevated ? 'yes' : 'no'} />
            <StatusCard label="DHCP sniffer" value={String(bg?.dhcpListening ?? false)} />
            <StatusCard label="DHCP mode" value={String(bg?.dhcpMode ?? '—')} />
            <StatusCard
              label="DHCP ifaces"
              value={
                Array.isArray(bg?.dhcpSniffIfaces) && (bg.dhcpSniffIfaces as string[]).length
                  ? (bg.dhcpSniffIfaces as string[]).join(', ')
                  : '—'
              }
            />
            <StatusCard
              label="DHCP fingerprints"
              value={`${bg?.dhcpInMemory ?? 0} live · ${bg?.dhcpPersisted ?? 0} stored`}
            />
            <StatusCard label="Passive signals" value={String(bg?.passiveSignals ?? 0)} />
            <StatusCard label="Background scan" value={String(bg?.scanEnabled ?? false)} />
            <StatusCard label="Config file" value={<span className="break-all text-xs">{obs.configPath}</span>} />
            <StatusCard
              label="Active scan"
              value={
                bg?.activeScan
                  ? `${(bg.activeScan as { status: string }).status} · ${(bg.activeScan as { cidr: string }).cidr}`
                  : 'none'
              }
            />
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-200">WiFi / SSIDs (OpenWrt scrape targets)</h2>
        {!wireless?.configured && (
          <p className="text-xs text-muted">Configure ROUTER_SCRAPE_TARGETS or ROUTER_SCRAPE_URL with kind=openwrt.</p>
        )}
        {wireless?.configured && (
          <div className="grid gap-3 md:grid-cols-2">
            {wireless.routers.map((r) => (
              <div key={r.url} className="rounded-lg border border-edge bg-panelup p-3">
                <div className="text-sm font-medium text-slate-200">{r.host}</div>
                <div className="text-xs text-muted">{r.url}</div>
                {!r.ok && <div className="mt-1 text-xs text-bad">{r.error ?? 'probe failed'}</div>}
                {r.ok && r.ssids.length === 0 && (
                  <div className="mt-1 text-xs text-muted">No WiFi radios / SSIDs (switch or WiFi disabled)</div>
                )}
                {r.ok && r.ssids.length > 0 && (
                  <ul className="mt-2 space-y-1 text-xs text-slate-300">
                    {r.ssids.map((s) => (
                      <li key={`${s.device}-${s.ifname}`}>
                        <span className={s.up ? 'text-good' : 'text-muted'}>{s.up ? '●' : '○'}</span>{' '}
                        <span className="font-medium">{s.ssid || '(hidden)'}</span>
                        <span className="text-muted"> · {s.device} ch={s.channel ?? '—'} {s.mode ?? ''}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-200">Recent discoveries</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="card p-4">
            <h3 className="mb-2 text-xs font-semibold uppercase text-muted">DHCP fingerprints</h3>
            {!(obs?.dhcpFingerprints?.length) ? (
              <div className="space-y-2 text-xs text-muted">
                <p>
                  None captured yet
                  {bg?.dhcpListening
                    ? ` — sniffer is listening (${String(bg?.dhcpMode ?? 'unknown')}).`
                    : ' — sniffer is not listening.'}
                </p>
                <p>
                  Fingerprints only appear after a client sends DHCP DISCOVER/REQUEST/INFORM on the wire
                  (reconnect Ethernet / renew lease). Lease APIs do not include option 55.
                </p>
                {Array.isArray(bg?.dhcpSniffIfaces) && (bg.dhcpSniffIfaces as string[]).length > 0 && (
                  <p className="font-mono text-[11px] text-slate-400">
                    ifaces: {(bg.dhcpSniffIfaces as string[]).join(', ')}
                  </p>
                )}
              </div>
            ) : (
              <pre className="max-h-48 overflow-auto text-[11px] text-slate-300">
                {JSON.stringify(obs.dhcpFingerprints, null, 2)}
              </pre>
            )}
          </div>
          <div className="card p-4">
            <h3 className="mb-2 text-xs font-semibold uppercase text-muted">Passive signals (sample)</h3>
            {!(obs?.passiveSample?.length) ? (
              <p className="text-xs text-muted">No passive signal samples yet.</p>
            ) : (
              <pre className="max-h-48 overflow-auto text-[11px] text-slate-300">
                {JSON.stringify(obs.passiveSample, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-200">Logs</h2>
        <LogViewer lines={logs} />
      </section>

      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Configuration</h2>
          <button type="button" disabled={saving || !Object.keys(draft).length} onClick={() => void save()} className="btn btn-primary">
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </div>
        {config &&
          [...grouped.entries()].map(([group, fields]) => (
            <div key={group} className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">{group}</h3>
              <div className="grid gap-3 md:grid-cols-2">
                {fields.map((field) => (
                  <ConfigField
                    key={field.key}
                    field={field}
                    value={config.values[field.key] ?? null}
                    draft={draft[field.key] ?? (field.type === 'boolean' ? String(config.values[field.key] ?? false) : String(config.values[field.key] ?? ''))}
                    onChange={onFieldChange}
                  />
                ))}
              </div>
            </div>
          ))}
      </section>
    </main>
  );
}
