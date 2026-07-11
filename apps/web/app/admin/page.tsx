'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { AppNav } from '../../components/AppNav';
import { AdminTabs, useAdminTab } from '../../components/AdminTabs';
import { AdminTabPanel } from '../../components/AdminTabPanel';
import { AdminWirelessSection } from '../../components/AdminWirelessSection';
import { CompalPanel } from '../../components/CompalPanel';
import { CpeAccessPanel } from '../../components/CpeAccessPanel';
import { LoadingBlock } from '../../components/LoadingSpinner';
import { PfSenseGatewaysPanel } from '../../components/PfSenseGatewaysPanel';
import { NetworkControlPanel } from '../../components/NetworkControlPanel';
import { SpeedTestPanel } from '../../components/SpeedTestPanel';
import { ClusterPeersPanel } from '../../components/ClusterPeersPanel';
import { api, type AdminConfigResponse, type AdminObservability, type AdminLogLine, type ConfigFieldSchema } from '../../lib/api';

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

function CollapsibleSection({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  return (
    <details className="group" open={defaultOpen}>
      <summary className="mb-2 cursor-pointer list-none text-sm font-semibold text-slate-200 marker:content-none [&::-webkit-details-marker]:hidden">
        <span className="inline-flex items-center gap-2">
          <span className="text-muted transition group-open:rotate-90">▸</span>
          {title}
        </span>
      </summary>
      {children}
    </details>
  );
}

function FieldHelp({ text }: { text: string }) {
  return (
    <span
      className="pointer-events-none invisible absolute bottom-full left-0 z-50 mb-2 w-72 rounded-lg border border-edge bg-panelup p-2.5 text-xs leading-relaxed text-slate-300 opacity-0 shadow-xl transition group-hover:visible group-hover:opacity-100"
      role="tooltip"
    >
      {text}
    </span>
  );
}

function ConfigFieldLabel({ field }: { field: ConfigFieldSchema }) {
  const help = field.help ?? field.description;
  return (
    <span className="group relative inline-flex cursor-help items-center gap-1">
      <span className="block text-sm font-medium text-slate-200">{field.label}</span>
      <span className="text-[10px] text-muted opacity-60">?</span>
      <FieldHelp text={help} />
      {field.restartRequired && <span className="text-[10px] font-normal text-warn">· restart</span>}
    </span>
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
      <label htmlFor={id} className="group relative flex cursor-pointer items-start gap-3 rounded-lg border border-edge bg-panelup p-3">
        <input
          id={id}
          type="checkbox"
          checked={Boolean(draft !== '' ? draft === 'true' : value)}
          onChange={(e) => onChange(field.key, e.target.checked)}
          className="mt-1"
        />
        <span className="min-w-0 flex-1">
          <ConfigFieldLabel field={field} />
        </span>
      </label>
    );
  }

  if (field.type === 'multiline') {
    return (
      <div className="group relative rounded-lg border border-edge bg-panelup p-3 md:col-span-2">
        <label htmlFor={id} className="mb-2 block">
          <ConfigFieldLabel field={field} />
        </label>
        <textarea
          id={id}
          rows={5}
          value={draft}
          onChange={(e) => onChange(field.key, e.target.value)}
          spellCheck={false}
          placeholder={'http://192.168.40.2|openwrt|root|password\nhttp://192.168.51.101|compal|CLARO_21A469|password'}
          className="w-full rounded-lg border border-edge bg-base px-3 py-2 font-mono text-xs leading-relaxed outline-none focus:border-accent"
        />
      </div>
    );
  }

  return (
    <div className="group relative rounded-lg border border-edge bg-panelup p-3">
      <label htmlFor={id} className="mb-2 block">
        <ConfigFieldLabel field={field} />
      </label>
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
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useAdminTab('overview');
  const [config, setConfig] = useState<AdminConfigResponse | null>(null);
  const [logs, setLogs] = useState<AdminLogLine[]>([]);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const restartingRef = useRef(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [o, c, l] = await Promise.all([
        api.adminObservability(),
        api.adminConfig(),
        api.adminLogs(250),
      ]);
      setObs(o);
      setConfig(c);
      setLogs([...l.memory, ...l.file].slice(-300).reverse());
      setError(null);
    } catch (e) {
      if (restartingRef.current) return;
      const msg = e instanceof Error ? e.message : 'Failed to load admin data';
      if (msg === 'Failed to fetch') {
        setError('Agent unavailable — check it is running at http://127.0.0.1:4000');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }, []);

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

  const groupOrder = [
    'Network Control',
    'Network Sites',
    'Integrations',
    'Topology',
    'Discovery',
    'Scanning',
    'Background',
    'Gateway',
    'Persistence',
    'Agent',
  ];

  const sortedGroups = useMemo(() => {
    const entries = [...grouped.entries()];
    entries.sort(([a], [b]) => {
      const ai = groupOrder.indexOf(a);
      const bi = groupOrder.indexOf(b);
      return (ai >= 0 ? ai : 99) - (bi >= 0 ? bi : 99) || a.localeCompare(b);
    });
    return entries;
  }, [grouped]);

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
    setMessage('Restarting agent…');
    restartingRef.current = true;
    try {
      await api.agentRestart();
      setMessage('Agent restarted.');
      await refresh();
    } catch (e) {
      setMessage(null);
      const msg = e instanceof Error ? e.message : 'Restart failed';
      setError(msg === 'Failed to fetch' ? 'Could not reach the agent during restart.' : msg);
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
            <p className="text-[10px] text-muted">Full reference: <code className="text-slate-400">docs/admin.md</code> in the repository.</p>
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

      <AdminTabs active={tab} onChange={setTab} />

      <AdminTabPanel tab="overview" active={tab}>
          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-slate-200">Runtime status</h2>
            <LoadingBlock loading={loading && !obs} label="Loading status…">
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
            </LoadingBlock>
          </section>

          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-slate-200">Logs</h2>
            <LoadingBlock loading={loading && logs.length === 0} label="Loading logs…">
              <LogViewer lines={logs} />
            </LoadingBlock>
          </section>
      </AdminTabPanel>

      <AdminTabPanel tab="integrations" active={tab}>
        <CompalPanel />
        <CpeAccessPanel />
      </AdminTabPanel>

      <AdminTabPanel tab="network" active={tab}>
        <PfSenseGatewaysPanel />
        <AdminWirelessSection />
        <NetworkControlPanel />
      </AdminTabPanel>

      <AdminTabPanel tab="speed" active={tab}>
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-slate-200">Internet speed</h2>
          <SpeedTestPanel />
        </section>
      </AdminTabPanel>

      <AdminTabPanel tab="discovery" active={tab}>
        <LoadingBlock loading={loading && !obs} label="Loading discoveries…">
        <CollapsibleSection title="Recent discoveries" defaultOpen>
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
      </CollapsibleSection>
        </LoadingBlock>
      </AdminTabPanel>

      <AdminTabPanel tab="cluster" active={tab}>
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-slate-200">Multi-agent cluster</h2>
          <p className="text-xs text-muted">
            Peers discovered via UDP beacon. Only the control leader writes pfSense/Compal. See docs/multi-agent.md.
          </p>
          <ClusterPeersPanel />
        </section>
      </AdminTabPanel>

      <AdminTabPanel tab="settings" active={tab}>
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Configuration</h2>
          <button type="button" disabled={saving || !Object.keys(draft).length} onClick={() => void save()} className="btn btn-primary">
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </div>
        <LoadingBlock loading={loading && !config} label="Loading configuration…">
        {config &&
          sortedGroups.map(([group, fields]) => (
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
        </LoadingBlock>
      </section>
      </AdminTabPanel>
    </main>
  );
}
