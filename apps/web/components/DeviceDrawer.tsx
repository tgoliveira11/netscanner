'use client';

import { useEffect, useState } from 'react';
import type { CveFinding, DnsProfile, Traffic } from '@netscanner/contracts';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import { deviceMeta } from '../lib/device-ui';
import { DevicePolicy } from './DevicePolicy';

const fmtBytes = (n: number) =>
  n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n > 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${n} B`;

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
      <div className="text-sm text-slate-100">{value ?? '—'}</div>
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
    <details className="group mt-5" open={defaultOpen}>
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

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard API unavailable — silently ignore
    }
  };

  return (
    <button
      onClick={handleCopy}
      title={copied ? 'Copied!' : 'Copy MAC address'}
      className="ml-1 inline-flex items-center rounded p-0.5 text-muted transition-colors hover:bg-panelup hover:text-slate-200"
    >
      {copied ? (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" className="h-3.5 w-3.5 text-green-400">
          <path fillRule="evenodd" d="M12.416 3.376a.75.75 0 0 1 .208 1.04l-5 7.5a.75.75 0 0 1-1.154.114l-3-3a.75.75 0 0 1 1.06-1.06l2.353 2.353 4.493-6.74a.75.75 0 0 1 1.04-.207Z" clipRule="evenodd" />
        </svg>
      ) : (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" className="h-3.5 w-3.5">
          <path d="M5.5 3.5A1.5 1.5 0 0 1 7 2h2a1.5 1.5 0 0 1 1.5 1.5v.5h1A1.5 1.5 0 0 1 13 5.5v8A1.5 1.5 0 0 1 11.5 15h-7A1.5 1.5 0 0 1 3 13.5v-8A1.5 1.5 0 0 1 4.5 4h1v-.5ZM7 3a.5.5 0 0 0-.5.5V4h3v-.5A.5.5 0 0 0 9 3H7Zm4.5 2.5h-7a.5.5 0 0 0-.5.5v8a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 .5-.5v-8a.5.5 0 0 0-.5-.5Z" />
        </svg>
      )}
    </button>
  );
}

function isRouterPanel(device: { deviceType: string; services: { port: number }[] }): boolean {
  if (['router', 'switch', 'access-point', 'firewall'].includes(device.deviceType)) return true;
  return device.services.some((s) => s.port === 80 || s.port === 443);
}

/** Slide-over panel with the full per-device detail: attributes, ports, flags, notes. */
export function DeviceDrawer() {
  const id = useStore((s) => s.selectedId);
  const device = useStore((s) => (id ? s.devices[id] : null));
  const select = useStore((s) => s.select);
  const applyDevice = useStore((s) => s.applyDevice);
  const [label, setLabel] = useState('');
  const [notes, setNotes] = useState('');
  const [routerUser, setRouterUser] = useState('');
  const [routerPassword, setRouterPassword] = useState('');

  useEffect(() => {
    setLabel(device?.label ?? '');
    setNotes(device?.notes ?? '');
    setRouterUser(device?.routerScrapeUser ?? '');
    setRouterPassword('');
  }, [device?.id, device?.label, device?.notes, device?.routerScrapeUser, device?.routerScrapePasswordSet]);

  if (!id || !device) return null;
  const meta = deviceMeta(device.deviceType);
  const showRouterAccess = isRouterPanel(device);

  const save = async () => {
    const body: {
      label: string | null;
      notes: string | null;
      routerScrapeUser?: string | null;
      routerScrapePassword?: string | null;
    } = {
      label: label || null,
      notes: notes || null,
    };
    if (showRouterAccess) {
      body.routerScrapeUser = routerUser.trim() || null;
      if (routerPassword.trim()) body.routerScrapePassword = routerPassword;
    }
    const { device: updated } = await api.updateDevice(device.id, body);
    applyDevice(updated);
    setRouterPassword('');
  };

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={() => select(null)}>
      <aside
        className="h-full w-full max-w-md overflow-y-auto border-l border-edge bg-panel p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <span className="text-3xl">{meta.icon}</span>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">
                {device.label ?? device.hostname ?? device.ip}
              </h2>
              <div className="text-xs text-muted">
                {meta.label} · {Math.round(device.classificationConfidence * 100)}% confidence
              </div>
            </div>
          </div>
          <button onClick={() => select(null)} className="btn btn-ghost">
            Close
          </button>
        </div>

        {(() => {
          const reasons = device.signals?.classification as string[] | undefined;
          const evidence = device.signals?.classificationEvidence as
            | { deviceType: string; posterior: number; reasons: string[] }[]
            | undefined;
          if ((!reasons?.length) && (!evidence?.length)) return null;
          return (
            <CollapsibleSection title="Classification evidence">
              {evidence && evidence.length > 0 && (
                <div className="mb-2 space-y-1">
                  {evidence.map((row) => (
                    <div
                      key={row.deviceType}
                      className="rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs"
                    >
                      <div className="flex justify-between text-slate-200">
                        <span>{row.deviceType}</span>
                        <span className="text-muted">{Math.round(row.posterior * 100)}% posterior</span>
                      </div>
                      {row.reasons.map((r) => (
                        <div key={r} className="mt-0.5 text-muted">
                          {r}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
              {reasons && reasons.length > 0 && (
                <ul className="list-inside list-disc space-y-0.5 text-xs text-muted">
                  {reasons.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              )}
            </CollapsibleSection>
          );
        })()}

        <div className="grid grid-cols-2 gap-4">
          <Field label="IP" value={<span className="font-mono">{device.ip}</span>} />
          <Field
            label="MAC"
            value={
              device.mac ? (
                <span className="flex items-center">
                  <span className="font-mono">{device.mac}</span>
                  <CopyButton text={device.mac} />
                </span>
              ) : (
                '—'
              )
            }
          />
          <Field label="Vendor" value={device.vendor} />
          <Field label="Brand" value={device.brand} />
          <Field label="Model" value={device.model} />
          <Field label="Hostname" value={device.hostname} />
          <Field
            label="OS"
            value={
              device.os
                ? `${device.os.name ?? device.os.family ?? '?'}${device.os.version ? ` ${device.os.version}` : ''} (${device.os.accuracy ?? 0}%${device.os.source === 'inferred' ? ', inferred' : ''})`
                : '—'
            }
          />
          <Field
            label="Fingerbank"
            value={
              typeof device.signals?.fingerbankDevice === 'string'
                ? `${device.signals.fingerbankDevice}${
                    device.signals.fingerbankVersion ? ` ${device.signals.fingerbankVersion}` : ''
                  }`
                : '—'
            }
          />
          <Field
            label="Connection"
            value={
              <span
                title={
                  typeof device.signals?.connectionBasis === 'string'
                    ? device.signals.connectionBasis
                    : 'Inferred; definitive wired/WiFi needs switch/AP data'
                }
              >
                {device.connectionType === 'wifi'
                  ? '📶 WiFi'
                  : device.connectionType === 'wired'
                    ? '🔌 Wired'
                    : '❔ Unknown'}
              </span>
            }
          />
          <Field label="Latency" value={device.latencyMs != null ? `${device.latencyMs} ms` : '—'} />
          <Field label="Status" value={device.isOnline ? 'online' : 'offline'} />
          <Field label="First seen" value={new Date(device.firstSeen).toLocaleString()} />
          <Field label="Last seen" value={new Date(device.lastSeen).toLocaleString()} />
        </div>

        {(() => {
          const ips = device.signals?.infrastructureIps as string[] | undefined;
          const aliases = device.signals?.infrastructureAliases as
            | { ip: string; mac: string | null; interfaceLabel: string | null }[]
            | undefined;
          if (!ips?.length || ips.length <= 1) return null;
          const labelByIp = new Map(
            (aliases ?? []).map((a) => [a.ip, a.interfaceLabel] as const),
          );
          return (
            <section className="mt-5">
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Interface IPs</h3>
              <p className="mb-2 text-xs text-muted">
                Multi-homed appliance — one logical device, several VLAN/WAN interfaces.
              </p>
              <div className="space-y-1">
                {ips.map((ip) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs"
                  >
                    <span className="font-mono">{ip}</span>
                    <span className="text-muted">
                      {ip === device.ip
                        ? 'primary'
                        : labelByIp.get(ip) ?? 'interface'}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          );
        })()}

        <section className="mt-5">
          <h3 className="mb-2 text-sm font-semibold text-slate-200">Open services ({device.services.length})</h3>
          <div className="space-y-1">
            {device.services.map((s) => (
              <div
                key={`${s.protocol}-${s.port}`}
                className="flex items-center justify-between rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs"
              >
                <span className="font-mono">
                  {s.port}/{s.protocol}
                </span>
                <span className="text-slate-300">
                  {[s.serviceName, s.product, s.version].filter(Boolean).join(' ') || '—'}
                </span>
              </div>
            ))}
            {device.services.length === 0 && <div className="text-xs text-muted">No open ports detected.</div>}
          </div>
        </section>

        {device.securityFlags.length > 0 && (
          <section className="mt-5">
            <h3 className="mb-2 text-sm font-semibold text-bad">Security findings</h3>
            <div className="space-y-1">
              {device.securityFlags.map((f) => (
                <div key={f.code} className="rounded-lg border border-bad/40 bg-bad/10 px-3 py-1.5 text-xs text-slate-200">
                  <span className="badge mr-2 bg-bad/20 text-bad">{f.severity}</span>
                  {f.message}
                </div>
              ))}
            </div>
          </section>
        )}

        {(() => {
          const cves = (device.signals?.cveFindings as CveFinding[] | undefined) ?? [];
          const risk = typeof device.signals?.riskScore === 'number' ? device.signals.riskScore : null;
          if (cves.length === 0 && (risk == null || risk === 0)) return null;
          return (
            <section className="mt-5">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200">
                Vulnerabilities
                {risk != null && (
                  <span
                    className={`badge ${risk >= 50 ? 'bg-bad/20 text-bad' : risk >= 20 ? 'bg-warn/20 text-warn' : 'bg-good/20 text-good'}`}
                  >
                    risk {risk}
                  </span>
                )}
              </h3>
              <div className="space-y-1">
                {cves.map((c) => (
                  <a
                    key={c.cveId}
                    href={c.url}
                    target="_blank"
                    rel="noopener"
                    className="block rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs hover:border-accent"
                  >
                    <span className="badge mr-2 bg-bad/20 text-bad">{c.severity}</span>
                    <span className="font-mono">{c.cveId}</span>{' '}
                    {c.confidence === 'fuzzy' && <span className="text-muted">(potential)</span>}
                    <div className="mt-0.5 text-muted">{c.summary}</div>
                  </a>
                ))}
                {cves.length === 0 && <div className="text-xs text-muted">No known CVEs matched.</div>}
              </div>
            </section>
          );
        })()}

        {(() => {
          const dns = device.signals?.dnsProfile as DnsProfile | undefined;
          const recent = device.signals?.dnsRecentQueries;
          const queryList = Array.isArray(recent) ? recent.map(String) : [];
          const topDomains =
            dns?.topDomains?.length
              ? dns.topDomains
              : queryList.map((domain) => ({ domain, count: 1, vendor: undefined, category: undefined }));
          if (topDomains.length === 0) return null;
          return (
            <CollapsibleSection title="Network activity (DNS)">
              {dns?.categories && dns.categories.length > 0 && (
                <div className="mb-2 flex flex-wrap gap-1">
                  {dns.categories.map((c) => (
                    <span key={c} className="badge bg-panelup text-slate-300">
                      {c}
                    </span>
                  ))}
                </div>
              )}
              <div className="space-y-1">
                {topDomains.slice(0, 25).map((d) => (
                  <div
                    key={d.domain}
                    className="flex items-center justify-between rounded-lg border border-edge bg-panelup px-3 py-1 text-xs"
                  >
                    <span className="font-mono">{d.domain}</span>
                    <span className="text-muted">
                      {[d.vendor ?? d.category, d.count > 1 ? `${d.count}×` : null].filter(Boolean).join(' · ')}
                    </span>
                  </div>
                ))}
              </div>
              {dns?.externalEndpoints != null && (
                <div className="mt-1 text-[10px] text-muted">
                  {dns.externalEndpoints} external domains contacted
                </div>
              )}
              {!dns && queryList.length > 0 && (
                <div className="mt-1 text-[10px] text-muted">From passive DNS capture — profile pending enrichment.</div>
              )}
            </CollapsibleSection>
          );
        })()}

        {(() => {
          const t = device.signals?.traffic as Traffic | undefined;
          if (!t) return null;
          return (
            <section className="mt-5">
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Traffic</h3>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
                  <div className="text-muted">In</div>
                  {fmtBytes(t.bytesIn)}
                </div>
                <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
                  <div className="text-muted">Out</div>
                  {fmtBytes(t.bytesOut)}
                </div>
                <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
                  <div className="text-muted">Rate</div>
                  {(t.rateBps / 1000).toFixed(0)} kbps
                </div>
              </div>
            </section>
          );
        })()}

        <DevicePolicy device={device} />

        {showRouterAccess && (
          <section className="mt-5 space-y-2">
            <h3 className="text-sm font-semibold text-slate-200">Router panel (LuCI scrape)</h3>
            <p className="text-xs text-muted">
              Credentials for this device only — used for DHCP leases and WiFi/SSID probe.
            </p>
            <input
              value={routerUser}
              onChange={(e) => setRouterUser(e.target.value)}
              placeholder="Username (e.g. root)"
              autoComplete="username"
              className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <input
              type="password"
              value={routerPassword}
              onChange={(e) => setRouterPassword(e.target.value)}
              placeholder={device.routerScrapePasswordSet ? '•••••••• (leave blank to keep)' : 'Password'}
              autoComplete="current-password"
              className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
            />
          </section>
        )}

        <section className="mt-5 space-y-2">
          <h3 className="text-sm font-semibold text-slate-200">Label & notes</h3>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Friendly name"
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
          />
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Notes…"
            rows={3}
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
          />
          <button onClick={save} className="btn btn-primary">
            Save
          </button>
        </section>
      </aside>
    </div>
  );
}
