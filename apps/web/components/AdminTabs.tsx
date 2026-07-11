'use client';

import { useCallback, useEffect, useState } from 'react';

export type AdminTabId = 'overview' | 'network' | 'speed' | 'integrations' | 'discovery' | 'cluster' | 'settings';

const TABS: { id: AdminTabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'network', label: 'Network' },
  { id: 'speed', label: 'Speed' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'cluster', label: 'Cluster' },
  { id: 'settings', label: 'Settings' },
];

function tabFromHash(): AdminTabId {
  if (typeof window === 'undefined') return 'overview';
  const h = window.location.hash.replace('#', '') as AdminTabId;
  return TABS.some((t) => t.id === h) ? h : 'overview';
}

export function AdminTabs({
  active,
  onChange,
}: {
  active: AdminTabId;
  onChange: (tab: AdminTabId) => void;
}) {
  return (
    <nav className="flex flex-wrap gap-1 border-b border-edge pb-1" aria-label="Admin sections">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`rounded-t-lg px-3 py-2 text-xs font-medium transition ${
            active === tab.id
              ? 'border border-b-0 border-edge bg-panel text-slate-100'
              : 'text-muted hover:bg-panelup hover:text-slate-200'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
}

export function useAdminTab(defaultTab: AdminTabId = 'overview') {
  const [tab, setTab] = useState<AdminTabId>(defaultTab);

  useEffect(() => {
    setTab(tabFromHash());
    const onHash = () => setTab(tabFromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const setActiveTab = useCallback((next: AdminTabId) => {
    setTab(next);
    if (typeof window !== 'undefined') {
      window.history.replaceState(null, '', `#${next}`);
    }
  }, []);

  return [tab, setActiveTab] as const;
}
