'use client';

import { useEffect } from 'react';
import { useStore } from '../lib/store';
import { Header } from '../components/Header';
import { ScanControls } from '../components/ScanControls';
import { StatsBar } from '../components/StatsBar';
import { DeviceTable } from '../components/DeviceTable';
import { DeviceDrawer } from '../components/DeviceDrawer';
import { AlertsPanel } from '../components/AlertsPanel';
import { TopologyView } from '../components/TopologyView';

export default function DashboardPage() {
  const bootstrap = useStore((s) => s.bootstrap);
  const connect = useStore((s) => s.connect);

  useEffect(() => {
    connect();
    bootstrap().catch(() => undefined);
  }, [connect, bootstrap]);

  return (
    <main className="mx-auto max-w-7xl space-y-4 p-5">
      <Header />
      <ScanControls />
      <StatsBar />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <DeviceTable />
        </div>
        <div className="space-y-4">
          <AlertsPanel />
        </div>
      </div>
      <TopologyView />
      <DeviceDrawer />
      <footer className="pt-4 text-center text-xs text-muted">
        Connection type (wired/WiFi) is reported as “unknown” unless a router integration provides it — it
        cannot be reliably detected from a remote host.
      </footer>
    </main>
  );
}
