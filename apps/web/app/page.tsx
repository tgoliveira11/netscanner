'use client';

import { useEffect } from 'react';
import { useStore } from '../lib/store';
import { Header } from '../components/Header';
import { ScanControls } from '../components/ScanControls';
import { StatsBar } from '../components/StatsBar';
import { DeviceTable } from '../components/DeviceTable';
import { DeviceDrawer } from '../components/DeviceDrawer';
import { TopologyView } from '../components/TopologyView';

export default function DashboardPage() {
  const bootstrap = useStore((s) => s.bootstrap);
  const connect = useStore((s) => s.connect);

  useEffect(() => {
    connect();
    bootstrap().catch(() => undefined);
  }, [connect, bootstrap]);

  return (
    <main className="mx-auto w-full max-w-[1920px] space-y-4 p-4 md:p-5">
      <Header />
      <ScanControls />
      <StatsBar />
      <DeviceTable />
      <div className="min-h-[680px]">
        <TopologyView />
      </div>
      <DeviceDrawer />
      <footer className="pt-2 text-center text-xs text-muted">
        Connection type (wired/WiFi) is reported as “unknown” unless a router integration provides it — it
        cannot be reliably detected from a remote host.
      </footer>
    </main>
  );
}
