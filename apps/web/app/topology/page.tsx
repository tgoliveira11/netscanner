'use client';

import { Header } from '../../components/Header';
import { TopologyView } from '../../components/TopologyView';
import { DeviceDrawer } from '../../components/DeviceDrawer';

/** Topology page — inventory/socket bootstrap lives in StoreBootstrap. */
export default function TopologyPage() {
  return (
    <main className="mx-auto w-full max-w-[1920px] space-y-4 p-4 md:p-5">
      <Header />
      <div className="min-h-[calc(100vh-8rem)]">
        <TopologyView fullPage />
      </div>
      <DeviceDrawer />
    </main>
  );
}
