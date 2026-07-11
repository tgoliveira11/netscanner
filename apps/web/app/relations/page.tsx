'use client';

import { Header } from '../../components/Header';
import { RelationsPanel } from '../../components/RelationsPanel';
import { DeviceDrawer } from '../../components/DeviceDrawer';

/** Relations — inventory/socket bootstrap lives in StoreBootstrap. */
export default function RelationsPage() {
  return (
    <main className="mx-auto w-full max-w-[1920px] space-y-4 p-4 md:p-5">
      <Header />
      <RelationsPanel fullPage />
      <DeviceDrawer />
    </main>
  );
}
