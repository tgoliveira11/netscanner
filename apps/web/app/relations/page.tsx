'use client';

import { useEffect } from 'react';
import { useStore } from '../../lib/store';
import { Header } from '../../components/Header';
import { RelationsPanel } from '../../components/RelationsPanel';
import { DeviceDrawer } from '../../components/DeviceDrawer';

export default function RelationsPage() {
  const bootstrap = useStore((s) => s.bootstrap);
  const connect = useStore((s) => s.connect);

  useEffect(() => {
    connect();
    bootstrap().catch(() => undefined);
  }, [connect, bootstrap]);

  return (
    <main className="mx-auto w-full max-w-[1920px] space-y-4 p-4 md:p-5">
      <Header />
      <RelationsPanel fullPage />
      <DeviceDrawer />
    </main>
  );
}
