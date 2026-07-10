'use client';

import { useEffect } from 'react';
import { useBackgroundDataStore } from '../lib/background-data-store';
import { useStore } from '../lib/store';
import { useTopologyStore } from '../lib/topology-store';

/** Connect Socket.IO, load devices, and keep slow panels updating in the background. */
export function StoreBootstrap() {
  const connect = useStore((s) => s.connect);
  const bootstrap = useStore((s) => s.bootstrap);
  const startBackground = useBackgroundDataStore((s) => s.start);
  const startTopology = useTopologyStore((s) => s.startBackgroundPolling);

  useEffect(() => {
    connect();
    bootstrap().catch(() => undefined);
    startBackground();
    startTopology();
  }, [connect, bootstrap, startBackground, startTopology]);

  return null;
}
