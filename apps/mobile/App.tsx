import { aggregateDevices, agentFromBeacon, standaloneLimitedScan } from './src/discovery';

/**
 * Placeholder root component logic (wire to React Native / Expo UI next).
 * Demonstrates discovery + aggregation contracts used by the mobile app.
 */
export async function bootstrapMobileShell(): Promise<{
  agents: ReturnType<typeof agentFromBeacon>[];
  devices: Awaited<ReturnType<typeof standaloneLimitedScan>>;
}> {
  const agents = [
    agentFromBeacon(
      {
        agentId: '00000000-0000-4000-8000-000000000001',
        hostname: 'netscanner-box',
        httpPort: 4000,
        role: 'leader',
      },
      '192.168.51.10',
    ),
  ];
  const devices = await standaloneLimitedScan();
  return { agents, devices: aggregateDevices(devices) };
}
