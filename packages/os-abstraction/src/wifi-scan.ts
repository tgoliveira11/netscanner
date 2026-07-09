import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { WifiAp } from '@netscanner/contracts';

const execFileAsync = promisify(execFile);

const airport =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

/** Parse macOS `airport -s` output into AP list with channel collision hints. */
export async function scanWifiAps(): Promise<{
  currentSsid: string | null;
  aps: WifiAp[];
  channelCollisions: { channel: number; count: number }[];
}> {
  let currentSsid: string | null = null;
  try {
    const { stdout } = await execFileAsync('networksetup', ['-getairportnetwork', 'en0'], { timeout: 5000 });
    const m = stdout.match(/:\s*(.+)$/);
    if (m?.[1]?.trim()) currentSsid = m[1].trim();
  } catch {
    /* ignore */
  }

  const aps: WifiAp[] = [];
  try {
    const { stdout } = await execFileAsync(airport, ['-s'], { timeout: 10_000 });
    for (const line of stdout.split('\n').slice(1)) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 7) continue;
      const ssid = parts[0]!;
      const rssi = Number(parts.at(-2));
      const channelRaw = parts[parts.length - 3];
      const channel = channelRaw ? Number(channelRaw) : undefined;
      aps.push({
        ssid,
        bssid: parts[1],
        rssi: Number.isFinite(rssi) ? rssi : undefined,
        channel: Number.isFinite(channel) ? channel : undefined,
        security: parts.slice(6, -2).join(' ') || undefined,
      });
    }
  } catch {
    /* ignore */
  }

  const byChannel = new Map<number, number>();
  for (const ap of aps) {
    if (ap.channel == null) continue;
    byChannel.set(ap.channel, (byChannel.get(ap.channel) ?? 0) + 1);
  }
  const channelCollisions = [...byChannel.entries()]
    .filter(([, count]) => count > 1)
    .map(([channel, count]) => ({ channel, count }))
    .sort((a, b) => b.count - a.count);

  return { currentSsid, aps, channelCollisions };
}
