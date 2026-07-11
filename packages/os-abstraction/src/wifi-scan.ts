import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import type { WifiAp } from '@netscanner/contracts';

const execFileAsync = promisify(execFile);

const airport =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

const nativeDir = join(dirname(fileURLToPath(import.meta.url)), '../native/macos-wifiscan');
const coreWlanBin = join(nativeDir, 'wifiscan');
const coreWlanSrc = join(nativeDir, 'main.swift');

async function isExecutable(path: string): Promise<boolean> {
  try {
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function isReadable(path: string): Promise<boolean> {
  try {
    await access(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function mostlyRedacted(aps: WifiAp[]): boolean {
  if (!aps.length) return false;
  const hidden = aps.filter((a) => a.ssid.startsWith('(SSID hidden')).length;
  return hidden / aps.length >= 0.8;
}

function parseCoreWlanJson(stdout: string): {
  aps: WifiAp[];
  currentSsid: string | null;
  currentBssid?: string;
  currentChannel?: number;
  currentBand?: WifiAp['band'];
} {
  const parsed = JSON.parse(stdout) as
    | Array<{
        ssid?: string;
        bssid?: string | null;
        channel?: number | null;
        rssi?: number | null;
        security?: string | null;
        band?: string | null;
        channelWidthMhz?: number | null;
        isConnected?: boolean | null;
      }>
    | {
        currentSsid?: string | null;
        currentBssid?: string | null;
        currentChannel?: number | null;
        currentBand?: string | null;
        aps?: Array<{
          ssid?: string;
          bssid?: string | null;
          channel?: number | null;
          rssi?: number | null;
          security?: string | null;
          band?: string | null;
          channelWidthMhz?: number | null;
          isConnected?: boolean | null;
        }>;
      };

  const wrapper = Array.isArray(parsed) ? null : parsed;
  const rows = Array.isArray(parsed) ? parsed : (parsed.aps ?? []);
  const currentSsid = wrapper?.currentSsid?.trim() || null;
  const currentBssid = wrapper?.currentBssid?.trim() || undefined;
  const currentChannel =
    typeof wrapper?.currentChannel === 'number' && Number.isFinite(wrapper.currentChannel)
      ? wrapper.currentChannel
      : undefined;
  const currentBand = parseBand(wrapper?.currentBand);

  const aps = rows
    .filter((row) => row.ssid)
    .map((row) => ({
      ssid: row.ssid!,
      bssid: row.bssid?.trim() || undefined,
      channel: typeof row.channel === 'number' && Number.isFinite(row.channel) ? row.channel : undefined,
      rssi: typeof row.rssi === 'number' && Number.isFinite(row.rssi) ? row.rssi : undefined,
      security: row.security?.trim() || undefined,
      band: parseBand(row.band),
      channelWidthMhz:
        typeof row.channelWidthMhz === 'number' && Number.isFinite(row.channelWidthMhz)
          ? row.channelWidthMhz
          : undefined,
      source: 'local' as const,
    }));

  return { aps, currentSsid: currentSsid || null, currentBssid, currentChannel, currentBand };
}

function parseBand(raw: string | null | undefined): WifiAp['band'] {
  if (!raw) return undefined;
  if (raw === '2.4' || raw === '5' || raw === '6') return raw;
  return undefined;
}

async function macosConsoleUser(): Promise<{ name: string; uid: number } | null> {
  try {
    const { stdout } = await execFileAsync('stat', ['-f', '%Su', '/dev/console'], { timeout: 3_000 });
    const name = stdout.trim();
    if (!name || name === 'root' || name === '_mbsetupuser') return null;
    const idOut = await execFileAsync('id', ['-u', name], { timeout: 3_000 });
    const uid = Number(idOut.stdout.trim());
    if (!Number.isFinite(uid)) return null;
    return { name, uid };
  } catch {
    return null;
  }
}

function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Active scan via CoreWLAN (real SSID names on macOS 14.4+). */
async function scanViaCoreWlan(): Promise<{
  aps: WifiAp[];
  currentSsid: string | null;
  currentBssid?: string;
  currentChannel?: number;
  currentBand?: WifiAp['band'];
}> {
  if (!(await isReadable(coreWlanSrc))) return { aps: [], currentSsid: null };

  type Attempt = { cmd: string; args: string[]; cwd?: string; env?: NodeJS.ProcessEnv };
  const attempts: Attempt[] = [];

  // LaunchDaemon runs as root — CoreWLAN needs the console user's GUI/Location context.
  const consoleUser = typeof process.getuid === 'function' && process.getuid() === 0
    ? await macosConsoleUser()
    : null;
  if (consoleUser) {
    const swiftCmd = `/usr/bin/swift ${shellSingleQuote(coreWlanSrc)}`;
    attempts.push({
      cmd: '/bin/launchctl',
      args: ['asuser', String(consoleUser.uid), '/usr/bin/su', consoleUser.name, '-c', swiftCmd],
      cwd: nativeDir,
    });
    if (await isExecutable(coreWlanBin)) {
      attempts.push({
        cmd: '/bin/launchctl',
        args: [
          'asuser',
          String(consoleUser.uid),
          '/usr/bin/su',
          consoleUser.name,
          '-c',
          shellSingleQuote(coreWlanBin),
        ],
      });
    }
  }

  // Prefer `swift main.swift` — ad-hoc compiled binaries lack Location Services access on macOS 14.4+.
  attempts.push({ cmd: 'swift', args: [coreWlanSrc], cwd: nativeDir });
  if (await isExecutable(coreWlanBin)) {
    attempts.push({ cmd: coreWlanBin, args: [] });
  }

  let fallback: {
    aps: WifiAp[];
    currentSsid: string | null;
    currentBssid?: string;
    currentChannel?: number;
    currentBand?: WifiAp['band'];
  } = {
    aps: [],
    currentSsid: null,
  };
  for (const attempt of attempts) {
    try {
      const { stdout } = await execFileAsync(attempt.cmd, attempt.args, {
        timeout: attempt.args.includes('swift') || attempt.cmd === 'swift' ? 90_000 : 45_000,
        maxBuffer: 4 * 1024 * 1024,
        cwd: attempt.cwd,
        env: attempt.env,
      });
      const result = parseCoreWlanJson(stdout);
      if (!result.aps.length) continue;
      if (!mostlyRedacted(result.aps)) return result;
      if (!fallback.aps.length || result.aps.length > fallback.aps.length) fallback = result;
    } catch {
      /* try next */
    }
  }
  return fallback;
}

function inferCurrentSsidFromScan(
  aps: WifiAp[],
  currentChannel: number | undefined,
  currentBand: WifiAp['band'] | undefined,
  currentBssid: string | undefined,
): string | null {
  if (currentBssid) {
    const byBssid = aps.find((a) => a.bssid?.toLowerCase() === currentBssid.toLowerCase());
    if (byBssid?.ssid && !byBssid.ssid.startsWith('(')) return byBssid.ssid;
  }
  if (currentChannel == null) return null;
  const matches = aps.filter(
    (a) =>
      a.source === 'local' &&
      a.channel === currentChannel &&
      (!currentBand || a.band === currentBand || a.band == null) &&
      !a.ssid.startsWith('('),
  );
  if (matches.length === 0) return null;
  if (matches.length === 1) return matches[0]!.ssid;
  return [...matches].sort((a, b) => (b.rssi ?? -999) - (a.rssi ?? -999))[0]?.ssid ?? null;
}

async function readCurrentNetworkFromProfiler(): Promise<{ ssid: string | null; channel?: number }> {
  try {
    const { stdout } = await execFileAsync('system_profiler', ['SPAirPortDataType', '-json'], {
      timeout: 15_000,
    });
    const doc = JSON.parse(stdout) as {
      SPAirPortDataType?: Array<{
        spairport_airport_interfaces?: Array<{
          spairport_current_network_information?: Record<string, string>;
        }>;
      }>;
    };
    const current = doc.SPAirPortDataType?.[0]?.spairport_airport_interfaces?.[0]
      ?.spairport_current_network_information;
    const name = current?._name?.trim();
    return {
      ssid: name && !name.startsWith('<') ? name : null,
      channel: parseChannel(current?.spairport_network_channel),
    };
  } catch {
    return { ssid: null };
  }
}

function parseChannel(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const m = raw.match(/(\d+)/);
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : undefined;
}

function parseRssi(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const m = raw.match(/(-?\d+)/);
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : undefined;
}

function securityLabel(mode: string | undefined): string | undefined {
  if (!mode) return undefined;
  return mode.replace(/^spairport_security_mode_/i, '').replace(/_/g, ' ');
}

/** macOS 12+ — `airport` CLI removed; use system_profiler JSON instead. */
async function scanViaSystemProfiler(): Promise<{ currentSsid: string | null; aps: WifiAp[] }> {
  let currentSsid: string | null = null;
  const aps: WifiAp[] = [];
  try {
    const { stdout } = await execFileAsync('system_profiler', ['SPAirPortDataType', '-json'], {
      timeout: 20_000,
    });
    const doc = JSON.parse(stdout) as {
      SPAirPortDataType?: Array<{
        spairport_airport_interfaces?: Array<{
          spairport_current_network_information?: Record<string, string>;
          spairport_airport_other_local_wireless_networks?: Array<Record<string, string>>;
        }>;
      }>;
    };
    const iface = doc.SPAirPortDataType?.[0]?.spairport_airport_interfaces?.[0];
    if (!iface) return { currentSsid, aps };

    const current = iface.spairport_current_network_information;
    if (current?._name) {
      currentSsid = current._name;
      aps.push({
        ssid: current._name,
        channel: parseChannel(current.spairport_network_channel),
        rssi: parseRssi(current.spairport_signal_noise),
        security: securityLabel(current.spairport_security_mode),
        source: 'local',
      });
    }

    const hiddenByChannel = new Set<string>();
    for (const net of iface.spairport_airport_other_local_wireless_networks ?? []) {
      const rawName = net._name;
      if (!rawName) continue;
      const channel = parseChannel(net.spairport_network_channel);
      const security = securityLabel(net.spairport_security_mode);
      // macOS 14.4+ redacts neighbor SSIDs unless Location Services grants the host app access.
      let ssid = rawName;
      if (rawName === currentSsid) {
        const key = `${channel ?? '?'}-${security ?? '?'}`;
        if (hiddenByChannel.has(key)) continue;
        hiddenByChannel.add(key);
        ssid = channel != null ? `(SSID hidden · ch ${channel})` : '(SSID hidden by macOS)';
      }
      aps.push({ ssid, channel, security, source: 'local' });
    }
  } catch {
    /* ignore */
  }
  return { currentSsid, aps };
}

/** Parse legacy macOS `airport -s` output when the binary still exists. */
async function scanViaAirport(): Promise<WifiAp[]> {
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
        source: 'local',
      });
    }
  } catch {
    /* ignore */
  }
  return aps;
}

/** Parse macOS `airport -s` output into AP list with channel collision hints. */
export async function scanWifiAps(): Promise<{
  currentSsid: string | null;
  currentChannel?: number;
  currentBand?: WifiAp['band'];
  connectedInferred?: boolean;
  aps: WifiAp[];
  channelCollisions: { channel: number; count: number }[];
  note?: string;
}> {
  let currentSsid: string | null = null;
  let currentChannel: number | undefined;
  let currentBand: WifiAp['band'] | undefined;
  let connectedInferred = false;
  let aps: WifiAp[] = [];
  let note: string | undefined;

  try {
    const { stdout } = await execFileAsync('networksetup', ['-getairportnetwork', 'en0'], { timeout: 5000 });
    const m = stdout.match(/:\s*(.+)$/);
    if (m?.[1]?.trim() && !/not associated|error|you are not/i.test(m[1])) {
      currentSsid = m[1].trim();
    }
  } catch {
    /* networksetup often fails for LaunchDaemon / root — CoreWLAN fallback below */
  }

  if (process.platform === 'darwin') {
    const core = await scanViaCoreWlan();
    aps = core.aps;
    if (core.currentSsid) currentSsid = core.currentSsid;
    currentChannel = core.currentChannel;
    currentBand = core.currentBand;
    const coreBssid = core.currentBssid;
    if (!aps.length) {
      const legacy = await scanViaAirport();
      if (legacy.length) {
        aps = legacy;
      } else {
        const modern = await scanViaSystemProfiler();
        currentSsid = modern.currentSsid ?? currentSsid;
        aps = modern.aps;
        if (!aps.length) {
          note =
            'No Wi‑Fi networks from this Mac. If the agent host uses Ethernet only, configure ROUTER_SCRAPE_TARGETS for AP SSIDs from your routers.';
        } else if (aps.some((a) => a.ssid.startsWith('(SSID hidden'))) {
          note =
            'macOS hides neighbor SSIDs without Location Services. Enable Location for Terminal or /usr/bin/swift (Settings → Privacy & Security → Location Services).';
        }
      }
    } else if (mostlyRedacted(aps)) {
      note =
        'Wi‑Fi scan returned mostly hidden SSIDs. Enable Location for /usr/bin/swift in System Settings → Privacy & Security → Location Services.';
    }

    if (!currentSsid) {
      const profiler = await readCurrentNetworkFromProfiler();
      if (profiler.ssid) {
        currentSsid = profiler.ssid;
      } else if (profiler.channel != null && currentChannel == null) {
        currentChannel = profiler.channel;
      }
    }

    if (!currentSsid) {
      const inferred = inferCurrentSsidFromScan(aps, currentChannel, currentBand, coreBssid);
      if (inferred) {
        currentSsid = inferred;
        connectedInferred = true;
      }
    }
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

  return {
    currentSsid,
    currentChannel,
    currentBand,
    connectedInferred: connectedInferred || undefined,
    aps,
    channelCollisions,
    note,
  };
}
