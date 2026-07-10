import type { WifiAp, WifiBand, WifiScanResponse } from '@netscanner/contracts';

export interface OwnNetworkInput {
  ssid: string;
  channel?: number;
  mode?: string;
  device?: string;
  ifname?: string;
  up?: boolean;
  routerHost: string;
  clients?: Array<{ mac: string; signal?: number | null }>;
}

export interface WifiAnalysisInput {
  currentSsid: string | null;
  aps: WifiAp[];
  ownNetworks?: OwnNetworkInput[];
}

const CHANNELS_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] as const;
const CHANNELS_5_COMMON = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165] as const;

/** Map IEEE channel number to band. */
export function inferWifiBand(channel: number | undefined | null): WifiBand {
  if (channel == null || !Number.isFinite(channel)) return 'unknown';
  if (channel >= 1 && channel <= 14) return '2.4';
  if (channel >= 36 && channel <= 196) return '5';
  if (channel >= 1 && channel <= 233) return '6'; // ambiguous with 2.4 — prefer 2.4 rule first
  return 'unknown';
}

/** Infer band from OpenWrt/Compal radio device name (e.g. radio0 = 2.4, radio1 = 5). */
export function inferBandFromRadio(device: string | undefined, channel?: number): WifiBand {
  if (device) {
    const d = device.toLowerCase();
    if (/5g|5ghz|radio1|wlan1|wifi1|ax5|ac5/.test(d)) return '5';
    if (/2g|2\.4|24g|radio0|wlan0|wifi0|ax2|ac2/.test(d)) return '2.4';
    if (/6g|6ghz|wifi2|ax6/.test(d)) return '6';
  }
  return inferWifiBand(channel);
}

function rssiWeight(rssi: number | undefined): number {
  if (rssi == null || !Number.isFinite(rssi)) return 0.35;
  // Stronger signals contribute more interference (-30 dBm >> -85 dBm)
  return Math.min(1, Math.max(0.05, (100 + rssi) / 70));
}

/** 2.4 GHz adjacent-channel overlap factor (20 MHz). */
export function overlapFactor24(ch1: number, ch2: number): number {
  const delta = Math.abs(ch1 - ch2);
  if (delta === 0) return 1;
  if (delta <= 2) return 0.7;
  if (delta <= 4) return 0.35;
  return 0;
}

/** 5 GHz — mostly co-channel at 20 MHz; partial for adjacent in same UNII group. */
export function overlapFactor5(ch1: number, ch2: number): number {
  if (ch1 === ch2) return 1;
  const delta = Math.abs(ch1 - ch2);
  if (delta <= 4) return 0.15;
  return 0;
}

function overlapFactor(band: WifiBand, ch1: number, ch2: number): number {
  if (band === '2.4') return overlapFactor24(ch1, ch2);
  if (band === '5') return overlapFactor5(ch1, ch2);
  if (band === '6') return ch1 === ch2 ? 1 : 0;
  return ch1 === ch2 ? 1 : 0;
}

function channelsForBand(band: WifiBand, seen: number[]): number[] {
  const base = band === '2.4' ? [...CHANNELS_24] : band === '5' ? [...CHANNELS_5_COMMON] : seen;
  const merged = new Set([...base, ...seen.filter((c) => inferWifiBand(c) === band)]);
  return [...merged].sort((a, b) => a - b);
}

function enrichAp(ap: WifiAp, ownSsids: Set<string>): WifiAp {
  const band = ap.band ?? inferWifiBand(ap.channel);
  const isOwn =
    ap.isOwnNetwork ??
    (ap.source === 'router' || Boolean(ap.ssid && ownSsids.has(ap.ssid.toLowerCase())));
  return { ...ap, band, isOwnNetwork: isOwn };
}

function scoreChannel(
  band: WifiBand,
  channel: number,
  aps: WifiAp[],
): {
  channel: number;
  band: WifiBand;
  apCount: number;
  coChannelCount: number;
  overlapScore: number;
  strongestRssi: number | null;
} {
  let overlapScore = 0;
  let coChannelCount = 0;
  let strongestRssi: number | null = null;
  let apCount = 0;

  for (const ap of aps) {
    const apBand = ap.band ?? inferWifiBand(ap.channel);
    if (apBand !== band || ap.channel == null) continue;
    apCount += 1;
    if (ap.channel === channel) coChannelCount += 1;
    const factor = overlapFactor(band, channel, ap.channel);
    if (factor <= 0) continue;
    overlapScore += factor * rssiWeight(ap.rssi);
    if (ap.rssi != null && (strongestRssi == null || ap.rssi > strongestRssi)) {
      strongestRssi = ap.rssi;
    }
  }

  return {
    channel,
    band,
    apCount,
    coChannelCount,
    overlapScore: Math.round(overlapScore * 100) / 100,
    strongestRssi,
  };
}

function pickBestChannels(scores: ReturnType<typeof scoreChannel>[], limit = 3): number[] {
  return [...scores]
    .sort((a, b) => a.overlapScore - b.overlapScore || a.coChannelCount - b.coChannelCount)
    .slice(0, limit)
    .map((s) => s.channel);
}

function pickWorstChannels(scores: ReturnType<typeof scoreChannel>[], limit = 3): number[] {
  return [...scores]
    .sort((a, b) => b.overlapScore - a.overlapScore || b.coChannelCount - a.coChannelCount)
    .slice(0, limit)
    .map((s) => s.channel);
}

function congestionLabel(score: number): number {
  // Normalize overlap score to 0-100 index (heuristic cap ~6 strong neighbors)
  return Math.min(100, Math.round((score / 6) * 100));
}

export function analyzeWifi(input: WifiAnalysisInput): NonNullable<WifiScanResponse['analysis']> {
  const ownSsids = new Set(
    (input.ownNetworks ?? []).map((n) => n.ssid.toLowerCase()).filter(Boolean),
  );
  if (input.currentSsid) ownSsids.add(input.currentSsid.toLowerCase());

  const aps = input.aps.map((ap) => enrichAp(ap, ownSsids));
  const recommendations: NonNullable<WifiScanResponse['analysis']>['recommendations'] = [];
  const issues: NonNullable<WifiScanResponse['analysis']>['issues'] = [];

  const bands = new Set<WifiBand>();
  for (const ap of aps) {
    const b = ap.band ?? inferWifiBand(ap.channel);
    if (b !== 'unknown') bands.add(b);
  }
  if (!bands.size) bands.add('2.4');

  const bandSummaries: NonNullable<WifiScanResponse['analysis']>['bandSummaries'] = [];
  let totalCongestion = 0;
  let bandCount = 0;

  for (const band of ['2.4', '5', '6'] as WifiBand[]) {
    if (!bands.has(band)) continue;
    const seen = aps.map((a) => a.channel).filter((c): c is number => c != null);
    const channelList = channelsForBand(band, seen);
    const channelScores = channelList.map((ch) => scoreChannel(band, ch, aps));
    const best = pickBestChannels(channelScores);
    const worst = pickWorstChannels(channelScores);
    const avgOverlap =
      channelScores.reduce((s, c) => s + c.overlapScore, 0) / Math.max(1, channelScores.length);
    totalCongestion += congestionLabel(avgOverlap);
    bandCount += 1;

    bandSummaries.push({
      band,
      channelScores,
      bestChannels: best,
      worstChannels: worst,
    });

    if (worst[0] != null && channelScores.find((c) => c.channel === worst[0])!.overlapScore >= 2) {
      issues.push({
        severity: band === '2.4' ? 'warn' : 'info',
        message: `${band} GHz: channel ${worst[0]} is among the most congested (${channelScores.find((c) => c.channel === worst[0])!.coChannelCount} AP(s) on the same channel).`,
      });
    }
  }

  const ownNetworks: NonNullable<WifiScanResponse['analysis']>['ownNetworks'] = [];

  for (const net of input.ownNetworks ?? []) {
    const band = inferBandFromRadio(net.device ?? net.ifname, net.channel);
    const channel = net.channel;
    const scores =
      bandSummaries.find((b) => b.band === band)?.channelScores ??
      (channel != null ? [scoreChannel(band, channel, aps)] : []);
    const currentScore = channel != null ? scores.find((s) => s.channel === channel) : undefined;
    const best = pickBestChannels(scores, 1)[0] ?? null;
    const clients = net.clients ?? [];
    const signals = clients.map((c) => c.signal).filter((s): s is number => s != null && Number.isFinite(s));
    const avgClientRssi = signals.length ? Math.round(signals.reduce((a, b) => a + b, 0) / signals.length) : null;
    const weakClientCount = signals.filter((s) => s < -72).length;

    ownNetworks.push({
      ssid: net.ssid,
      channel: channel ?? null,
      band,
      radioDevice: net.device ?? net.ifname,
      routerHost: net.routerHost,
      mode: net.mode,
      up: net.up,
      clientCount: clients.length,
      avgClientRssi,
      weakClientCount,
      congestionScore: currentScore ? congestionLabel(currentScore.overlapScore) : null,
      suggestedChannel: best,
    });

    if (channel != null && best != null && best !== channel) {
      const bestScore = scores.find((s) => s.channel === best);
      const cur = currentScore;
      if (bestScore && cur && bestScore.overlapScore + 0.5 < cur.overlapScore) {
        recommendations.push({
          severity: cur.overlapScore >= 3 ? 'warn' : 'info',
          category: 'channel',
          title: `Move ${net.ssid} from channel ${channel} → ${best}`,
          detail: `${band} GHz on ${net.routerHost}: channel ${channel} scores ${cur.overlapScore.toFixed(1)} vs ${bestScore.overlapScore.toFixed(1)} on channel ${best}. Less overlap with neighbors.`,
          ssid: net.ssid,
          currentChannel: channel,
          suggestedChannel: best,
        });
      }
    }

    if (net.up === false) {
      recommendations.push({
        severity: 'warn',
        category: 'modem',
        title: `SSID ${net.ssid} is down`,
        detail: `Radio ${net.device ?? net.ifname ?? '?'} on ${net.routerHost} reported as down.`,
        ssid: net.ssid,
      });
    }

    if (weakClientCount > 0) {
      recommendations.push({
        severity: weakClientCount >= 2 ? 'warn' : 'info',
        category: 'clients',
        title: `${weakClientCount} weak client(s) on ${net.ssid}`,
        detail: `Signal < −72 dBm on ${net.routerHost}. Consider repositioning the AP, enabling mesh/backhaul, or moving clients to 5 GHz.`,
        ssid: net.ssid,
      });
    }

    const mode = (net.mode ?? '').toLowerCase();
    if (/legacy|b/g.test(mode) && !/ax|ac|n/.test(mode)) {
      recommendations.push({
        severity: 'warn',
        category: 'modem',
        title: `${net.ssid} uses legacy mode (${net.mode})`,
        detail: '802.11b/g limits throughput and increases interference. Prefer 802.11n/ac/ax on 2.4 GHz radios.',
        ssid: net.ssid,
      });
    }
  }

  // Co-channel collisions on own SSIDs across radios
  const ownByChannel = new Map<string, number>();
  for (const net of input.ownNetworks ?? []) {
    if (net.channel == null) continue;
    const key = `${inferBandFromRadio(net.device, net.channel)}:${net.channel}`;
    ownByChannel.set(key, (ownByChannel.get(key) ?? 0) + 1);
  }
  for (const [key, count] of ownByChannel) {
    if (count > 1) {
      const [band, ch] = key.split(':');
      recommendations.push({
        severity: 'critical',
        category: 'modem',
        title: `Two of your radios on the same channel ${ch} (${band} GHz)`,
        detail: 'APs/mesh nodes on the same channel cause self-interference. Use different channels (e.g. 1 and 6 on 2.4, 36 and 149 on 5).',
        currentChannel: Number(ch),
      });
    }
  }

  // Open / weak security nearby
  for (const ap of aps) {
    if (ap.isOwnNetwork) continue;
    const sec = (ap.security ?? '').toLowerCase();
    if (sec.includes('open') || sec === 'none') {
      if (ap.rssi != null && ap.rssi > -75) {
        issues.push({
          severity: 'info',
          message: `Nearby open network: ${ap.ssid} (ch ${ap.channel ?? '?'}, ${ap.rssi} dBm).`,
        });
      }
    } else if (/wep|wpa[^2]|tkip/.test(sec) && ap.rssi != null && ap.rssi > -70) {
      issues.push({
        severity: 'warn',
        message: `Nearby weak security: ${ap.ssid} (${ap.security}).`,
      });
    }
  }

  // 2.4 GHz heavily used — suggest 5 GHz
  const summary24 = bandSummaries.find((b) => b.band === '2.4');
  const summary5 = bandSummaries.find((b) => b.band === '5');
  if (summary24 && summary5) {
    const avg24 =
      summary24.channelScores.reduce((s, c) => s + c.overlapScore, 0) /
      Math.max(1, summary24.channelScores.length);
    const has5Own = ownNetworks.some((n) => n.band === '5' && n.up !== false);
    if (avg24 >= 2.5 && has5Own) {
      recommendations.push({
        severity: 'info',
        category: 'band',
        title: '2.4 GHz congested — prefer 5 GHz',
        detail: 'Many neighboring APs on 2.4 GHz. Use a separate 5 GHz SSID or band-steering; reserve 2.4 for IoT/legacy.',
      });
    }
  }

  // Hidden SSID noise from macOS
  const hiddenCount = aps.filter((a) => a.ssid.startsWith('(SSID hidden')).length;
  if (hiddenCount > aps.length * 0.5) {
    issues.push({
      severity: 'info',
      message: `${hiddenCount} hidden network(s) in scan — enable Location Services for full names or use AP-side iwinfo scan.`,
    });
  }

  // Same channel neighbors as current connection
  if (input.currentSsid) {
    const currentAp = aps.find((a) => a.ssid === input.currentSsid && a.source === 'local');
    if (currentAp?.channel != null) {
      const sameCh = aps.filter(
        (a) => a.channel === currentAp.channel && a.ssid !== input.currentSsid && !a.isOwnNetwork,
      );
      if (sameCh.length >= 3) {
        recommendations.push({
          severity: 'warn',
          category: 'channel',
          title: `Your Mac on ch ${currentAp.channel} with ${sameCh.length} co-channel neighbors`,
          detail: 'Consider connecting on 5 GHz or asking the AP to change channel.',
          ssid: input.currentSsid,
          currentChannel: currentAp.channel,
          suggestedChannel: bandSummaries.find((b) => b.band === (currentAp.band ?? '2.4'))?.bestChannels[0],
        });
      }
    }
  }

  const congestionIndex = bandCount ? Math.round(totalCongestion / bandCount) : 0;

  // Dedupe recommendations by title
  const seenRec = new Set<string>();
  const dedupedRecs = recommendations.filter((r) => {
    if (seenRec.has(r.title)) return false;
    seenRec.add(r.title);
    return true;
  });

  dedupedRecs.sort((a, b) => {
    const rank = { critical: 0, warn: 1, info: 2 };
    return rank[a.severity] - rank[b.severity];
  });

  return {
    congestionIndex,
    bandSummaries,
    ownNetworks,
    recommendations: dedupedRecs,
    issues,
  };
}

/** Recompute exact-channel collision list from merged AP set. */
export function computeChannelCollisions(aps: WifiAp[]): { channel: number; count: number }[] {
  const byChannel = new Map<number, number>();
  for (const ap of aps) {
    if (ap.channel == null) continue;
    byChannel.set(ap.channel, (byChannel.get(ap.channel) ?? 0) + 1);
  }
  return [...byChannel.entries()]
    .filter(([, count]) => count > 1)
    .map(([channel, count]) => ({ channel, count }))
    .sort((a, b) => b.count - a.count);
}
