/** Parsed TCP SYN stack traits (p0f-style passive observation). */
export interface TcpSynTraits {
  ttl: number;
  window: number;
  mss: number | null;
  wscale: number | null;
  sack: boolean;
  ts: boolean;
}

export interface P0fOsGuess {
  family: string;
  name: string;
  confidence: number;
  reason: string;
}

/** Extract client IP and SYN traits from a verbose tcpdump line. */
export function parseTcpSynLine(line: string): { ip: string; traits: TcpSynTraits } | null {
  if (!/Flags \[S\]/i.test(line) || /Flags \[S\.\]/i.test(line)) return null;

  const ipMatch = /(\d+\.\d+\.\d+\.\d+)\.\d+ > .* Flags \[S\]/i.exec(line);
  if (!ipMatch) return null;

  const ttl = Number(/ttl (\d+)/i.exec(line)?.[1]);
  const win = Number(/win (\d+)/i.exec(line)?.[1]);
  if (!Number.isFinite(ttl) || !Number.isFinite(win)) return null;

  const opts = /options \[(.*?)\]/i.exec(line)?.[1] ?? '';
  const mss = Number(/mss (\d+)/i.exec(opts)?.[1]);
  const wscale = Number(/wscale (\d+)/i.exec(opts)?.[1]);

  return {
    ip: ipMatch[1]!,
    traits: {
      ttl: ttl,
      window: win,
      mss: Number.isFinite(mss) ? mss : null,
      wscale: Number.isFinite(wscale) ? wscale : null,
      sack: /sackOK/i.test(opts),
      ts: /TS val/i.test(opts),
    },
  };
}

function signatureKey(t: TcpSynTraits): string {
  return [t.ttl, t.window, t.mss ?? 0, t.wscale ?? -1, t.sack ? 1 : 0].join(':');
}

/**
 * Heuristic OS guess from SYN traits — complements DHCP/JA3 on firewalled mobiles.
 * Conservative accuracy; always tagged `source: inferred` downstream.
 */
export function guessOsFromSynTraits(t: TcpSynTraits): P0fOsGuess | null {
  const sig = signatureKey(t);

  const rules: { match: (t: TcpSynTraits, sig: string) => boolean; guess: (t: TcpSynTraits) => P0fOsGuess }[] = [
    {
      match: (x) => x.ttl === 64 && x.window === 65535 && x.mss === 1460 && x.wscale === 6,
      guess: () => ({
        family: 'iOS',
        name: 'Apple iOS/iPadOS (SYN stack)',
        confidence: 72,
        reason: 'TTL 64, win 65535, MSS 1460, wscale 6',
      }),
    },
    {
      match: (x) => x.ttl === 64 && x.window === 65535 && x.mss === 1460 && x.wscale === 7,
      guess: () => ({
        family: 'macOS',
        name: 'Apple macOS (SYN stack)',
        confidence: 68,
        reason: 'TTL 64, win 65535, MSS 1460, wscale 7',
      }),
    },
    {
      match: (x) => x.ttl === 64 && x.window >= 65535 && x.mss === 1460,
      guess: (x) => ({
        family: 'Linux',
        name: 'Linux / Android (SYN stack)',
        confidence: 55,
        reason: `TTL 64, win ${x.window}, MSS 1460`,
      }),
    },
    {
      match: (x) => x.ttl === 128 && x.window >= 8192,
      guess: (x) => ({
        family: 'Windows',
        name: 'Microsoft Windows (SYN stack)',
        confidence: 65,
        reason: `TTL 128, win ${x.window}`,
      }),
    },
    {
      match: (x) => x.ttl === 255 || x.ttl === 254,
      guess: (x) => ({
        family: 'embedded',
        name: 'Embedded / network appliance (SYN stack)',
        confidence: 45,
        reason: `TTL ${x.ttl}`,
      }),
    },
  ];

  for (const rule of rules) {
    if (rule.match(t, sig)) return rule.guess(t);
  }

  if (t.ttl === 64) {
    return {
      family: 'unix',
      name: 'Unix-like (SYN stack)',
      confidence: 40,
      reason: `TTL 64, win ${t.window}`,
    };
  }
  return null;
}

export function traitsToSignal(t: TcpSynTraits): Record<string, unknown> {
  const guess = guessOsFromSynTraits(t);
  const out: Record<string, unknown> = {
    p0fTtl: t.ttl,
    p0fWindow: t.window,
    p0fMss: t.mss,
    p0fWscale: t.wscale,
    p0fSignature: signatureKey(t),
    p0fPassive: true,
  };
  if (guess) {
    out.p0fOsFamily = guess.family;
    out.p0fOsName = guess.name;
    out.p0fOsConfidence = guess.confidence;
    out.p0fOsReason = guess.reason;
  }
  return out;
}
