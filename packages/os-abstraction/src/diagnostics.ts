import { execFile } from 'node:child_process';
import dns from 'node:dns/promises';
import { promisify } from 'node:util';
import { currentPlatform } from './platform.js';
import type { ICommandRunner } from './command-runner.js';

const execFileAsync = promisify(execFile);

const LATENCY_RE = /time[=<]\s*([\d.]+)\s*ms/i;

export async function runPing(
  runner: ICommandRunner,
  ip: string,
  count = 3,
  timeoutMs = 5000,
): Promise<{ alive: boolean; avgLatencyMs: number | null; output: string; received: number }> {
  const args =
    currentPlatform() === 'darwin'
      ? ['-c', String(count), '-t', String(Math.ceil(timeoutMs / 1000)), ip]
      : currentPlatform() === 'win32'
        ? ['-n', String(count), '-w', String(timeoutMs), ip]
        : ['-c', String(count), '-W', String(Math.ceil(timeoutMs / 1000)), ip];
  const res = await runner.run('ping', args, { timeoutMs: timeoutMs * count + 2000 });
  const latencies: number[] = [];
  for (const line of res.stdout.split('\n')) {
    const m = LATENCY_RE.exec(line);
    if (m?.[1]) latencies.push(Number(m[1]));
  }
  const received = (res.stdout.match(/bytes from/gi) ?? []).length;
  return {
    alive: res.code === 0 || received > 0,
    avgLatencyMs: latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null,
    output: [res.stdout, res.stderr].filter(Boolean).join('\n').trim(),
    received,
  };
}

export async function runTraceroute(
  ip: string,
  maxHops = 20,
  timeoutMs = 60_000,
): Promise<{ hops: { hop: number; host: string | null; ip: string | null; latencyMs: number | null }[]; output: string }> {
  const cmd = currentPlatform() === 'win32' ? 'tracert' : 'traceroute';
  const args =
    currentPlatform() === 'win32'
      ? ['-h', String(maxHops), ip]
      : ['-m', String(maxHops), '-n', ip];
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, { timeout: timeoutMs, maxBuffer: 512_000 });
    const output = [stdout, stderr].filter(Boolean).join('\n').trim();
    const hops: { hop: number; host: string | null; ip: string | null; latencyMs: number | null }[] = [];
    for (const line of stdout.split('\n')) {
      const m = line.match(/^\s*(\d+)\s+([\d.]+|\*)\s*(.*)$/);
      if (!m) continue;
      const hop = Number(m[1]);
      const ipPart = m[2] === '*' ? null : m[2]!;
      const rest = m[3] ?? '';
      const lat = LATENCY_RE.exec(rest)?.[1];
      hops.push({
        hop,
        ip: ipPart,
        host: ipPart ? null : rest.trim() || null,
        latencyMs: lat ? Number(lat) : null,
      });
    }
    return { hops, output };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { hops: [], output: msg };
  }
}

export async function runDnsLookup(
  name: string,
  type: 'A' | 'AAAA' | 'PTR' | 'CNAME' | 'MX',
  server?: string,
): Promise<{ records: string[]; output: string }> {
  const resolver = new dns.Resolver();
  if (server) resolver.setServers([server]);
  try {
    let records: string[] = [];
    switch (type) {
      case 'A':
        records = await resolver.resolve4(name);
        break;
      case 'AAAA':
        records = await resolver.resolve6(name);
        break;
      case 'PTR':
        records = await resolver.resolvePtr(name);
        break;
      case 'CNAME':
        records = await resolver.resolveCname(name);
        break;
      case 'MX':
        records = (await resolver.resolveMx(name)).map((r) => `${r.priority} ${r.exchange}`);
        break;
    }
    return { records, output: records.join('\n') };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { records: [], output: msg };
  }
}
