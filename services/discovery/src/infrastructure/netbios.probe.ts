import { createSocket } from 'node:dgram';
import { IpAddress, isOk } from '@netscanner/kernel';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';
import { mapPool } from './concurrency.js';

/** Build a NetBIOS Node Status (NBSTAT) request for name `*`. */
function nbstatRequest(): Buffer {
  const name = '*'.padEnd(16, ' ');
  const encoded = Buffer.alloc(32);
  for (let i = 0; i < 16; i++) {
    const c = name.charCodeAt(i);
    encoded[i * 2] = ((c >> 4) & 0xf) + 0x41;
    encoded[i * 2 + 1] = (c & 0xf) + 0x41;
  }
  return Buffer.from([
    0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    ...encoded,
    0x00, 0x00, 0x21, 0x00, 0x01,
  ]);
}

function parseNbstat(buf: Buffer): { hostname?: string; os?: string } {
  const text = buf.toString('latin1');
  const names: string[] = [];
  const re = /([A-Z0-9_-]{1,15})\s{2,}<00>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) names.push(m[1]!);
  const hostname = names.find((n) => !/^(WORKGROUP|MSHOME|DOMAIN)/i.test(n)) ?? names[0];
  let os: string | undefined;
  if (/windows 11/i.test(text)) os = 'Windows 11';
  else if (/windows 10/i.test(text)) os = 'Windows 10';
  else if (/windows/i.test(text)) os = 'Windows';
  return { hostname, os };
}

function queryNbstat(ip: string, timeoutMs: number): Promise<{ hostname?: string; os?: string } | null> {
  return new Promise((resolve) => {
    const socket = createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      resolve(null);
    }, timeoutMs);
    socket.on('message', (msg) => {
      clearTimeout(timer);
      socket.close();
      resolve(parseNbstat(msg));
    });
    socket.on('error', () => {
      clearTimeout(timer);
      socket.close();
      resolve(null);
    });
    socket.send(nbstatRequest(), 137, ip, () => undefined);
  });
}

/**
 * NetBIOS Node Status (UDP/137) — reveals Windows hostnames, workgroup, sometimes OS.
 */
export class NetbiosProbe implements IHostProbe {
  readonly name = 'netbios';
  readonly phase = 'enrich' as const;

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const hosts = [...ctx.cidr.hosts()].map((h) => h.value);
    await mapPool(
      hosts,
      Math.min(ctx.concurrency, 32),
      async (ip) => {
        if (ctx.signal.aborted) return;
        const parsed = IpAddress.create(ip);
        if (!isOk(parsed)) return;
        const res = await queryNbstat(ip, ctx.timeoutMs);
        if (!res) return;
        emit({
          ip,
          hostname: res.hostname,
          source: this.name,
          extra: {
            ...(res.hostname ? { netbiosName: res.hostname } : {}),
            ...(res.os ? { netbiosOs: res.os } : {}),
          },
        });
      },
      ctx.signal,
    );
  }
}
