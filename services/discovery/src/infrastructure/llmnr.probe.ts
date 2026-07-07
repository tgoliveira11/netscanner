import { createSocket } from 'node:dgram';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

const LLMNR_MCAST = '224.0.0.252';

/**
 * Passive LLMNR listener (UDP/5355) during the enrich phase. Windows hosts
 * respond to name queries on the link-local multicast group.
 */
export class LlmnrProbe implements IHostProbe {
  readonly name = 'llmnr';
  readonly phase = 'enrich' as const;

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    await new Promise<void>((resolve) => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      const seen = new Set<string>();

      const done = () => {
        try {
          socket.close();
        } catch {
          /* ignore */
        }
        resolve();
      };

      socket.on('message', (msg, rinfo) => {
        const ip = rinfo.address;
        if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return;
        if (seen.has(ip)) return;
        const text = msg.toString('utf8', 0, Math.min(msg.length, 512));
        const label = extractLlmnrLabel(text);
        if (!label) return;
        seen.add(ip);
        emit({
          ip,
          hostname: label,
          source: this.name,
          extra: { llmnrName: label },
        });
      });

      socket.on('error', done);
      socket.bind(5355, () => {
        try {
          socket.addMembership(LLMNR_MCAST);
        } catch {
          /* ignore */
        }
      });

      const timer = setTimeout(done, Math.max(ctx.timeoutMs, 3000));
      ctx.signal.addEventListener('abort', () => {
        clearTimeout(timer);
        done();
      });
    });
  }
}

/** Best-effort label extraction from an LLMNR/DNS-like response payload. */
function extractLlmnrLabel(buf: string): string | null {
  const printable = buf.replace(/[^\x20-\x7e]/g, ' ').trim();
  const tokens = printable.split(/\s+/).filter((t) => t.length > 1 && /^[a-z0-9][-a-z0-9.]*$/i.test(t));
  const candidate = tokens.find((t) => !/^(local|arpa|in-addr)$/i.test(t) && t.length <= 63);
  return candidate ?? null;
}
