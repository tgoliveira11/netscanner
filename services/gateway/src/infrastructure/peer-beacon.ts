import { createSocket, type Socket } from 'node:dgram';
import type { Logger } from '@netscanner/logger';
import { PeerBeaconSchema, type PeerBeacon } from '@netscanner/contracts';

const BROADCAST = '255.255.255.255';

export type PeerBeaconHandler = (beacon: PeerBeacon, address: string) => void;

function parsePeerHosts(raw: string | undefined): string[] {
  if (!raw?.trim()) return [];
  return [...new Set(raw.split(',').map((s) => s.trim()).filter(Boolean))];
}

/** UDP v1 peer beacon sender/receiver for LAN cluster discovery. */
export class PeerBeaconTransport {
  private socket: Socket | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly peerHosts: string[];

  constructor(
    private readonly port: number,
    private readonly logger: Logger,
    private readonly onBeacon: PeerBeaconHandler,
    peerHostsRaw = '',
  ) {
    this.peerHosts = parsePeerHosts(peerHostsRaw);
  }

  start(buildPayload: () => PeerBeacon, intervalMs = 2_000): void {
    if (this.socket) return;
    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    this.socket = socket;

    socket.on('error', (err) => {
      this.logger.warn({ err: err.message }, 'cluster beacon socket error');
    });

    socket.on('message', (msg, rinfo) => {
      try {
        const raw = JSON.parse(msg.toString('utf8'));
        const parsed = PeerBeaconSchema.safeParse(raw);
        if (!parsed.success) return;
        this.onBeacon(parsed.data, rinfo.address);
      } catch {
        /* ignore malformed */
      }
    });

    socket.bind(this.port, () => {
      try {
        socket.setBroadcast(true);
      } catch (err) {
        this.logger.warn({ err }, 'cluster beacon setBroadcast failed');
      }
      this.logger.info(
        { port: this.port, unicastPeers: this.peerHosts.length },
        'cluster beacon listening',
      );
    });

    this.timer = setInterval(() => {
      try {
        const payload = Buffer.from(JSON.stringify(buildPayload()), 'utf8');
        socket.send(payload, 0, payload.length, this.port, BROADCAST);
        for (const host of this.peerHosts) {
          socket.send(payload, 0, payload.length, this.port, host);
        }
      } catch (err) {
        this.logger.warn({ err }, 'cluster beacon send failed');
      }
    }, intervalMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.socket?.close();
    this.socket = null;
  }
}
