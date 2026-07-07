import { createSocket } from 'node:dgram';
import { connect } from 'node:net';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

const MQTT_CONNECT = Buffer.from([
  0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
]);
const COAP_GET = Buffer.from([0x40, 0x01, 0x12, 0x34, 0xb5, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x0b, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x03, 0x63, 0x6f, 0x72, 0x65]);

function probeTcp(ip: string, port: number, payload: Buffer, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: ip, port, timeout: timeoutMs }, () => {
      socket.write(payload);
    });
      socket.on('data', () => {
        socket.destroy();
        resolve(true);
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
    socket.on('error', () => resolve(false));
    setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeoutMs + 100);
  });
}

function probeUdp(ip: string, port: number, payload: Buffer, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      resolve(false);
    }, timeoutMs);
    socket.on('message', () => {
      clearTimeout(timer);
      socket.close();
      resolve(true);
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
    socket.send(payload, port, ip);
  });
}

/** Lightweight MQTT/CoAP discovery (Hue/Tuya often expose MQTT). */
export class ProtocolProbe implements IHostProbe {
  readonly name = 'protocol';
  readonly phase = 'enrich' as const;

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const ips = [...ctx.cidr.hosts(256)].map((h) => h.value).slice(0, 256);
    await Promise.allSettled(
      ips.map(async (ip) => {
        if (ctx.signal.aborted) return;
        const extra: Record<string, unknown> = {};
        if (await probeTcp(ip, 1883, MQTT_CONNECT, ctx.timeoutMs)) extra['mqttOpen'] = true;
        if (await probeUdp(ip, 5683, COAP_GET, ctx.timeoutMs)) extra['coapOpen'] = true;
        if (Object.keys(extra).length) emit({ ip, source: 'protocol', extra });
      }),
    );
  }
}
