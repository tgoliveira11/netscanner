import { createSocket } from 'node:dgram';
import { connect } from 'node:net';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

const MQTT_CONNECT = Buffer.from([
  0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
]);
const COAP_GET = Buffer.from([
  0x40, 0x01, 0x12, 0x34, 0xb5, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x0b,
  0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x03, 0x63, 0x6f, 0x72, 0x65,
]);

function probeMqtt(ip: string, timeoutMs: number): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const extra: Record<string, unknown> = {};
    const socket = connect({ host: ip, port: 1883, timeout: timeoutMs }, () => {
      socket.write(MQTT_CONNECT);
    });
    socket.on('data', (chunk) => {
      if (chunk[0] === 0x20) {
        extra.mqttOpen = true;
        extra.mqttConnack = `rc=${chunk[3] ?? 0}`;
      }
      socket.destroy();
      resolve(extra);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(extra);
    });
    socket.on('error', () => resolve(extra));
    setTimeout(() => {
      socket.destroy();
      resolve(extra);
    }, timeoutMs + 100);
  });
}

function probeCoap(ip: string, timeoutMs: number): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const extra: Record<string, unknown> = {};
    const socket = createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      resolve(extra);
    }, timeoutMs);
    socket.on('message', (msg) => {
      clearTimeout(timer);
      extra.coapOpen = true;
      extra.coapCode = msg[1] ?? 0;
      socket.close();
      resolve(extra);
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(extra);
    });
    socket.send(COAP_GET, 5683, ip);
  });
}

/** Lightweight MQTT/CoAP discovery with response parsing (Hue/Tuya/IoT). */
export class ProtocolProbe implements IHostProbe {
  readonly name = 'protocol';
  readonly phase = 'enrich' as const;

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const ips = [...ctx.cidr.hosts(256)].map((h) => h.value).slice(0, 256);
    await Promise.allSettled(
      ips.map(async (ip) => {
        if (ctx.signal.aborted) return;
        const mqtt = await probeMqtt(ip, ctx.timeoutMs);
        const coap = await probeCoap(ip, ctx.timeoutMs);
        const extra = { ...mqtt, ...coap };
        if (Object.keys(extra).length) emit({ ip, source: 'protocol', extra });
      }),
    );
  }
}
