import type { AppConfig } from '@netscanner/config';
import type {
  CameraScanResponse,
  DnsLookupResponse,
  PingResponse,
  PortScanResponse,
  TracerouteResponse,
  WifiScanResponse,
} from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import { runDnsLookup, runPing, runTraceroute } from '@netscanner/os-abstraction';
import { scanWifiAps } from '@netscanner/os-abstraction';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { FingerprintHostUseCase } from '@netscanner/scanner';
import type { IDeviceRepository } from '@netscanner/inventory';
import { Socket } from 'node:net';

export class DiagnosticsService {
  constructor(
    private readonly runner: ICommandRunner,
    private readonly fingerprint: FingerprintHostUseCase,
    private readonly repo: IDeviceRepository,
    private readonly logger: Logger,
    private readonly getSiteId: () => string,
  ) {}

  async ping(ip: string, count = 3): Promise<PingResponse> {
    const res = await runPing(this.runner, ip, count);
    return {
      ip,
      alive: res.alive,
      packetsSent: count,
      packetsReceived: res.received,
      avgLatencyMs: res.avgLatencyMs,
      output: res.output,
    };
  }

  async traceroute(ip: string, maxHops = 20): Promise<TracerouteResponse> {
    const res = await runTraceroute(ip, maxHops);
    return { ip, hops: res.hops, output: res.output };
  }

  async dnsLookup(name: string, type: 'A' | 'AAAA' | 'PTR' | 'CNAME' | 'MX', server?: string): Promise<DnsLookupResponse> {
    const res = await runDnsLookup(name, type, server);
    return { name, type, records: res.records, output: res.output };
  }

  async portScan(ip: string, depth: 'quick' | 'standard'): Promise<PortScanResponse> {
    const started = Date.now();
    const fp = await this.fingerprint.execute({
      ip,
      depth,
      osDetection: false,
      timeoutMs: depth === 'quick' ? 15_000 : 45_000,
    });
    return {
      ip,
      services: fp.services.map((s) => ({
        port: s.port,
        protocol: s.protocol,
        state: s.state,
        product: s.product ?? undefined,
        version: s.version ?? undefined,
      })),
      durationMs: Date.now() - started,
    };
  }

  async wifiScan(): Promise<WifiScanResponse> {
    return scanWifiAps();
  }

  async cameraScan(cidr?: string): Promise<CameraScanResponse> {
    const siteId = this.getSiteId();
    const devices = await this.repo.list({ siteId });
    const candidates = [];
    for (const d of devices) {
      const reasons: string[] = [];
      if (d.deviceType === 'camera') reasons.push('classified as camera');
      if (d.services.some((s) => s.port === 554)) reasons.push('RTSP port 554 open');
      const flags = d.securityFlags.map((f) => f.code);
      if (flags.some((c) => /camera|rtsp|onvif/i.test(c))) reasons.push('security flag');
      const signals = JSON.stringify(d.signals ?? {});
      if (/hikvision|dahua|axis|onvif|rtsp/i.test(signals)) reasons.push('vendor/signal hint');
      if (!reasons.length) continue;
      const rtspOpen = await this.probeRtsp(d.ip);
      candidates.push({
        ip: d.ip,
        mac: d.mac,
        hostname: d.hostname,
        reasons,
        rtspOpen,
        confidence: Math.min(0.95, 0.3 + reasons.length * 0.15 + (rtspOpen ? 0.3 : 0)),
      });
    }
    this.logger.info({ cidr, count: candidates.length }, 'camera scan complete');
    return {
      candidates: candidates.sort((a, b) => b.confidence - a.confidence),
      disclaimer:
        'Indicative only — not proof of hidden cameras. Verify physically; false positives from smart TVs and IoT are common.',
    };
  }

  private probeRtsp(ip: string, timeoutMs = 2000): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new Socket();
      const done = (ok: boolean) => {
        socket.destroy();
        resolve(ok);
      };
      socket.setTimeout(timeoutMs);
      socket.once('connect', () => done(true));
      socket.once('timeout', () => done(false));
      socket.once('error', () => done(false));
      socket.connect(554, ip);
    });
  }
}
