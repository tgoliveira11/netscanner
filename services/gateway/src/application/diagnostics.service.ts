import type { AppConfig } from '@netscanner/config';
import type {
  CameraScanResponse,
  Device,
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

  async cameraScan(opts?: { cidr?: string; travelMode?: boolean }): Promise<CameraScanResponse> {
    const siteId = this.getSiteId();
    const devices = await this.repo.list({ siteId });
    const candidates = [];
    const seen = new Set<string>();

    for (const d of devices) {
      const reasons = this.collectCameraReasons(d);
      if (!reasons.length && !opts?.travelMode) continue;
      if (!reasons.length) continue;
      const rtspOpen = await this.probeRtsp(d.ip);
      candidates.push(this.toCameraCandidate(d, reasons, rtspOpen));
      seen.add(d.ip);
    }

    if (opts?.travelMode) {
      for (const d of devices.filter((x) => x.isOnline)) {
        if (seen.has(d.ip)) continue;
        const rtspOpen = await this.probeRtsp(d.ip);
        const alt = await this.probeTcp(d.ip, 8554);
        if (!rtspOpen && !alt) continue;
        candidates.push(
          this.toCameraCandidate(d, [`RTSP port ${rtspOpen ? 554 : 8554} open (active probe)`], rtspOpen || alt),
        );
        seen.add(d.ip);
      }
    }

    this.logger.info({ cidr: opts?.cidr, travelMode: opts?.travelMode, count: candidates.length }, 'camera scan complete');
    return {
      candidates: candidates.sort((a, b) => b.confidence - a.confidence),
      disclaimer:
        'Indicative only — Echo/Ring/Blink cameras often use cloud-only video (no local RTSP). Verify physically; smart TVs and IoT cause false positives.',
    };
  }

  private collectCameraReasons(d: Device): string[] {
    const reasons: string[] = [];
    const host = (d.hostname ?? d.label ?? '').toLowerCase();
    const vendor = (d.vendor ?? '').toLowerCase();
    const signals = d.signals ?? {};
    const dnsCats = Array.isArray(signals.dnsCategories) ? (signals.dnsCategories as string[]) : [];
    const blob = JSON.stringify(signals);

    if (d.deviceType === 'camera') reasons.push('classified as camera');
    if (d.deviceType === 'smart-speaker') reasons.push('classified as smart speaker');
    if (d.services.some((s) => s.port === 554 || s.port === 8554)) reasons.push('RTSP port open in inventory');

    if (/^amazon-[a-f0-9]+$/i.test(host) || (host.startsWith('amazon-') && vendor.includes('amazon'))) {
      reasons.push('Amazon Alexa hostname pattern');
    }
    if (vendor.includes('amazon') && dnsCats.includes('voice-assistant')) {
      reasons.push('Amazon Alexa cloud traffic (voice-assistant DNS)');
    }
    if (dnsCats.includes('security-cam')) reasons.push('DNS: security camera vendor cloud');

    if (/amazonalexa|minerva\.devices\.a2z|ring\.com|blink|cloudfront.*alexa/i.test(blob)) {
      reasons.push('DNS queries to Alexa/Ring cloud');
    }
    if (/smart-speaker|security-cam|ring|echo show|blink/i.test(blob)) {
      reasons.push('classification / traffic hint');
    }
    if (/hikvision|dahua|axis|onvif|rtsp|reolink/i.test(blob)) reasons.push('vendor/signal hint');

    const flags = d.securityFlags.map((f) => f.code);
    if (flags.some((c) => /camera|rtsp|onvif/i.test(c))) reasons.push('security flag');

    return [...new Set(reasons)];
  }

  private toCameraCandidate(d: Device, reasons: string[], rtspOpen: boolean) {
    const cloudOnly =
      !rtspOpen && reasons.some((r) => /alexa|amazon|ring|blink|cloud/i.test(r));
    const confidence = Math.min(
      0.95,
      0.25 + reasons.length * 0.12 + (rtspOpen ? 0.35 : cloudOnly ? 0.2 : 0),
    );
    return {
      ip: d.ip,
      mac: d.mac,
      hostname: d.hostname,
      reasons: cloudOnly ? [...reasons, 'cloud-only device — no local RTSP (typical Echo/Ring/Blink)'] : reasons,
      rtspOpen,
      confidence,
    };
  }

  private probeTcp(ip: string, port: number, timeoutMs = 2000): Promise<boolean> {
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
      socket.connect(port, ip);
    });
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
