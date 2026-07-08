import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';
import type { PfSenseTelemetry } from '../domain/pfsense-telemetry.js';
import { mergePfSenseLeases } from './pfsense-lease-normalize.js';
import {
  applyInterfaceLabels,
  buildInterfaceLabelMap,
  enrichLeasesFromStaticMappings,
  normalizePfSenseArpRow,
  normalizePfSenseDhcpRows,
  normalizePfSenseGatewayRow,
  normalizePfSenseInterfaceRow,
} from './pfsense-telemetry-normalize.js';
import { CompositeLeaseSource } from './composite-lease-source.js';

export interface PfSenseConfig {
  baseUrl: string;
  apiKey: string;
  leasesPath: string;
  insecureTls: boolean;
  timeoutMs?: number;
}

const DEFAULT_PATHS = {
  arp: '/api/v2/diagnostics/arp_table',
  gateways: '/api/v2/status/gateways',
  interfaces: '/api/v2/status/interfaces',
  staticMappings: '/api/v2/services/dhcp_server/static_mappings',
  version: '/api/v2/system/version',
  hostname: '/api/v2/system/hostname',
} as const;

/**
 * Pulls DHCP leases, ARP, gateways, and interfaces from pfSense via the REST API
 * package (v2). Merges DHCP + ARP, maps internal iface names to GUI labels, and
 * caches the last snapshot for topology / device signals.
 */
export class PfSenseRestAdapter implements IRouterLeaseSource {
  readonly name = 'pfsense-rest';

  private telemetry: PfSenseTelemetry | null = null;
  private leases: RouterLease[] = [];

  constructor(
    private readonly config: PfSenseConfig,
    private readonly logger: Logger,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    await this.refresh();
    return this.leases;
  }

  getTelemetry(): PfSenseTelemetry | null {
    return this.telemetry;
  }

  private async refresh(): Promise<void> {
    const timeout = this.config.timeoutMs ?? 8000;
    const [dhcpRaw, arpRaw, gwRaw, ifRaw, staticRaw, versionRaw, hostnameRaw] = await Promise.all([
      this.getPath(this.config.leasesPath, timeout),
      this.getPath(DEFAULT_PATHS.arp, timeout),
      this.getPath(DEFAULT_PATHS.gateways, timeout),
      this.getPath(DEFAULT_PATHS.interfaces, timeout),
      this.getPath(DEFAULT_PATHS.staticMappings, timeout).catch(() => []),
      this.getPathObject(DEFAULT_PATHS.version, timeout).catch(() => null),
      this.getPathObject(DEFAULT_PATHS.hostname, timeout).catch(() => null),
    ]);

    const dhcp = normalizePfSenseDhcpRows(this.extractArray(dhcpRaw));
    const arp = this.extractArray(arpRaw)
      .map((r) => normalizePfSenseArpRow(r))
      .filter((l): l is RouterLease => l !== null);
    const interfaces = this.extractArray(ifRaw).map((r) => normalizePfSenseInterfaceRow(r));
    const labelMap = buildInterfaceLabelMap(interfaces);

    let merged = mergePfSenseLeases(dhcp, arp);
    merged = enrichLeasesFromStaticMappings(merged, this.extractArray(staticRaw));
    merged = applyInterfaceLabels(merged, labelMap);

    const gateways = this.extractArray(gwRaw).map((r) => normalizePfSenseGatewayRow(r));
    const version = strField(versionRaw, 'version') ?? strField(versionRaw, 'base');
    const hostname =
      strField(hostnameRaw, 'hostname') ??
      (typeof hostnameRaw === 'string' ? hostnameRaw : null);

    this.leases = merged;
    this.telemetry = {
      version,
      hostname,
      gateways,
      interfaces,
      fetchedAt: new Date().toISOString(),
    };

    this.logger.info(
      {
        source: this.name,
        leases: merged.length,
        arp: arp.length,
        gateways: gateways.length,
        interfaces: interfaces.length,
      },
      'pfSense snapshot fetched',
    );
  }

  private async getPath(path: string, timeoutMs: number): Promise<unknown> {
    const url = new URL(path, this.config.baseUrl);
    return this.getJson(url, timeoutMs);
  }

  private async getPathObject(path: string, timeoutMs: number): Promise<Record<string, unknown> | null> {
    const raw = await this.getPath(path, timeoutMs);
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      const data = (raw as Record<string, unknown>)['data'];
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data as Record<string, unknown>;
      }
      return raw as Record<string, unknown>;
    }
    return null;
  }

  /** The REST API wraps results as { data: [...] }; fall back to any array found. */
  private extractArray(raw: unknown): Record<string, unknown>[] {
    if (Array.isArray(raw)) return raw as Record<string, unknown>[];
    if (raw && typeof raw === 'object') {
      const data = (raw as Record<string, unknown>)['data'];
      if (Array.isArray(data)) return data as Record<string, unknown>[];
      for (const value of Object.values(raw as Record<string, unknown>)) {
        if (Array.isArray(value)) return value as Record<string, unknown>[];
      }
    }
    return [];
  }

  private getJson(url: URL, timeoutMs: number): Promise<unknown> {
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method: 'GET',
          headers: { 'X-API-Key': this.config.apiKey, Accept: 'application/json' },
          timeout: timeoutMs,
          ...(isHttps ? { rejectUnauthorized: !this.config.insecureTls } : {}),
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => {
            if ((res.statusCode ?? 500) >= 400) {
              reject(new Error(`pfSense API ${res.statusCode}: ${body.slice(0, 200)}`));
              return;
            }
            try {
              resolve(JSON.parse(body));
            } catch {
              reject(new Error('pfSense API returned non-JSON (check URL/path/key)'));
            }
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('pfSense API timeout')));
      req.on('error', reject);
      req.end();
    });
  }
}

/** Resolve cached pfSense telemetry from a simple or composite lease source. */
export function resolvePfSenseTelemetry(source?: IRouterLeaseSource): PfSenseTelemetry | null {
  if (!source) return null;
  if (source instanceof PfSenseRestAdapter) return source.getTelemetry();
  if (source instanceof CompositeLeaseSource) {
    for (const child of source.listSources()) {
      const telemetry = resolvePfSenseTelemetry(child);
      if (telemetry) return telemetry;
    }
  }
  return null;
}

function strField(raw: Record<string, unknown> | null, key: string): string | null {
  if (!raw) return null;
  const v = raw[key];
  if (v == null) return null;
  const s = String(v).trim();
  return s.length ? s : null;
}
