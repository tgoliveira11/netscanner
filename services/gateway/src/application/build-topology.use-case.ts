import type { AppConfig } from '@netscanner/config';
import { mergeRouterScrapeTargets } from '@netscanner/config';
import type {
  Device,
  IConnectionSource,
  TopologyEdge,
  TopologyNode,
  TopologyResponse,
  TopologySsid,
  TopologyVlan,
} from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import {
  isLocalScannerDevice,
  normalizeMac,
  probeOpenWrtWireless,
  resolveDeviceVlan,
  type TopologyEligibilityContext,
} from '@netscanner/discovery';
import type { RouterScrapeTarget } from '@netscanner/config';
import type { LocalInterface } from '@netscanner/os-abstraction';
import type { IDeviceRepository } from '@netscanner/inventory';

const CORE_VLAN_ORDER = ['VLAN40', 'VLAN10', 'VLAN30', 'VLAN20'] as const;

/**
 * Builds a VLAN-centric home topology from inventory + pfSense interface tags +
 * optional OpenWrt wireless probes:
 *
 *   Internet-facing hosts excluded
 *   pfSense (gateway)
 *     ├── VLAN40  → wired switch/router
 *     ├── VLAN10   → WiFi AP → clients
 *     ├── VLAN30  → WiFi AP → clients
 *     └── VLAN20    → WiFi AP → clients
 */
export class BuildTopologyUseCase {
  constructor(
    private readonly repo: IDeviceRepository,
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly connectionSource?: IConnectionSource,
    private readonly listLocalInterfaces: () => LocalInterface[] = () => [],
  ) {}

  async execute(): Promise<TopologyResponse> {
    if (this.connectionSource) {
      try {
        await this.connectionSource.refresh();
      } catch (error) {
        this.logger.warn(
          { err: error instanceof Error ? error.message : String(error) },
          'topology: SNMP connection refresh failed',
        );
      }
    }

    const devices = await this.repo.list();
    const localIfaces = this.listLocalInterfaces();
    const scrapeTargets = await this.resolveScrapeTargets();
    const managedRouterIps = new Set(
      scrapeTargets.map((t) => hostFromUrl(t.baseUrl)).filter(Boolean),
    );
    if (this.config.SNMP_SWITCH_HOST) managedRouterIps.add(this.config.SNMP_SWITCH_HOST);
    if (this.config.ROUTER_SNMP_HOST) managedRouterIps.add(this.config.ROUTER_SNMP_HOST);

    const wireless =
      scrapeTargets.length > 0
        ? await probeOpenWrtWireless(
            scrapeTargets.map((t) => ({
              baseUrl: t.baseUrl,
              kind: t.kind,
              username: t.username,
              password: t.password,
            })),
            this.logger,
          )
        : [];

    const gateway = pickGateway(devices, localIfaces, this.config);
    const eligibility: TopologyEligibilityContext = {
      localIfaces,
      managedRouterIps,
      gatewayId: gateway?.id ?? null,
    };

    const edges: TopologyEdge[] = [];
    const nodes: TopologyNode[] = [];
    const placed = new Set<string>();

    if (!gateway) {
      return { gatewayId: null, edges: [], ssids: [], vlans: [], nodes: [] };
    }

    nodes.push({ id: gateway.id, role: 'gateway', tier: 0, wifiCapable: false });
    placed.add(gateway.id);

    const switchDevice = pickWiredInfra(devices, gateway, eligibility, this.config, this.connectionSource);
    const wifiAps = pickWifiAccessPoints(devices, gateway, eligibility, wireless, scrapeTargets);

    if (switchDevice) {
      const vlan = resolveDeviceVlan(switchDevice);
      edges.push(edge(switchDevice.id, gateway.id, 'wired', 'infra', vlan));
      nodes.push({ id: switchDevice.id, role: 'wired-router', tier: 1, wifiCapable: false });
      placed.add(switchDevice.id);
    }

    for (const ap of wifiAps) {
      const vlan = resolveDeviceVlan(ap);
      edges.push(edge(ap.id, gateway.id, 'wired', 'uplink', vlan));
      nodes.push({ id: ap.id, role: 'wifi-ap', tier: 2, wifiCapable: true });
      placed.add(ap.id);
    }

    const apByVlan = new Map<string, Device>();
    for (const ap of wifiAps) {
      const vlan = resolveDeviceVlan(ap);
      if (!apByVlan.has(vlan.id)) apByVlan.set(vlan.id, ap);
    }

    for (const device of devices) {
      if (placed.has(device.id)) continue;
      if (!isTopologyClient(device, gateway, localIfaces)) continue;

      const vlan = resolveDeviceVlan(device);
      if (isWanOrUnusedSegment(vlan.id)) continue;

      const snmp = lookupSnmp(device, this.connectionSource);
      const isWifi = device.connectionType === 'wifi' || snmp?.type === 'wifi';
      const isWired = device.connectionType === 'wired' || snmp?.type === 'wired';

      let parentId: string | null = null;
      let kind: TopologyEdge['kind'] = 'unknown';
      let label = vlan.label;
      let ssid: string | undefined;

      if (isWifi) {
        const ap = apByVlan.get(vlan.id) ?? apForIp(device.ip, wifiAps);
        parentId = ap?.id ?? gateway.id;
        kind = 'wifi';
        const assocSsid = findClientSsid(device, wireless);
        if (assocSsid) {
          ssid = assocSsid;
          label = assocSsid;
        } else {
          label = 'wifi';
        }
      } else if (isWired) {
        if (
          switchDevice &&
          (vlan.id === 'VLAN40' || sameIpv4Slash24(device.ip, switchDevice.ip))
        ) {
          parentId = switchDevice.id;
        } else {
          parentId = gateway.id;
        }
        kind = 'wired';
        label = snmp?.ifName ?? 'wired';
      } else {
        // Unknown attachment: hang under AP if same VLAN has one, else gateway.
        const ap = apByVlan.get(vlan.id);
        parentId = ap?.id ?? gateway.id;
        kind = ap ? 'wifi' : 'wired';
        label = ap ? 'wifi' : 'lan';
      }

      if (!parentId || parentId === device.id) continue;

      edges.push(edge(device.id, parentId, kind, label, vlan, ssid));
      nodes.push({
        id: device.id,
        role: 'endpoint',
        tier: kind === 'wifi' ? 3 : switchDevice && parentId === switchDevice.id ? 2 : 3,
        wifiCapable: isWifi,
      });
      placed.add(device.id);
    }

    const ssids = collectSsids(wireless, wifiAps);

    return {
      gatewayId: gateway.id,
      edges,
      ssids,
      vlans: collectVlans(edges),
      nodes,
    };
  }

  private async resolveScrapeTargets(): Promise<RouterScrapeTarget[]> {
    const creds = await this.repo.listRouterScrapeCredentials();
    return mergeRouterScrapeTargets(
      this.config,
      creds.map((row) => ({
        ip: row.ip,
        deviceType: row.deviceType,
        brand: row.brand,
        routerScrapeUser: row.routerScrapeUser,
        routerScrapePassword: row.routerScrapePassword,
      })),
    );
  }
}

/** Prefer configured SNMP/pfSense host, then pfSense-branded routers, then any .1 that isn't WAN/side. */
export function pickGateway(
  devices: Device[],
  localIfaces: LocalInterface[],
  config: AppConfig,
): Device | null {
  const routers = devices.filter(
    (d) => d.deviceType === 'router' && !isLocalScannerDevice(d, localIfaces),
  );
  if (routers.length === 0) return null;

  const byIp = (ip: string) => (ip ? routers.find((d) => d.ip === ip) ?? null : null);
  const pfsenseHost = hostFromUrl(config.PFSENSE_URL ?? '');

  return (
    byIp(config.ROUTER_SNMP_HOST ?? '') ??
    byIp(pfsenseHost) ??
    routers.find((d) => {
      const iface = String(d.signals?.pfsenseHostname ?? '');
      return iface.toLowerCase() === 'pfsense' || d.brand?.toLowerCase().includes('pfsense');
    }) ??
    routers.find((d) => d.ip.endsWith('.1') && !isWanOrSideIp(d.ip)) ??
    routers[0] ??
    null
  );
}

export function pickWiredInfra(
  devices: Device[],
  gateway: Device,
  eligibility: TopologyEligibilityContext,
  config: AppConfig,
  connectionSource?: IConnectionSource,
): Device | null {
  const candidates = devices.filter((d) => {
    if (d.id === gateway.id) return false;
    if (d.deviceType !== 'router' && d.deviceType !== 'switch') return false;
    if (isLocalScannerDevice(d, eligibility.localIfaces)) return false;
    if (isWanOrSideIp(d.ip)) return false;
    if (d.connectionType === 'wifi') return false;

    const vlan = resolveDeviceVlan(d).id;
    if (vlan.startsWith('WAN') || vlan === 'LAN') return false;

    if (config.SNMP_SWITCH_HOST && d.ip === config.SNMP_SWITCH_HOST) return true;
    if (eligibility.managedRouterIps.has(d.ip) && !looksLikeWifiAp(d, [], [])) {
      const wifiish =
        d.brand?.toLowerCase().includes('compal') ||
        d.brand?.toLowerCase().includes('openwrt') ||
        (d.hostname ?? '').toLowerCase().startsWith('cbnre');
      if (wifiish) return false;
      return true;
    }

    if (vlan === 'VLAN40') return true;

    const snmp = lookupSnmp(d, connectionSource);
    if (snmp?.type === 'wired' && !looksLikeWifiAp(d, [], [])) return true;
    return false;
  });

  return (
    candidates.find((d) => d.ip === config.SNMP_SWITCH_HOST) ??
    candidates.find((d) => resolveDeviceVlan(d).id === 'VLAN40') ??
    candidates[0] ??
    null
  );
}

export function pickWifiAccessPoints(
  devices: Device[],
  gateway: Device,
  eligibility: TopologyEligibilityContext,
  wireless: Awaited<ReturnType<typeof probeOpenWrtWireless>>,
  scrapeTargets: RouterScrapeTarget[],
): Device[] {
  return devices.filter((d) => {
    if (d.id === gateway.id) return false;
    if (d.deviceType !== 'router' && d.deviceType !== 'access-point') return false;
    if (isLocalScannerDevice(d, eligibility.localIfaces)) return false;
    if (isWanOrSideIp(d.ip)) return false;
    if (isWanOrUnusedSegment(resolveDeviceVlan(d).id)) return false;
    return looksLikeWifiAp(d, wireless, scrapeTargets);
  });
}

export function looksLikeWifiAp(
  device: Device,
  wireless: Awaited<ReturnType<typeof probeOpenWrtWireless>>,
  scrapeTargets: RouterScrapeTarget[],
): boolean {
  const probe = wireless.find((w) => w.host === device.ip);
  if (probe?.ok && probe.wifiCapable) return true;
  if (scrapeTargets.some((t) => hostFromUrl(t.baseUrl) === device.ip && t.kind === 'compal')) {
    return true;
  }
  const brand = (device.brand ?? '').toLowerCase();
  const host = (device.hostname ?? '').toLowerCase();
  if (brand.includes('compal') || brand.includes('openwrt')) return true;
  if (host.startsWith('cbnre')) return true;
  if (device.deviceType === 'access-point') return true;
  return false;
}

export function isTopologyClient(
  device: Device,
  gateway: Device,
  localIfaces: LocalInterface[],
): boolean {
  if (device.id === gateway.id) return false;
  if (isLocalScannerDevice(device, localIfaces)) return false;
  if (isWanOrSideIp(device.ip)) return false;
  // Router/AP nodes are placed separately; never treat them as leaf clients.
  if (device.deviceType === 'router' || device.deviceType === 'access-point' || device.deviceType === 'switch') {
    return false;
  }
  if (device.deviceType === 'firewall') return false;
  return true;
}

export function isWanOrSideIp(ip: string): boolean {
  if (ip.startsWith('192.168.0.')) return true; // ISP/WAN handoff
  if (ip.startsWith('192.168.64.')) return true; // Mac Internet Sharing
  if (ip.startsWith('10.8.') || ip.startsWith('10.14.')) return true; // VPN overlays
  return false;
}

export function isWanOrUnusedSegment(vlanId: string): boolean {
  const id = vlanId.toUpperCase();
  if (id.startsWith('WAN')) return true;
  if (id === 'LAN') return true; // no-carrier legacy segment
  if (id === 'TRUNK') return true;
  return false;
}

function sameIpv4Slash24(a: string, b: string): boolean {
  const pa = a.split('.');
  const pb = b.split('.');
  if (pa.length !== 4 || pb.length !== 4) return false;
  return pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2];
}

function apForIp(ip: string, aps: Device[]): Device | undefined {
  return aps.find((ap) => sameIpv4Slash24(ip, ap.ip));
}

function findClientSsid(
  device: Device,
  wireless: Awaited<ReturnType<typeof probeOpenWrtWireless>>,
): string | undefined {
  const mac = normalizeMac(device.mac);
  if (!mac) return undefined;
  for (const probe of wireless) {
    if (!probe.ok) continue;
    for (const ssid of probe.ssids) {
      if (ssid.clients?.some((c) => normalizeMac(c.mac) === mac)) return ssid.ssid;
    }
  }
  return undefined;
}

function collectSsids(
  wireless: Awaited<ReturnType<typeof probeOpenWrtWireless>>,
  wifiAps: Device[],
): TopologySsid[] {
  const apByIp = new Map(wifiAps.map((d) => [d.ip, d]));
  const out: TopologySsid[] = [];
  for (const probe of wireless) {
    if (!probe.ok) continue;
    const ap = apByIp.get(probe.host);
    if (!ap) continue;
    for (const ssid of probe.ssids) {
      out.push({
        routerId: ap.id,
        routerIp: ap.ip,
        ssid: ssid.ssid,
        up: ssid.up,
        channel: ssid.channel,
        clientCount: ssid.clients?.length ?? 0,
      });
    }
  }
  return out;
}

function hostFromUrl(baseUrl: string): string {
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return baseUrl.replace(/^https?:\/\//, '').split('/')[0] ?? '';
  }
}

function lookupSnmp(device: Device, source?: IConnectionSource) {
  const mac = normalizeMac(device.mac);
  if (!mac || !source) return null;
  return source.lookupByMac(mac);
}

function edge(
  from: string,
  to: string,
  kind: TopologyEdge['kind'],
  label: string,
  vlan: { id: string; label: string },
  ssid?: string,
): TopologyEdge {
  return {
    from,
    to,
    kind,
    label,
    vlan: vlan.id,
    vlanLabel: vlan.label,
    ...(ssid ? { ssid } : {}),
  };
}

export function collectVlans(edges: TopologyEdge[]): TopologyVlan[] {
  const seen = new Map<string, string>();
  for (const edge of edges) {
    if (!edge.vlan) continue;
    if (isWanOrUnusedSegment(edge.vlan)) continue;
    seen.set(edge.vlan, edge.vlanLabel ?? edge.vlan);
  }
  return [...seen.entries()]
    .map(([id, label]) => ({ id, label }))
    .sort((a, b) => {
      const ai = CORE_VLAN_ORDER.indexOf(a.id as (typeof CORE_VLAN_ORDER)[number]);
      const bi = CORE_VLAN_ORDER.indexOf(b.id as (typeof CORE_VLAN_ORDER)[number]);
      if (ai >= 0 || bi >= 0) return (ai >= 0 ? ai : 99) - (bi >= 0 ? bi : 99);
      return a.label.localeCompare(b.label);
    });
}

/** @deprecated kept for existing tests — prefer pickWiredInfra / pickWifiAccessPoints */
export function resolveWiredParent(
  device: Device,
  snmp: ReturnType<IConnectionSource['lookupByMac']>,
  wiredHubId: string | null,
  gatewayId: string | null,
): string | null {
  if (snmp?.type === 'wired' && wiredHubId) return wiredHubId;
  return gatewayId ?? wiredHubId;
}

export function wiredEdge(
  from: string,
  to: string,
  label: string,
  vlan: { id: string; label: string },
): TopologyEdge {
  return edge(from, to, 'wired', label, vlan);
}

export const isWifiCapableRouter = looksLikeWifiAp;
export const resolveRouterUplinkParent = (
  _router: Device,
  gatewayId: string,
  wiredHubId: string | null,
  wifiCapable: boolean,
): string => (wifiCapable ? gatewayId : wiredHubId && wiredHubId !== _router.id ? wiredHubId : gatewayId);

export { lookupSnmp };
