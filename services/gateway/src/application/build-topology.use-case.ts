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
const MAC_SHARING_PREFIX = '192.168.64.';

interface PfSenseIfaceSignal {
  name?: string | null;
  descr?: string | null;
  ipaddr?: string | null;
  mac?: string | null;
}

interface PfSenseGatewaySignal {
  name?: string | null;
  gateway?: string | null;
  srcip?: string | null;
  interface?: string | null;
}

/**
 * Builds a VLAN-centric home topology from inventory + pfSense interface tags +
 * optional OpenWrt wireless probes:
 *
 *   ISP modem(s)  →  pfSense (gateway)
 *     ├── VLAN40  → wired switch/router
 *     ├── VLAN10   → WiFi AP → clients
 *     ├── VLAN30  → WiFi AP → clients
 *     ├── VLAN20    → WiFi AP → clients
 *     └── Mac host   → Mac Internet Sharing clients (192.168.64.x)
 *
 * VPN overlays stay out of the main tree. pfSense self-NICs are never leaf clients.
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

    const wanModems = pickWanModems(devices, gateway);
    for (const modem of wanModems) {
      const vlan = resolveDeviceVlan(modem);
      const label = modemLabel(modem);
      // Edge from modem → gateway (child→parent), same convention as LAN tree.
      edges.push(edge(gateway.id, modem.id, 'wired', label, { id: vlan.id, label: vlan.label || label }));
      nodes.push({ id: modem.id, role: 'wan', tier: 0, wifiCapable: false });
      placed.add(modem.id);
    }

    nodes.push({ id: gateway.id, role: 'gateway', tier: wanModems.length > 0 ? 1 : 0, wifiCapable: false });
    placed.add(gateway.id);

    const switchDevice = pickWiredInfra(devices, gateway, eligibility, this.config, this.connectionSource);
    const wifiAps = pickWifiAccessPoints(devices, gateway, eligibility, wireless, scrapeTargets);
    const macShareHost = pickMacSharingHost(devices, localIfaces);

    if (switchDevice) {
      const vlan = resolveDeviceVlan(switchDevice);
      edges.push(edge(switchDevice.id, gateway.id, 'wired', 'infra', vlan));
      nodes.push({
        id: switchDevice.id,
        role: 'wired-router',
        tier: wanModems.length > 0 ? 2 : 1,
        wifiCapable: false,
      });
      placed.add(switchDevice.id);
    }

    for (const ap of wifiAps) {
      const vlan = resolveDeviceVlan(ap);
      edges.push(edge(ap.id, gateway.id, 'wired', 'uplink', vlan));
      nodes.push({
        id: ap.id,
        role: 'wifi-ap',
        tier: wanModems.length > 0 ? 3 : 2,
        wifiCapable: true,
      });
      placed.add(ap.id);
    }

    if (macShareHost && !placed.has(macShareHost.id) && macShareHost.id !== gateway.id) {
      const vlan = resolveDeviceVlan(macShareHost);
      // Hang the sharing Mac under the normal LAN tree (gateway / AP / switch) first,
      // so Mac Sharing clients can attach to it as a mid-tier branch.
      const snmp = lookupSnmp(macShareHost, this.connectionSource);
      const apByVlan = new Map<string, Device>();
      for (const ap of wifiAps) {
        const v = resolveDeviceVlan(ap);
        if (!apByVlan.has(v.id)) apByVlan.set(v.id, ap);
      }
      const attachment = resolveClientAttachment({
        device: macShareHost,
        vlan,
        snmp,
        switchDevice,
        gateway,
        wifiAps,
        apByVlan,
        wireless,
      });
      if (attachment && attachment.parentId !== macShareHost.id) {
        edges.push(
          edge(
            macShareHost.id,
            attachment.parentId,
            attachment.kind,
            attachment.label,
            vlan,
            attachment.ssid,
          ),
        );
      } else {
        edges.push(edge(macShareHost.id, gateway.id, 'wired', 'lan', vlan));
      }
      nodes.push({
        id: macShareHost.id,
        role: 'endpoint',
        tier: wanModems.length > 0 ? 3 : 2,
        wifiCapable: macShareHost.connectionType === 'wifi',
      });
      placed.add(macShareHost.id);
    }

    const apByVlan = new Map<string, Device>();
    for (const ap of wifiAps) {
      const vlan = resolveDeviceVlan(ap);
      if (!apByVlan.has(vlan.id)) apByVlan.set(vlan.id, ap);
    }

    for (const device of devices) {
      if (placed.has(device.id)) continue;
      if (isPfSenseSelfNic(device)) continue;
      if (isVpnOverlayIp(device.ip)) continue;

      // Mac Internet Sharing clients hang under the sharing Mac, not pfSense.
      if (isMacSharingIp(device.ip)) {
        if (!macShareHost || device.id === macShareHost.id) continue;
        if (isLocalScannerDevice(device, localIfaces)) continue;
        edges.push(
          edge(device.id, macShareHost.id, 'wired', 'mac-sharing', {
            id: 'MAC_SHARING',
            label: 'Mac Sharing',
          }),
        );
        nodes.push({
          id: device.id,
          role: 'endpoint',
          tier: wanModems.length > 0 ? 4 : 3,
          wifiCapable: device.connectionType === 'wifi',
        });
        placed.add(device.id);
        continue;
      }

      if (!isTopologyClient(device, gateway, localIfaces)) continue;

      const vlan = resolveDeviceVlan(device);
      if (isWanOrUnusedSegment(vlan.id)) continue;

      const snmp = lookupSnmp(device, this.connectionSource);
      const attachment = resolveClientAttachment({
        device,
        vlan,
        snmp,
        switchDevice,
        gateway,
        wifiAps,
        apByVlan,
        wireless,
      });
      if (!attachment || attachment.parentId === device.id) continue;

      edges.push(
        edge(device.id, attachment.parentId, attachment.kind, attachment.label, vlan, attachment.ssid),
      );
      const baseTier = wanModems.length > 0;
      nodes.push({
        id: device.id,
        role: 'endpoint',
        tier:
          attachment.kind === 'wifi'
            ? baseTier
              ? 4
              : 3
            : switchDevice && attachment.parentId === switchDevice.id
              ? baseTier
                ? 3
                : 2
              : baseTier
                ? 4
                : 3,
        wifiCapable: attachment.wifiCapable,
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
    (d) =>
      (d.deviceType === 'router' || d.deviceType === 'firewall') &&
      !isLocalScannerDevice(d, localIfaces) &&
      !isWanModemCandidate(d) &&
      !isMacSharingIp(d.ip),
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
    routers.find((d) => d.ip.endsWith('.1') && !isVpnOverlayIp(d.ip) && !isWanHandoffIp(d.ip)) ??
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
    if (isPfSenseSelfNic(d)) return false;
    if (isWanModemCandidate(d)) return false;
    if (isVpnOverlayIp(d.ip) || isMacSharingIp(d.ip) || isWanHandoffIp(d.ip)) return false;
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
    if (isPfSenseSelfNic(d)) return false;
    if (isWanModemCandidate(d)) return false;
    if (isVpnOverlayIp(d.ip) || isMacSharingIp(d.ip) || isWanHandoffIp(d.ip)) return false;
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

/**
 * ISP CPE / modem nodes upstream of pfSense.
 * Prefer WAN gateway next-hop, else non-self hosts on WAN* with `.1` (typical CPE).
 */
export function pickWanModems(devices: Device[], gateway: Device): Device[] {
  const out: Device[] = [];
  const seen = new Set<string>();

  for (const device of devices) {
    if (device.id === gateway.id) continue;
    if (isPfSenseSelfNic(device)) continue;
    if (isVpnOverlayIp(device.ip) || isMacSharingIp(device.ip)) continue;
    if (!isWanModemCandidate(device)) continue;
    if (seen.has(device.id)) continue;
    seen.add(device.id);
    out.push(device);
  }

  return out.sort((a, b) => a.ip.localeCompare(b.ip));
}

export function isWanModemCandidate(device: Device): boolean {
  if (isPfSenseSelfNic(device)) return false;

  const gateways = asRows<PfSenseGatewaySignal>(device.signals?.pfsenseGateways);
  for (const gw of gateways) {
    if (gw.gateway && gw.gateway === device.ip && isWanLikeName(gw.name, gw.interface)) {
      return true;
    }
  }

  const leaseIface = String(device.signals?.pfsenseInterface ?? device.signals?.routerInterface ?? '');
  if (isWanLikeName(leaseIface, null) && !isPfSenseSelfNic(device)) {
    if (device.ip.endsWith('.1') || device.deviceType === 'router') return true;
  }

  // Heuristic when VLAN/lease tags are missing but the host is classic CPE .1 on a
  // handoff segment and not a pfSense iface IP.
  if (isWanHandoffIp(device.ip) && device.ip.endsWith('.1') && !isPfSenseSelfNic(device)) {
    return true;
  }

  return false;
}

/**
 * Prefer the inventory device that shares a primary LAN IP with the agent host,
 * else the local bridge100 / Mac Sharing gateway address itself.
 */
export function pickMacSharingHost(
  devices: Device[],
  localIfaces: LocalInterface[],
): Device | null {
  const hasSharingNet =
    localIfaces.some((i) => i.address.startsWith(MAC_SHARING_PREFIX) || /bridge/i.test(i.name)) ||
    devices.some((d) => isMacSharingIp(d.ip));
  if (!hasSharingNet) return null;

  // Prefer a non-sharing-subnet address of the scanner that also appears in inventory
  // (the Mac on the home LAN). Match by LAN IP first — WiFi MACs are often randomized
  // and will not equal the bridge100 MAC.
  const lanLocalIps = new Set(
    localIfaces
      .filter((i) => !isMacSharingIp(i.address) && !isVpnOverlayIp(i.address) && !/(bridge|utun|awdl)/i.test(i.name))
      .map((i) => i.address),
  );
  const localMacs = new Set(
    localIfaces.map((i) => normalizeMac(i.mac)).filter((m): m is string => Boolean(m)),
  );

  const lanHost =
    devices.find(
      (d) =>
        !isMacSharingIp(d.ip) &&
        !isVpnOverlayIp(d.ip) &&
        !isWanHandoffIp(d.ip) &&
        (lanLocalIps.has(d.ip) || (d.mac != null && localMacs.has(normalizeMac(d.mac) ?? ''))),
    ) ?? null;
  if (lanHost) return lanHost;

  // Fallback: the Mac Sharing gateway (.1 / bridge addr) as the parent node.
  return (
    devices.find((d) => isLocalScannerDevice(d, localIfaces) && isMacSharingIp(d.ip)) ??
    devices.find((d) => d.ip === `${MAC_SHARING_PREFIX}1`) ??
    null
  );
}

export function isTopologyClient(
  device: Device,
  gateway: Device,
  localIfaces: LocalInterface[],
): boolean {
  if (device.id === gateway.id) return false;
  if (isLocalScannerDevice(device, localIfaces)) return false;
  if (isPfSenseSelfNic(device)) return false;
  if (isWanModemCandidate(device)) return false;
  if (isVpnOverlayIp(device.ip)) return false;
  if (isMacSharingIp(device.ip)) return false;
  if (isWanHandoffIp(device.ip)) return false;
  // Router/AP nodes are placed separately; never treat them as leaf clients.
  if (
    device.deviceType === 'router' ||
    device.deviceType === 'access-point' ||
    device.deviceType === 'switch' ||
    device.deviceType === 'firewall'
  ) {
    return false;
  }
  return true;
}

/** @deprecated Prefer isVpnOverlayIp / isMacSharingIp / isWanHandoffIp / isWanModemCandidate. */
export function isWanOrSideIp(ip: string): boolean {
  return isWanHandoffIp(ip) || isMacSharingIp(ip) || isVpnOverlayIp(ip);
}

export function isVpnOverlayIp(ip: string): boolean {
  return ip.startsWith('10.8.') || ip.startsWith('10.14.');
}

export function isMacSharingIp(ip: string): boolean {
  return ip.startsWith(MAC_SHARING_PREFIX);
}

/** Typical ISP handoff / CPE management segment (not auto-scanned). */
export function isWanHandoffIp(ip: string): boolean {
  return ip.startsWith('192.168.0.');
}

export function isWanOrUnusedSegment(vlanId: string): boolean {
  const id = vlanId.toUpperCase();
  if (id.startsWith('WAN')) return true;
  if (id === 'LAN') return true; // no-carrier legacy segment
  if (id === 'TRUNK') return true;
  return false;
}

export function isPfSenseSelfNic(device: Device): boolean {
  const ifaces = asRows<PfSenseIfaceSignal>(device.signals?.pfsenseInterfaces);
  if (ifaces.length === 0) return false;
  const mac = normalizeMac(device.mac);
  for (const iface of ifaces) {
    if (iface.ipaddr && iface.ipaddr === device.ip) return true;
    if (mac && isPhysMac(iface.mac) && normalizeMac(iface.mac) === mac) return true;
  }
  return false;
}

function isPhysMac(mac: string | null | undefined): boolean {
  const n = normalizeMac(mac);
  return Boolean(n && /^[0-9a-f]{12}$/.test(n));
}

function isWanLikeName(name: string | null | undefined, descr?: string | null): boolean {
  const hay = `${name ?? ''} ${descr ?? ''}`.toUpperCase();
  return /\bWAN\b/.test(hay) || hay.includes('WAN_');
}

function asRows<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function modemLabel(device: Device): string {
  const iface = String(device.signals?.pfsenseInterface ?? device.signals?.routerInterface ?? '');
  if (iface && isWanLikeName(iface, null)) {
    // e.g. WAN_ISP → Modem WAN_ISP
    return iface.startsWith('Modem') ? iface : `Modem ${iface}`;
  }
  return 'Modem';
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
    if (edge.vlan === 'MAC_SHARING') continue;
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

/**
 * Decide where a leaf client hangs in the tree.
 *
 * Priority:
 * 1. SNMP BRIDGE-MIB wired → physical switch (authoritative L2)
 * 2. SNMP wifi / device wifi → AP on same VLAN (or matching /24)
 * 3. Device wired without SNMP → switch only on INFRA / switch subnet, else gateway
 * 4. Unknown → AP on VLAN if any, else gateway
 */
export function resolveClientAttachment(input: {
  device: Device;
  vlan: { id: string; label: string };
  snmp: ReturnType<IConnectionSource['lookupByMac']>;
  switchDevice: Device | null;
  gateway: Device;
  wifiAps: Device[];
  apByVlan: Map<string, Device>;
  wireless: Awaited<ReturnType<typeof probeOpenWrtWireless>>;
}): {
  parentId: string;
  kind: TopologyEdge['kind'];
  label: string;
  ssid?: string;
  wifiCapable: boolean;
} | null {
  const { device, vlan, snmp, switchDevice, gateway, wifiAps, apByVlan, wireless } = input;

  // Authoritative: MAC learned on a switch access port → hang under the switch.
  if (snmp?.type === 'wired' && switchDevice) {
    return {
      parentId: switchDevice.id,
      kind: 'wired',
      label: snmp.ifName ?? 'wired',
      wifiCapable: device.connectionType === 'wifi',
    };
  }

  const isWifi = snmp?.type === 'wifi' || device.connectionType === 'wifi';
  const isWired = snmp?.type === 'wired' || device.connectionType === 'wired';

  if (isWifi) {
    const ap = apByVlan.get(vlan.id) ?? apForIp(device.ip, wifiAps);
    const assocSsid = findClientSsid(device, wireless);
    return {
      parentId: ap?.id ?? gateway.id,
      kind: 'wifi',
      label: assocSsid ?? 'wifi',
      ...(assocSsid ? { ssid: assocSsid } : {}),
      wifiCapable: true,
    };
  }

  if (isWired) {
    if (
      switchDevice &&
      (vlan.id === 'VLAN40' || sameIpv4Slash24(device.ip, switchDevice.ip))
    ) {
      return {
        parentId: switchDevice.id,
        kind: 'wired',
        label: snmp?.ifName ?? 'wired',
        wifiCapable: false,
      };
    }
    return {
      parentId: gateway.id,
      kind: 'wired',
      label: snmp?.ifName ?? 'wired',
      wifiCapable: false,
    };
  }

  const ap = apByVlan.get(vlan.id);
  return {
    parentId: ap?.id ?? gateway.id,
    kind: ap ? 'wifi' : 'wired',
    label: ap ? 'wifi' : 'lan',
    wifiCapable: Boolean(ap),
  };
}

/** @deprecated kept for existing tests — prefer resolveClientAttachment */
export function resolveWiredParent(
  _device: Device,
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
