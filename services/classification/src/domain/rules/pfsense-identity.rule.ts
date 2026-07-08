import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

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

function normalizeMac(mac: string | null | undefined): string | null {
  if (!mac) return null;
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, '');
  return hex.length === 12 ? hex : null;
}

function asRows<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function isWanLike(name: string | null | undefined, descr: string | null | undefined): boolean {
  const hay = `${name ?? ''} ${descr ?? ''}`.toUpperCase();
  return /\bWAN\b/.test(hay) || hay.includes('WAN_');
}

function isValidPhysMac(mac: string | null | undefined): boolean {
  const n = normalizeMac(mac);
  if (!n) return false;
  // pfSense virtual ifaces report names like ovpnc1 / tun_wg2 as "mac".
  return /^[0-9a-f]{12}$/.test(n);
}

function matchesSelfIface(input: ClassificationInput, ifaces: PfSenseIfaceSignal[]): boolean {
  const mac = normalizeMac(input.mac);
  for (const iface of ifaces) {
    if (iface.ipaddr && iface.ipaddr === input.ip) return true;
    if (mac && isValidPhysMac(iface.mac) && normalizeMac(iface.mac) === mac) return true;
  }
  return false;
}

function isWanNextHop(input: ClassificationInput, gateways: PfSenseGatewaySignal[], ifaces: PfSenseIfaceSignal[]): boolean {
  for (const gw of gateways) {
    if (!gw.gateway || gw.gateway !== input.ip) continue;
    if (gw.interface && isWanLike(gw.interface, gw.name)) return true;
    if (gw.name && isWanLike(gw.name, null)) return true;
  }

  // DHCP WANs often expose gateway="dynamic" with no resolvable next-hop; treat
  // non-self hosts on a WAN* lease / .1 of a WAN handoff as ISP CPE / modem.
  const leaseIface = String(input.signals['pfsenseInterface'] ?? input.signals['routerInterface'] ?? '');
  if (isWanLike(leaseIface, null) && !matchesSelfIface(input, ifaces)) {
    if (input.ip.endsWith('.1')) return true;
  }
  return false;
}

/**
 * Prefer pfSense self-interface / WAN-gateway signals already attached to devices.
 * - MAC/IP matching `pfsenseInterfaces` → firewall (pfSense NIC, not a leaf client)
 * - WAN next-hop / WAN* `.1` CPE → router (ISP modem)
 */
export class PfSenseIdentityRule implements ClassificationRule {
  readonly name = 'pfsense-identity';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const ifaces = asRows<PfSenseIfaceSignal>(input.signals['pfsenseInterfaces']);
    const gateways = asRows<PfSenseGatewaySignal>(input.signals['pfsenseGateways']);
    if (ifaces.length === 0 && gateways.length === 0) return [];

    if (matchesSelfIface(input, ifaces)) {
      return [
        {
          deviceType: 'firewall',
          weight: 0.95,
          reason: 'MAC/IP matches a pfSense interface (self NIC)',
        },
      ];
    }

    if (isWanNextHop(input, gateways, ifaces)) {
      const leaseIface = String(input.signals['pfsenseInterface'] ?? input.signals['routerInterface'] ?? '');
      const label = leaseIface && isWanLike(leaseIface, null) ? leaseIface : 'WAN';
      return [
        {
          deviceType: 'router',
          weight: 0.9,
          reason: `WAN gateway / ISP CPE on ${label}`,
        },
      ];
    }

    return [];
  }
}
