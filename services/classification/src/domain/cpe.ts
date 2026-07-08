import type { OsGuess, ServiceInfo } from '@netscanner/contracts';

/** A simplified CPE 2.3 tuple used to match a device against a CVE database. */
export interface Cpe {
  part: 'a' | 'o' | 'h';
  vendor: string;
  product: string;
  version: string | null;
}

export interface CpeIdentity {
  brand: string | null;
  model: string | null;
  os: OsGuess | null;
  services: readonly ServiceInfo[];
}

/** CPE token: lowercase, spaces→underscore, strip legal suffixes and noise. */
export function cpeToken(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/,?\s*(inc\.?|llc|ltd\.?|limited|corporation|co\.?)\b/g, '')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

/** Map an inferred/detected OS name to (vendor, product) CPE components. */
function osToCpe(os: OsGuess): { vendor: string; product: string } | null {
  const text = `${os.name ?? ''} ${os.family ?? ''}`.toLowerCase();
  if (/ios|iphone|ipad/.test(text)) return { vendor: 'apple', product: 'iphone_os' };
  if (/watchos/.test(text)) return { vendor: 'apple', product: 'watchos' };
  if (/mac ?os|os x|macos/.test(text)) return { vendor: 'apple', product: 'macos' };
  if (/windows/.test(text)) return { vendor: 'microsoft', product: 'windows' };
  if (/android/.test(text)) return { vendor: 'google', product: 'android' };
  if (/free ?bsd/.test(text)) return { vendor: 'freebsd', product: 'freebsd' };
  if (/linux/.test(text)) return { vendor: 'linux', product: 'linux_kernel' };
  return null;
}

/** Known service-product → (vendor, product) normalizations for CPE. */
const SERVICE_CPE: { match: RegExp; vendor: string; product: string }[] = [
  { match: /openssh/i, vendor: 'openbsd', product: 'openssh' },
  { match: /nginx/i, vendor: 'nginx', product: 'nginx' },
  { match: /apache/i, vendor: 'apache', product: 'http_server' },
  { match: /lighttpd/i, vendor: 'lighttpd', product: 'lighttpd' },
  { match: /dropbear/i, vendor: 'dropbear_ssh_project', product: 'dropbear_ssh' },
];

/**
 * Build candidate CPEs from a device's resolved identity: its OS, its brand/model
 * hardware, and the products behind its open services. Pure & deterministic.
 * Version is kept when known so a resolver can range-match; null → fuzzy match.
 */
export function buildCpes(identity: CpeIdentity): Cpe[] {
  const cpes: Cpe[] = [];

  if (identity.os) {
    const mapped = osToCpe(identity.os);
    if (mapped) cpes.push({ part: 'o', ...mapped, version: identity.os.version ?? null });
  }

  if (identity.brand && identity.model) {
    cpes.push({
      part: 'h',
      vendor: cpeToken(identity.brand),
      product: cpeToken(identity.model),
      version: null,
    });
  }

  for (const svc of identity.services) {
    const product = svc.product;
    if (!product) continue;
    const known = SERVICE_CPE.find((s) => s.match.test(product));
    cpes.push(
      known
        ? { part: 'a', vendor: known.vendor, product: known.product, version: svc.version ?? null }
        : { part: 'a', vendor: cpeToken(product), product: cpeToken(product), version: svc.version ?? null },
    );
  }

  // De-dupe by part:vendor:product:version.
  const seen = new Set<string>();
  return cpes.filter((c) => {
    const k = `${c.part}:${c.vendor}:${c.product}:${c.version ?? ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function formatCpe(c: Cpe): string {
  return `cpe:2.3:${c.part}:${c.vendor}:${c.product}:${c.version ?? '*'}`;
}
