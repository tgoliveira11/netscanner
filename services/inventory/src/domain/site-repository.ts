import type {
  NetworkFingerprint,
  NetworkSite,
  SiteIntegrations,
} from '@netscanner/contracts';

export interface ISiteRepository {
  findById(id: string): Promise<NetworkSite | null>;
  findBySlug(slug: string): Promise<NetworkSite | null>;
  list(): Promise<NetworkSite[]>;
  save(site: NetworkSite): Promise<void>;
  delete(id: string): Promise<void>;
  create(insert: SiteInsert): Promise<NetworkSite>;
}

export interface SiteInsert {
  name: string;
  slug: string;
  fingerprint: NetworkFingerprint;
  integrations?: SiteIntegrations;
  isDefault?: boolean;
}

export function slugifySiteName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48) || 'site';
}

export function suggestSiteName(obs: NetworkFingerprint): string {
  if (obs.geoLabel) return obs.geoLabel;
  if (obs.gatewayIp) return `Network ${obs.gatewayIp}`;
  if (obs.cidrs[0]) return `Network ${obs.cidrs[0]}`;
  return 'New network';
}
