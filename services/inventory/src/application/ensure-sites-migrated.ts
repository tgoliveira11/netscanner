import type { NetworkSite } from '@netscanner/contracts';
import { LEGACY_DEFAULT_SITE_ID, NetworkFingerprintSchema } from '@netscanner/contracts';
import type { ISiteRepository } from '../domain/site-repository.js';

/** Ensure the legacy default site exists (migration from pre-site inventory). */
export async function ensureDefaultSite(sites: ISiteRepository): Promise<NetworkSite> {
  let site = await sites.findById(LEGACY_DEFAULT_SITE_ID);
  if (!site) {
    const now = new Date().toISOString();
    site = {
      id: LEGACY_DEFAULT_SITE_ID,
      name: 'Default',
      slug: 'default',
      createdAt: now,
      lastSeenAt: now,
      fingerprint: NetworkFingerprintSchema.parse({}),
      integrations: {},
      isDefault: true,
    };
    await sites.save(site);
  }
  return site;
}
