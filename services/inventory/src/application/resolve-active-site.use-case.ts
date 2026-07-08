import { v4 as uuid } from 'uuid';
import type {
  ActiveSiteResponse,
  NetworkFingerprint,
  NetworkSite,
} from '@netscanner/contracts';
import type { AppConfig } from '@netscanner/config';
import type { ISiteRepository } from '../domain/site-repository.js';
import { slugifySiteName, suggestSiteName } from '../domain/site-repository.js';
import { mergeFingerprints, rankSiteMatches } from '../domain/site-matcher.js';

export interface ResolveSiteResult {
  site: NetworkSite | null;
  action: ActiveSiteResponse['action'];
  confidence: number | null;
  candidates: ActiveSiteResponse['candidates'];
}

export class ResolveActiveSiteUseCase {
  constructor(
    private readonly sites: ISiteRepository,
    private readonly config: AppConfig,
  ) {}

  async resolve(
    observation: NetworkFingerprint,
    opts?: { lockedSiteId?: string | null; skipAutoCreate?: boolean },
  ): Promise<ResolveSiteResult> {
    if (opts?.lockedSiteId) {
      const locked = await this.sites.findById(opts.lockedSiteId);
      if (locked) {
        return { site: locked, action: 'locked', confidence: 1, candidates: [] };
      }
    }

    const all = await this.sites.list();
    const ranked = rankSiteMatches(observation, all, this.config);
    const best = ranked[0];
    const second = ranked[1];

    if (best && best.score >= this.config.SITE_MATCH_THRESHOLD) {
      return {
        site: best.site,
        action: 'match',
        confidence: best.score,
        candidates: ranked.slice(0, 3),
      };
    }

    const ambiguous =
      best &&
      best.score >= this.config.SITE_AMBIGUOUS_THRESHOLD &&
      second &&
      second.score >= this.config.SITE_AMBIGUOUS_THRESHOLD &&
      best.score - second.score < 0.12;

    if (ambiguous) {
      return {
        site: null,
        action: 'confirm',
        confidence: best.score,
        candidates: ranked.slice(0, 3),
      };
    }

    if (!this.config.SITE_AUTO_CREATE || opts?.skipAutoCreate) {
      return { site: null, action: 'confirm', confidence: best?.score ?? null, candidates: ranked.slice(0, 3) };
    }

    const name = suggestSiteName(observation);
    let slug = slugifySiteName(name);
    if (await this.sites.findBySlug(slug)) slug = `${slug}-${Date.now().toString(36)}`;

    const repo = this.sites as ISiteRepository & {
      create?: (insert: {
        name: string;
        slug: string;
        fingerprint: NetworkFingerprint;
      }) => Promise<NetworkSite>;
    };
    const site = repo.create
      ? await repo.create({ name, slug, fingerprint: observation })
      : await this.createInline(name, slug, observation);

    return { site, action: 'create', confidence: null, candidates: [] };
  }

  async touchSite(site: NetworkSite, observation: NetworkFingerprint): Promise<NetworkSite> {
    const next: NetworkSite = {
      ...site,
      lastSeenAt: new Date().toISOString(),
      fingerprint: mergeFingerprints(site.fingerprint, observation),
    };
    await this.sites.save(next);
    return next;
  }

  private async createInline(
    name: string,
    slug: string,
    fingerprint: NetworkFingerprint,
  ): Promise<NetworkSite> {
    const now = new Date().toISOString();
    const site: NetworkSite = {
      id: uuid(),
      name,
      slug,
      createdAt: now,
      lastSeenAt: now,
      fingerprint,
      integrations: {},
      isDefault: false,
    };
    await this.sites.save(site);
    return site;
  }
}
