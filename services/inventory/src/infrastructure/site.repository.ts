import { v4 as uuid } from 'uuid';
import type { NetworkSite, NetworkFingerprint } from '@netscanner/contracts';
import { LEGACY_DEFAULT_SITE_ID } from '@netscanner/contracts';
import type { PrismaClient } from '@prisma/client';
import type { ISiteRepository, SiteInsert } from '../domain/site-repository.js';
import { parseSiteFingerprint, parseSiteIntegrations } from '../domain/site-matcher.js';

type SiteRow = {
  id: string;
  name: string;
  slug: string;
  createdAt: Date;
  lastSeenAt: Date;
  fingerprintJson: string;
  integrationsJson: string;
  isDefault: boolean;
};

function toDomain(row: SiteRow): NetworkSite {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    createdAt: row.createdAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    fingerprint: parseSiteFingerprint(row.fingerprintJson),
    integrations: parseSiteIntegrations(row.integrationsJson),
    isDefault: row.isDefault,
  };
}

export class PrismaSiteRepository implements ISiteRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string): Promise<NetworkSite | null> {
    const row = await this.prisma.networkSiteRecord.findUnique({ where: { id } });
    return row ? toDomain(row as SiteRow) : null;
  }

  async findBySlug(slug: string): Promise<NetworkSite | null> {
    const row = await this.prisma.networkSiteRecord.findUnique({ where: { slug } });
    return row ? toDomain(row as SiteRow) : null;
  }

  async list(): Promise<NetworkSite[]> {
    const rows = await this.prisma.networkSiteRecord.findMany({
      orderBy: { lastSeenAt: 'desc' },
    });
    return rows.map((r) => toDomain(r as SiteRow));
  }

  async save(site: NetworkSite): Promise<void> {
    await this.prisma.networkSiteRecord.upsert({
      where: { id: site.id },
      create: {
        id: site.id,
        name: site.name,
        slug: site.slug,
        createdAt: new Date(site.createdAt),
        lastSeenAt: new Date(site.lastSeenAt),
        fingerprintJson: JSON.stringify(site.fingerprint),
        integrationsJson: JSON.stringify(site.integrations ?? {}),
        isDefault: site.isDefault,
      },
      update: {
        name: site.name,
        slug: site.slug,
        lastSeenAt: new Date(site.lastSeenAt),
        fingerprintJson: JSON.stringify(site.fingerprint),
        integrationsJson: JSON.stringify(site.integrations ?? {}),
        isDefault: site.isDefault,
      },
    });
  }

  async delete(id: string): Promise<void> {
    await this.prisma.networkSiteRecord.delete({ where: { id } });
  }

  async create(insert: SiteInsert): Promise<NetworkSite> {
    const now = new Date();
    const site: NetworkSite = {
      id: uuid(),
      name: insert.name,
      slug: insert.slug,
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      fingerprint: insert.fingerprint,
      integrations: insert.integrations ?? {},
      isDefault: insert.isDefault ?? false,
    };
    await this.save(site);
    return site;
  }
}

export class InMemorySiteRepository implements ISiteRepository {
  private readonly sites = new Map<string, NetworkSite>();

  async findById(id: string): Promise<NetworkSite | null> {
    return this.sites.get(id) ?? null;
  }

  async findBySlug(slug: string): Promise<NetworkSite | null> {
    return [...this.sites.values()].find((s) => s.slug === slug) ?? null;
  }

  async list(): Promise<NetworkSite[]> {
    return [...this.sites.values()].sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
  }

  async save(site: NetworkSite): Promise<void> {
    this.sites.set(site.id, site);
  }

  async delete(id: string): Promise<void> {
    this.sites.delete(id);
  }

  async create(insert: SiteInsert): Promise<NetworkSite> {
    const now = new Date().toISOString();
    const site: NetworkSite = {
      id: uuid(),
      name: insert.name,
      slug: insert.slug,
      createdAt: now,
      lastSeenAt: now,
      fingerprint: insert.fingerprint as NetworkFingerprint,
      integrations: insert.integrations ?? {},
      isDefault: insert.isDefault ?? false,
    };
    await this.save(site);
    return site;
  }
}
