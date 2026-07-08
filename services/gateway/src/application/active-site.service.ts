import type { AppConfig } from '@netscanner/config';
import { mergeSiteIntegrations } from '@netscanner/config';
import {
  LEGACY_DEFAULT_SITE_ID,
  type ActiveSiteResponse,
  type NetworkSite,
  type SiteIntegrations,
  type UpdateSiteRequest,
} from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import { collectNetworkObservation } from '@netscanner/os-abstraction';
import type { ISiteRepository } from '@netscanner/inventory';
import { ResolveActiveSiteUseCase } from '@netscanner/inventory';

export interface ActiveSiteState {
  site: NetworkSite | null;
  action: ActiveSiteResponse['action'];
  confidence: number | null;
  vpnDetected: boolean;
  locked: boolean;
  candidates: ActiveSiteResponse['candidates'];
  observation?: ActiveSiteResponse['observation'];
}

/** Tracks the active network site, manual lock, and per-site config overrides. */
export class ActiveSiteService {
  private site: NetworkSite | null = null;
  private lockedSiteId: string | null = null;
  private pendingConfirm = false;
  private lastObservation: ActiveSiteResponse['observation'];
  private lastAction: ActiveSiteResponse['action'] = 'match';
  private lastConfidence: number | null = null;
  private lastCandidates: ActiveSiteResponse['candidates'] = [];

  private readonly resolver: ResolveActiveSiteUseCase;

  constructor(
    private readonly sites: ISiteRepository,
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly routerIdProbe?: () => Promise<string | null>,
  ) {
    this.resolver = new ResolveActiveSiteUseCase(sites, config);
  }

  getActiveSite(): NetworkSite | null {
    return this.site;
  }

  getActiveSiteId(): string | null {
    return this.site?.id ?? null;
  }

  isLocked(): boolean {
    return this.lockedSiteId != null;
  }

  needsConfirmation(): boolean {
    return this.pendingConfirm && !this.lockedSiteId;
  }

  effectiveConfig(): AppConfig {
    if (!this.site?.integrations) return this.config;
    return mergeSiteIntegrations(this.config, this.site.integrations);
  }

  state(): ActiveSiteState {
    return {
      site: this.site,
      action: this.lastAction,
      confidence: this.lastConfidence,
      vpnDetected: this.lastObservation?.vpnDetected ?? false,
      locked: this.lockedSiteId != null,
      candidates: this.lastCandidates,
      observation: this.lastObservation,
    };
  }

  async initialize(): Promise<NetworkSite | null> {
    return this.refresh();
  }

  async refresh(): Promise<NetworkSite | null> {
    const routerId = this.routerIdProbe ? await this.routerIdProbe() : null;
    const cfg = this.effectiveConfig();
    const observation = await collectNetworkObservation({
      extraCidrs: cfg.SCAN_CIDRS,
      routerId,
      includeGeo: true,
    });
    this.lastObservation = observation;

    const result = await this.resolver.resolve(observation, {
      lockedSiteId: this.lockedSiteId,
    });

    // Migration: adopt empty default site instead of auto-creating a duplicate on first boot.
    if (result.action === 'create') {
      const legacy = await this.sites.findById(LEGACY_DEFAULT_SITE_ID);
      if (legacy?.isDefault && !legacy.fingerprint.gatewayIp) {
        this.site = await this.resolver.touchSite(legacy, observation);
        this.lastAction = 'match';
        this.lastConfidence = 1;
        this.lastCandidates = [];
        this.pendingConfirm = false;
        this.logger.info({ siteId: this.site.id }, 'adopted legacy default site for current network');
        return this.site;
      }
    }

    this.lastAction = result.action;
    this.lastConfidence = result.confidence;
    this.lastCandidates = result.candidates;
    this.pendingConfirm = result.action === 'confirm';

    if (result.site) {
      this.site = await this.resolver.touchSite(result.site, observation);
      this.logger.info(
        { siteId: this.site.id, siteName: this.site.name, action: result.action, vpn: observation.vpnDetected },
        'active network site resolved',
      );
    } else {
      this.site = null;
      this.logger.warn({ action: result.action, vpn: observation.vpnDetected }, 'network site unresolved');
    }

    return this.site;
  }

  async confirmSite(siteId: string): Promise<NetworkSite | null> {
    const picked = await this.sites.findById(siteId);
    if (!picked || !this.lastObservation) return null;
    this.site = await this.resolver.touchSite(picked, this.lastObservation);
    this.pendingConfirm = false;
    this.lastAction = 'match';
    this.lastConfidence = 1;
    return this.site;
  }

  async lockSite(siteId: string | null): Promise<void> {
    this.lockedSiteId = siteId;
    if (siteId) {
      const locked = await this.sites.findById(siteId);
      if (locked) {
        this.site = locked;
        this.pendingConfirm = false;
        this.lastAction = 'locked';
      }
    } else {
      await this.refresh();
    }
  }

  async updateSite(siteId: string, patch: UpdateSiteRequest): Promise<NetworkSite | null> {
    const existing = await this.sites.findById(siteId);
    if (!existing) return null;
    const next: NetworkSite = {
      ...existing,
      name: patch.name ?? existing.name,
      integrations: patch.integrations
        ? ({ ...existing.integrations, ...patch.integrations } as SiteIntegrations)
        : existing.integrations,
    };
    await this.sites.save(next);
    if (this.site?.id === siteId) this.site = next;
    return next;
  }

  async listSites(): Promise<NetworkSite[]> {
    return this.sites.list();
  }

  async deleteSite(siteId: string): Promise<boolean> {
    if (siteId === LEGACY_DEFAULT_SITE_ID) {
      throw new Error('cannot delete the default site');
    }
    if (this.lockedSiteId === siteId || this.site?.id === siteId) {
      throw new Error('cannot delete the active site — lock another site first');
    }
    const existing = await this.sites.findById(siteId);
    if (!existing) return false;
    await this.sites.delete(siteId);
    this.logger.info({ siteId, name: existing.name }, 'network site deleted');
    return true;
  }
}
