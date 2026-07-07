import type { DeviceType, ServiceInfo } from '@netscanner/contracts';

/** Extra identity gleaned from application-layer probes (UPnP/HTTP/TLS). */
export interface HostEnrichment {
  hostname?: string | null;
  vendor?: string | null;
  deviceHint?: DeviceType | null;
  /** Raw signals merged into the device record (upnpModel, httpServer, tlsSubject…). */
  signals: Record<string, unknown>;
}

/**
 * Port for post-scan application-layer enrichment. Given a host's open services
 * and discovery signals, adapters actively query the device (UPnP description,
 * HTTP title/Server header, TLS certificate) to extract an exact vendor/model.
 */
export interface IHostEnricher {
  enrich(
    ip: string,
    services: ServiceInfo[],
    signals: Record<string, unknown>,
  ): Promise<HostEnrichment>;
}
