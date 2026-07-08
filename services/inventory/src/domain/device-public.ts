import type { Device } from '@netscanner/contracts';

/** Device as stored internally (includes router scrape password). */
export type StoredDevice = Device & { routerScrapePassword?: string | null };

export function toPublicDevice(device: StoredDevice): Device {
  const { routerScrapePassword, ...rest } = device as StoredDevice & { routerScrapePassword?: string | null };
  return {
    ...rest,
    routerScrapePasswordSet: Boolean(routerScrapePassword),
  };
}

export function isRouterPanelCandidate(device: Device): boolean {
  if (['router', 'switch', 'access-point', 'firewall'].includes(device.deviceType)) return true;
  return device.services.some((s) => s.port === 80 || s.port === 443);
}
