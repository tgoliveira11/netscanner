import type { DeviceType } from '@netscanner/contracts';

/** Emoji glyph + human label per device type for compact, icon-free rendering. */
export const DEVICE_META: Record<DeviceType, { icon: string; label: string }> = {
  router: { icon: '🛜', label: 'Router' },
  switch: { icon: '🔀', label: 'Switch' },
  'access-point': { icon: '📶', label: 'Access Point' },
  firewall: { icon: '🧱', label: 'Firewall' },
  computer: { icon: '🖥️', label: 'Computer' },
  laptop: { icon: '💻', label: 'Laptop' },
  phone: { icon: '📱', label: 'Phone' },
  tablet: { icon: '📱', label: 'Tablet' },
  wearable: { icon: '⌚', label: 'Wearable' },
  printer: { icon: '🖨️', label: 'Printer' },
  nas: { icon: '🗄️', label: 'NAS' },
  tv: { icon: '📺', label: 'TV' },
  'streaming-device': { icon: '📺', label: 'Streaming' },
  'game-console': { icon: '🎮', label: 'Console' },
  camera: { icon: '📷', label: 'Camera' },
  'smart-speaker': { icon: '🔊', label: 'Speaker' },
  'smart-home': { icon: '🏠', label: 'Smart Home' },
  iot: { icon: '📟', label: 'IoT' },
  server: { icon: '🖧', label: 'Server' },
  'virtual-machine': { icon: '🧩', label: 'VM' },
  unknown: { icon: '❔', label: 'Unknown' },
};

export function deviceMeta(type: string) {
  return DEVICE_META[type as DeviceType] ?? DEVICE_META.unknown;
}

/** Compact glyph for the connection type, shown in the device table. */
export function connectionGlyph(type: string): string {
  return type === 'wifi' ? '📶' : type === 'wired' ? '🔌' : '';
}

export function confidenceColor(c: number): string {
  if (c >= 0.7) return 'text-good';
  if (c >= 0.4) return 'text-warn';
  return 'text-muted';
}
