/**
 * Curated subset of the IEEE OUI registry (first 3 octets, no separators → vendor).
 * Covers the most common consumer/enterprise vendors so classification works out
 * of the box. For full coverage, OuiLookup.loadFromFile() can ingest the complete
 * IEEE `oui.csv` at runtime without code changes (OCP).
 */
export const OUI_TABLE: Readonly<Record<string, string>> = {
  // Apple
  '3c0754': 'Apple',
  f0d1a9: 'Apple',
  a45e60: 'Apple',
  '001451': 'Apple',
  ac1f74: 'Apple',
  // Samsung
  '002566': 'Samsung Electronics',
  '5001bb': 'Samsung Electronics',
  fcc734: 'Samsung Electronics',
  // Google / Nest
  '3c5ab4': 'Google',
  f4f5d8: 'Google',
  '54600f': 'Google Nest',
  // Amazon
  '447c7f': 'Amazon Technologies',
  fca667: 'Amazon Technologies',
  '68370e': 'Amazon Technologies',
  // Raspberry Pi
  b827eb: 'Raspberry Pi Foundation',
  dca632: 'Raspberry Pi Trading',
  e45f01: 'Raspberry Pi Trading',
  // Intel
  '001e67': 'Intel',
  a0a8cd: 'Intel',
  '8c1645': 'Intel',
  // TP-Link
  '5091e3': 'TP-Link',
  '54af97': 'TP-Link',
  ac84c6: 'TP-Link',
  // Cisco / Meraki
  '00000c': 'Cisco Systems',
  '000142': 'Cisco Systems',
  e0553d: 'Cisco Meraki',
  // Ubiquiti
  '0418d6': 'Ubiquiti Networks',
  fcecda: 'Ubiquiti Networks',
  '245a4c': 'Ubiquiti Networks',
  // Netgear
  '000fb5': 'Netgear',
  '20e52a': 'Netgear',
  // AVM (FritzBox)
  '3810d5': 'AVM',
  c80e14: 'AVM',
  // Sonos
  '000e58': 'Sonos',
  '5cae7a': 'Sonos',
  // Philips Hue
  '001788': 'Philips Lighting (Hue)',
  ecb5fa: 'Philips Lighting (Hue)',
  // Espressif (ESP8266/ESP32 IoT)
  '5ccf7f': 'Espressif (ESP)',
  '240ac4': 'Espressif (ESP)',
  a4cf12: 'Espressif (ESP)',
  // Sony
  '000ad9': 'Sony',
  f8461c: 'Sony',
  // Microsoft / Xbox
  '000d3a': 'Microsoft',
  '7c1e52': 'Microsoft',
  // HP / printers
  '001321': 'Hewlett Packard',
  '3822e2': 'HP Inc',
  // Brother printers
  '008077': 'Brother Industries',
  '30055c': 'Brother Industries',
};
