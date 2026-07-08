import { describe, expect, it } from 'vitest';
import { extractWifiAssociations, deviceIdByMac } from './wifi-topology.js';
import type { OpenWrtWirelessResult } from './openwrt-wireless-probe.js';

describe('extractWifiAssociations', () => {
  it('flattens assoclist clients per SSID', () => {
    const results: OpenWrtWirelessResult[] = [
      {
        url: 'http://10.0.2.101',
        host: '10.0.2.101',
        ok: true,
        wifiCapable: true,
        radioCount: 1,
        ssids: [
          {
            device: 'wifi0',
            ifname: 'ath0',
            ssid: 'Example-Guest',
            up: true,
            clients: [{ mac: 'aa:bb:cc:dd:ee:01', signal: -51 }],
          },
        ],
      },
    ];
    expect(extractWifiAssociations(results)).toEqual([
      {
        mac: 'aa:bb:cc:dd:ee:01',
        ssid: 'Example-Guest',
        routerHost: '10.0.2.101',
        signal: -51,
      },
    ]);
  });
});

describe('deviceIdByMac', () => {
  it('matches normalized MAC', () => {
    const id = deviceIdByMac(
      [{ id: 'd1', mac: 'aa:bb:cc:dd:ee:01' } as never],
      'AA-BB-CC-DD-EE-01',
    );
    expect(id).toBe('d1');
  });
});
