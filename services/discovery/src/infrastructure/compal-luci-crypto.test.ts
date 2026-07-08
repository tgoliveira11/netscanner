import { describe, expect, it } from 'vitest';
import {
  deriveClaroUsername,
  parseCompalWirelessNetworkIds,
  parseCompalWirelessStatusJson,
} from './compal-luci-crypto.js';

describe('deriveClaroUsername', () => {
  it('derives CLARO username from MAC with colons', () => {
    expect(deriveClaroUsername('aa:bb:cc:11:22:33')).toBe('CLARO_112233');
    expect(deriveClaroUsername('aa:bb:cc:de:ad:01')).toBe('CLARO_DEAD01');
  });

  it('returns null for invalid MAC', () => {
    expect(deriveClaroUsername('bad')).toBeNull();
  });
});

describe('parseCompalWirelessNetworkIds', () => {
  it('reads network ids from wifidevs block', () => {
    const html = `var wifidevs = {"wifi1.network1":"wifi1","wifi0.network3":"wifi0","wifi0.network1":"wifi0"};`;
    expect(parseCompalWirelessNetworkIds(html)).toEqual([
      'wifi1.network1',
      'wifi0.network3',
      'wifi0.network1',
    ]);
  });

  it('falls back to wireless_status poll path', () => {
    const html = `XHR.poll(5, '/cgi-bin/luci/;stok=abc/admin/network/wireless_status/wifi0.network1,wifi1.network1', null,`;
    expect(parseCompalWirelessNetworkIds(html)).toEqual(['wifi0.network1', 'wifi1.network1']);
  });
});

describe('parseCompalWirelessStatusJson', () => {
  it('accepts wireless_status array', () => {
    const rows = parseCompalWirelessStatusJson([
      { id: 'wifi0.network1', ssid: 'Example-Guest', up: true, ifname: 'ath0' },
    ]);
    expect(rows[0]?.ssid).toBe('Example-Guest');
  });
});
