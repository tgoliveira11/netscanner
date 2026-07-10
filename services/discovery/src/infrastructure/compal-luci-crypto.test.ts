import { describe, expect, it } from 'vitest';
import {
  deriveIspUsername,
  parseCompalWirelessNetworkIds,
  parseCompalWirelessStatusJson,
  parseCompalWirelessStatusBody,
} from './compal-luci-crypto.js';

describe('deriveIspUsername', () => {
  it('derives ISP username from MAC with colons', () => {
    expect(deriveIspUsername('aa:bb:cc:11:22:33')).toBe('ISP_112233');
    expect(deriveIspUsername('aa:bb:cc:de:ad:01')).toBe('ISP_DEAD01');
  });

  it('returns null for invalid MAC', () => {
    expect(deriveIspUsername('bad')).toBeNull();
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

describe('parseCompalWirelessStatusBody', () => {
  it('parses bare JSON array', () => {
    const raw = '[{"ssid":"Guest","up":true}]';
    expect(parseCompalWirelessStatusBody(raw)).toEqual([{ ssid: 'Guest', up: true }]);
  });

  it('extracts JSON array from HTML wrapper', () => {
    const raw = '<html>OK [{"ssid":"IoT","up":false}]</html>';
    expect(parseCompalWirelessStatusBody(raw)).toEqual([{ ssid: 'IoT', up: false }]);
  });

  it('returns null for login HTML', () => {
    const raw = '<form name="login"><input name="luci_username"></form>';
    expect(parseCompalWirelessStatusBody(raw)).toBeNull();
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
