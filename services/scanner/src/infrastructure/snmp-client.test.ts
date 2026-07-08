import { describe, expect, it } from 'vitest';
import { SnmpClient, normalizeSnmpWalkValue } from './snmp-client.js';

describe('normalizeSnmpWalkValue', () => {
  it('strips STRING / INTEGER tags and quotes', () => {
    expect(normalizeSnmpWalkValue('STRING: "AA BB CC DD EE FF"')).toBe('AA BB CC DD EE FF');
    expect(normalizeSnmpWalkValue('INTEGER: 2')).toBe('2');
    expect(normalizeSnmpWalkValue('Hex-STRING: AA BB CC DD EE FF')).toBe('AA BB CC DD EE FF');
    expect(normalizeSnmpWalkValue('"eth2"')).toBe('eth2');
  });
});

describe('SnmpClient.parseMac', () => {
  it('parses tagged STRING MAC from snmpwalk -On', () => {
    expect(SnmpClient.parseMac('STRING: "04 4B A5 01 02 03"')).toBe('04:4b:a5:01:02:03');
  });

  it('parses space-separated and colon MAC forms', () => {
    expect(SnmpClient.parseMac('aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff');
    expect(SnmpClient.parseMac('AA BB CC DD EE FF')).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('rejects non-MAC values', () => {
    expect(SnmpClient.parseMac('INTEGER: 2')).toBeNull();
    expect(SnmpClient.parseMac('eth2')).toBeNull();
  });
});
