import { describe, it, expect } from 'vitest';
import {
  buildTuyaSign,
  extractMacFromTuyaId,
  indexTuyaIdentities,
  isPrivateLanIp,
  normalizeTuyaMac,
  parseFactoryInfoMacs,
  parseTuyaDeviceRow,
  tuyaApiHost,
} from './infrastructure/tuya-cloud-identity.js';
import type { CloudDeviceIdentity } from './domain/cloud-device-identity.js';

describe('tuyaApiHost', () => {
  it('maps data centers', () => {
    expect(tuyaApiHost('us')).toBe('openapi.tuyaus.com');
    expect(tuyaApiHost('eu')).toBe('openapi.tuyaeu.com');
    expect(tuyaApiHost('cn')).toBe('openapi.tuyacn.com');
  });
});

describe('normalizeTuyaMac', () => {
  it('normalizes separators', () => {
    expect(normalizeTuyaMac('AA-BB-CC-DD-EE-FF')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeTuyaMac('aabbccddeeff')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeTuyaMac('bad')).toBeNull();
  });
});

describe('extractMacFromTuyaId / isPrivateLanIp', () => {
  it('extracts embedded MAC suffix', () => {
    expect(extractMacFromTuyaId('84015433ecfabcb249ea')).toBe('ec:fa:bc:b2:49:ea');
    expect(extractMacFromTuyaId('eb2f638cc8d83a30beo8zz')).toBeNull();
  });

  it('accepts only RFC1918 IPs for LAN matching', () => {
    expect(isPrivateLanIp('192.168.60.101')).toBe(true);
    expect(isPrivateLanIp('45.179.91.108')).toBe(false);
  });
});

describe('buildTuyaSign', () => {
  it('is stable for a known token request', () => {
    const sign = buildTuyaSign({
      accessId: 'clientId',
      accessSecret: 'secret',
      timestampMs: 1_700_000_000_000,
      method: 'GET',
      pathWithQuery: '/v1.0/token?grant_type=1',
      body: '',
      accessToken: null,
    });
    expect(sign).toMatch(/^[A-F0-9]{64}$/);
    expect(
      buildTuyaSign({
        accessId: 'clientId',
        accessSecret: 'secret',
        timestampMs: 1_700_000_000_000,
        method: 'GET',
        pathWithQuery: '/v1.0/token?grant_type=1',
        body: '',
        accessToken: null,
      }),
    ).toBe(sign);
  });
});

describe('parseTuyaDeviceRow', () => {
  it('maps product fields and strips local_key from identity', () => {
    const id = parseTuyaDeviceRow({
      id: 'dev1',
      name: 'Sala plug',
      product_name: 'Smart Plug 20A',
      category: 'cz',
      mac: 'AABBCCDDEEFF',
      ip: '192.168.60.10',
      online: true,
      local_key: 'SHOULD_NOT_LEAK',
    });
    expect(id).toEqual({
      deviceId: 'dev1',
      name: 'Sala plug',
      productName: 'Smart Plug 20A',
      category: 'cz',
      mac: 'aa:bb:cc:dd:ee:ff',
      ip: '192.168.60.10',
      online: true,
    });
    expect(JSON.stringify(id)).not.toContain('SHOULD_NOT_LEAK');
  });

  it('drops public WAN IPs and recovers MAC from id suffix', () => {
    const id = parseTuyaDeviceRow({
      id: '84015433ecfabcb249ea',
      name: 'IR box',
      ip: '45.179.91.108',
    });
    expect(id?.mac).toBe('ec:fa:bc:b2:49:ea');
    expect(id?.ip).toBeNull();
  });
});

describe('parseFactoryInfoMacs', () => {
  it('maps factory-infos rows', () => {
    const map = parseFactoryInfoMacs([
      { id: 'dev1', mac: 'B8:06:0D:1C:83:D8' },
      { device_id: 'dev2', mac_address: '80-64-7c-aa-1a-79' },
    ]);
    expect(map.get('dev1')).toBe('b8:06:0d:1c:83:d8');
    expect(map.get('dev2')).toBe('80:64:7c:aa:1a:79');
  });
});

describe('indexTuyaIdentities', () => {
  it('indexes by mac and ip', () => {
    const devices: CloudDeviceIdentity[] = [
      {
        deviceId: '1',
        name: 'Lamp',
        productName: 'Bulb',
        category: 'dj',
        mac: 'aa:bb:cc:dd:ee:01',
        ip: '10.0.0.1',
        online: true,
      },
    ];
    const { byMac, byIp } = indexTuyaIdentities(devices);
    expect(byMac.get('aa:bb:cc:dd:ee:01')?.name).toBe('Lamp');
    expect(byIp.get('10.0.0.1')?.productName).toBe('Bulb');
  });
});

describe('TuyaCloudIdentityClient hydrate/persist', () => {
  it('hydrates lookups from the catalog store without network', async () => {
    const { TuyaCloudIdentityClient } = await import('./infrastructure/tuya-cloud-identity.js');
    const store = {
      rows: [
        {
          deviceId: 'dev1',
          name: 'Interruptor Sala',
          productName: 'Switch',
          category: 'kg',
          mac: 'b8:06:0d:1c:83:d8',
          ip: null,
          online: true,
        },
      ] as CloudDeviceIdentity[],
      async loadAll() {
        return this.rows.map((r) => ({ ...r }));
      },
      async replaceAll(rows: readonly CloudDeviceIdentity[]) {
        this.rows = rows.map((r) => ({ ...r }));
      },
    };
    const logger = { info() {}, warn() {}, error() {}, debug() {} };
    const client = new TuyaCloudIdentityClient(
      {
        accessId: 'id',
        accessSecret: 'secret',
        store,
      },
      logger as never,
    );
    expect(await client.hydrate()).toBe(1);
    expect(client.lookupByMac('b8:06:0d:1c:83:d8')?.name).toBe('Interruptor Sala');
    expect(client.size()).toBe(1);
  });
});
