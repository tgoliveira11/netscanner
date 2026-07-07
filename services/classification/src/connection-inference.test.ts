import { describe, it, expect } from 'vitest';
import { inferConnection } from './domain/connection-inference.js';

describe('inferConnection', () => {
  it('treats a randomized/private MAC as WiFi (WiFi-only feature)', () => {
    const r = inferConnection({ mac: 'be:06:60:32:27:c6', deviceType: 'laptop', isGateway: false });
    expect(r.type).toBe('wifi');
    expect(r.basis).toMatch(/randomized/i);
  });

  it('treats infrastructure (router/NAS) and the gateway as wired', () => {
    expect(inferConnection({ mac: '60:be:b4:00:00:04', deviceType: 'router', isGateway: true }).type).toBe('wired');
    expect(inferConnection({ mac: '00:11:22:33:44:55', deviceType: 'nas', isGateway: false }).type).toBe('wired');
  });

  it('treats phones/wearables as WiFi', () => {
    expect(inferConnection({ mac: null, deviceType: 'phone', isGateway: false }).type).toBe('wifi');
    expect(inferConnection({ mac: null, deviceType: 'wearable', isGateway: false }).type).toBe('wifi');
  });

  it('leaves genuinely ambiguous devices (wired-capable, universal MAC) as unknown', () => {
    expect(inferConnection({ mac: '00:11:22:33:44:55', deviceType: 'computer', isGateway: false }).type).toBe('unknown');
    expect(inferConnection({ mac: '00:11:22:33:44:55', deviceType: 'printer', isGateway: false }).type).toBe('unknown');
  });

  it('lets an authoritative switch/AP value override the heuristic', () => {
    const r = inferConnection({ mac: null, deviceType: 'phone', isGateway: false, authoritative: 'wired' });
    expect(r.type).toBe('wired');
    expect(r.basis).toMatch(/authoritative/i);
  });
});
