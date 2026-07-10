import { describe, expect, it } from 'vitest';
import { formatCompalUptime, parseCompalSystemStatus } from './compal-status.js';

describe('parseCompalSystemStatus', () => {
  it('parses uptime and localtime from status JSON', () => {
    const status = parseCompalSystemStatus(
      JSON.stringify({
        uptime: 293478,
        localtime: 'Thu Jul  9 16:13:39 2026',
        loadavg: [185344, 164512, 159968],
        memory: { total: 240996352, free: 29413376 },
      }),
    );
    expect(status?.uptimeSec).toBe(293478);
    expect(status?.localtime).toContain('2026');
    expect(status?.loadavg).toHaveLength(3);
    expect(status?.memoryTotalBytes).toBe(240996352);
  });

  it('returns null for invalid payload', () => {
    expect(parseCompalSystemStatus('not json')).toBeNull();
    expect(parseCompalSystemStatus('{}')).toBeNull();
  });
});

describe('formatCompalUptime', () => {
  it('formats days, hours and minutes', () => {
    expect(formatCompalUptime(293478)).toBe('3d 9h 31m');
    expect(formatCompalUptime(3661)).toBe('1h 1m');
    expect(formatCompalUptime(45)).toBe('45s');
  });
});
