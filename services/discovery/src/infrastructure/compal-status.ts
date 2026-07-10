export interface CompalSystemStatus {
  uptimeSec: number;
  localtime?: string;
  loadavg?: number[];
  memoryTotalBytes?: number;
  memoryFreeBytes?: number;
}

/** Parse Compal LuCI `/admin/status?status=1` JSON payload. */
export function parseCompalSystemStatus(body: string): CompalSystemStatus | null {
  try {
    const doc = JSON.parse(body) as {
      uptime?: unknown;
      localtime?: unknown;
      loadavg?: unknown;
      memory?: { total?: unknown; free?: unknown };
    };
    const uptimeSec = typeof doc.uptime === 'number' ? doc.uptime : Number(doc.uptime);
    if (!Number.isFinite(uptimeSec) || uptimeSec < 0) return null;
    const loadavg = Array.isArray(doc.loadavg)
      ? doc.loadavg.map((v) => Number(v)).filter((n) => Number.isFinite(n))
      : undefined;
    return {
      uptimeSec,
      localtime: typeof doc.localtime === 'string' ? doc.localtime : undefined,
      loadavg: loadavg?.length ? loadavg : undefined,
      memoryTotalBytes:
        typeof doc.memory?.total === 'number' ? doc.memory.total : undefined,
      memoryFreeBytes: typeof doc.memory?.free === 'number' ? doc.memory.free : undefined,
    };
  } catch {
    return null;
  }
}

export function formatCompalUptime(uptimeSec: number): string {
  const sec = Math.max(0, Math.floor(uptimeSec));
  const d = Math.floor(sec / 86_400);
  const h = Math.floor((sec % 86_400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${sec % 60}s`;
}
