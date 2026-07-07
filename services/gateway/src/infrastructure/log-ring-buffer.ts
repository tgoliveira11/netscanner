import { Writable } from 'node:stream';
import { readFileSync, existsSync } from 'node:fs';

export interface LogEntry {
  at: string;
  level: number;
  levelLabel: string;
  msg: string;
  raw: Record<string, unknown>;
}

const LEVELS: Record<number, string> = {
  10: 'trace',
  20: 'debug',
  30: 'info',
  40: 'warn',
  50: 'error',
  60: 'fatal',
};

/** In-memory ring buffer of structured log lines for /admin. */
export class LogRingBuffer {
  private entries: LogEntry[] = [];

  constructor(private readonly max = 500) {}

  push(obj: Record<string, unknown>): void {
    const level = typeof obj.level === 'number' ? obj.level : 30;
    const entry: LogEntry = {
      at: typeof obj.time === 'number' ? new Date(obj.time).toISOString() : new Date().toISOString(),
      level,
      levelLabel: LEVELS[level] ?? 'info',
      msg: String(obj.msg ?? ''),
      raw: obj,
    };
    this.entries.push(entry);
    if (this.entries.length > this.max) this.entries.shift();
  }

  tail(n = 200): LogEntry[] {
    return this.entries.slice(-n);
  }

  asStream(): Writable {
    const buffer = this;
    return new Writable({
      write(chunk, _enc, cb) {
        try {
          const line = chunk.toString().trim();
          if (line) buffer.push(JSON.parse(line) as Record<string, unknown>);
        } catch {
          /* ignore non-json */
        }
        cb();
      },
    });
  }
}

/** Tail lines from agent.log on disk (best-effort). */
export function tailAgentLogFile(filePath: string, lines = 200): string[] {
  if (!existsSync(filePath)) return [];
  try {
    const text = readFileSync(filePath, 'utf8');
    return text.split('\n').filter(Boolean).slice(-lines);
  } catch {
    return [];
  }
}
