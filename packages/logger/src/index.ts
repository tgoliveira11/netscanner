import pino, { type Logger } from 'pino';
import type { Writable } from 'node:stream';

export type { Logger };

const isDev = process.env.NODE_ENV !== 'production';

/** Create a pino logger; optional extra stream (e.g. in-memory ring buffer for /admin). */
export function createLogger(name: string, extraStream?: Writable): Logger {
  const opts = {
    name,
    level: process.env.LOG_LEVEL ?? (isDev ? 'debug' : 'info'),
    transport: isDev && !extraStream
      ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } }
      : undefined,
  };
  if (extraStream) {
    return pino(opts, pino.multistream([{ stream: process.stdout }, { stream: extraStream }]));
  }
  return pino(opts);
}
