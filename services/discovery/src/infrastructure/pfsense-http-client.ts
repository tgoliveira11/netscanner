import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';

export interface PfSenseHttpConfig {
  baseUrl: string;
  apiKey: string;
  insecureTls: boolean;
  timeoutMs?: number;
}

/** Minimal pfSense REST v2 HTTP client (GET/POST/PATCH/DELETE). */
export class PfSenseHttpClient {
  constructor(private readonly config: PfSenseHttpConfig) {}

  get(path: string, timeoutMs?: number): Promise<unknown> {
    return this.request('GET', path, undefined, timeoutMs);
  }

  post(path: string, body: unknown, apply = true, timeoutMs?: number): Promise<unknown> {
    const q = apply ? '?apply=true' : '';
    return this.request('POST', `${path}${q}`, body, timeoutMs);
  }

  patch(path: string, body: unknown, apply = true, timeoutMs?: number): Promise<unknown> {
    const q = apply ? '?apply=true' : '';
    return this.request('PATCH', `${path}${q}`, body, timeoutMs);
  }

  delete(path: string, apply = true, timeoutMs?: number): Promise<unknown> {
    const q = apply ? '?apply=true' : '';
    return this.request('DELETE', `${path}${q}`, undefined, timeoutMs);
  }

  extractArray(raw: unknown): Record<string, unknown>[] {
    if (Array.isArray(raw)) return raw as Record<string, unknown>[];
    if (raw && typeof raw === 'object') {
      const data = (raw as Record<string, unknown>)['data'];
      if (Array.isArray(data)) return data as Record<string, unknown>[];
      for (const value of Object.values(raw as Record<string, unknown>)) {
        if (Array.isArray(value)) return value as Record<string, unknown>[];
      }
    }
    return [];
  }

  extractObject(raw: unknown): Record<string, unknown> | null {
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      const data = (raw as Record<string, unknown>)['data'];
      if (data && typeof data === 'object' && !Array.isArray(data)) return data as Record<string, unknown>;
      return raw as Record<string, unknown>;
    }
    return null;
  }

  private request(method: string, path: string, body: unknown, timeoutMs?: number): Promise<unknown> {
    const timeout = timeoutMs ?? this.config.timeoutMs ?? 12_000;
    const url = new URL(path.startsWith('/') ? path : `/${path}`, this.config.baseUrl);
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    const payload = body !== undefined ? JSON.stringify(body) : undefined;

    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method,
          headers: {
            'X-API-Key': this.config.apiKey,
            Accept: 'application/json',
            ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
          },
          timeout,
          ...(isHttps ? { rejectUnauthorized: !this.config.insecureTls } : {}),
        },
        (res) => {
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () => {
            if ((res.statusCode ?? 500) >= 400) {
              reject(new Error(`pfSense ${method} ${path} ${res.statusCode}: ${data.slice(0, 300)}`));
              return;
            }
            if (!data.trim()) {
              resolve({});
              return;
            }
            try {
              resolve(JSON.parse(data));
            } catch {
              resolve({ raw: data });
            }
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('pfSense API timeout')));
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }
}
