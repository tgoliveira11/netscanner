import { createServer, connect as netConnect, type Server as NetServer, type Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { Logger } from '@netscanner/logger';
import type { AppConfig } from '@netscanner/config';
import type { CpeAccessOpenRequest, CpeAccessSession } from '@netscanner/contracts';
import {
  type ICpeAccessSessionStore,
  type SecretCipher,
  isEncryptedSecret,
} from '@netscanner/inventory';
import { resolvePfSenseSshHost } from '@netscanner/scanner';

const PROBE_MS = 2_500;

type ActiveSession = {
  meta: CpeAccessSession;
  /** Host/port the HTTP client uses to reach the CPE (direct IP or 127.0.0.1 via tunnel). */
  upstreamHost: string;
  upstreamPort: number;
  upstreamTls: boolean;
  /** Decrypted password — never returned by list/open API. */
  password: string;
  /** Inject fill+click once on the CPE login page, then clear flag in DB. */
  autoLogin: boolean;
  /**
   * CPE session cookies captured from Set-Cookie and replayed upstream.
   * Keeps Vivo/Claro auth alive even when the browser drops cookies across frames.
   */
  upstreamCookies: Map<string, string>;
  ssh?: ChildProcess;
};

/**
 * Generic CPE/modem admin access broker.
 *
 * Sessions persist in SQLite until Admin "Close tunnel". On agent restart, tunnels
 * are re-established. Credentials are stored encrypted when SecretCipher is available.
 */
export class CpeAccessService {
  private readonly sessions = new Map<string, ActiveSession>();
  private restorePromise: Promise<void> | null = null;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly store: ICpeAccessSessionStore,
    private readonly cipher: SecretCipher | null = null,
  ) {}

  /** Load persisted sessions and re-open SSH/direct reachability. */
  start(): void {
    this.restorePromise = this.restoreFromStore().catch((error) => {
      this.logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'CPE session restore failed',
      );
    });
  }

  list(): { sessions: CpeAccessSession[]; pfsenseTunnelAvailable: boolean } {
    return {
      sessions: [...this.sessions.values()].map((s) => s.meta),
      pfsenseTunnelAvailable: this.pfsenseTunnelAvailable(),
    };
  }

  async open(req: CpeAccessOpenRequest): Promise<{
    ok: boolean;
    session?: CpeAccessSession;
    error?: string;
    hint?: string;
  }> {
    await this.restorePromise;

    const ip = req.ip.trim();
    const port = req.port && req.port > 0 ? req.port : req.tls ? 443 : 80;
    const tls = Boolean(req.tls);
    const username = req.username.trim();
    const label = req.label?.trim() || null;

    if (!ip) return { ok: false, error: 'ip is required' };
    if (!username) return { ok: false, error: 'username is required' };
    if (!req.password) return { ok: false, error: 'password is required' };

    const reach = await this.establishReachability(ip, port, tls);
    if (!reach.ok) {
      return { ok: false, error: reach.error, hint: reach.hint };
    }

    const id = randomBytes(8).toString('hex');
    const createdAt = new Date();
    const proxyPath = `/api/admin/cpe/proxy/${id}/`;
    const meta: CpeAccessSession = {
      id,
      ip,
      port,
      tls,
      label,
      username,
      via: reach.via,
      proxyPath,
      openUrl: proxyPath,
      createdAt: createdAt.toISOString(),
      expiresAt: null,
    };

    this.sessions.set(id, {
      meta,
      upstreamHost: reach.upstreamHost,
      upstreamPort: reach.upstreamPort,
      upstreamTls: reach.upstreamTls,
      password: req.password,
      autoLogin: true,
      upstreamCookies: new Map(),
      ssh: reach.ssh,
    });

    await this.store.upsert({
      id,
      ip,
      port,
      tls,
      label,
      username,
      passwordEnc: this.encryptPassword(req.password),
      via: reach.via,
      autoLoginPending: true,
      createdAt,
    });

    this.logger.info({ id, ip, port, via: reach.via }, 'CPE access session opened');
    return {
      ok: true,
      session: meta,
      hint: 'Session persisted until you click Close tunnel. Opening the UI auto-fills login once.',
    };
  }

  async close(id: string): Promise<boolean> {
    await this.restorePromise;
    const s = this.sessions.get(id);
    if (!s) {
      await this.store.delete(id);
      return false;
    }
    try {
      s.ssh?.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    this.sessions.delete(id);
    await this.store.delete(id);
    this.logger.info({ id, ip: s.meta.ip }, 'CPE access session closed');
    return true;
  }

  /** Re-arm one-shot auto-login (e.g. when user clicks Open UI again). */
  async rearmAutoLogin(id: string): Promise<boolean> {
    await this.restorePromise;
    const s = this.sessions.get(id);
    if (!s) return false;
    s.autoLogin = true;
    await this.store.updateAutoLogin(id, true);
    return true;
  }

  get(id: string): ActiveSession | null {
    return this.sessions.get(id) ?? null;
  }

  async proxyHttp(
    id: string,
    request: http.IncomingMessage,
    response: http.ServerResponse,
    suffixPath: string,
  ): Promise<void> {
    await this.restorePromise;
    let s = this.get(id);
    if (!s) {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('CPE session not found — open a tunnel from Admin → Integrations');
      return;
    }

    // Lazily re-establish tunnel if SSH died after restart / network blip.
    if (s.meta.via === 'pfsense-tunnel' && (!s.ssh || s.ssh.killed || s.ssh.exitCode != null)) {
      const reach = await this.establishReachability(s.meta.ip, s.meta.port, s.meta.tls);
      if (reach.ok) {
        s.upstreamHost = reach.upstreamHost;
        s.upstreamPort = reach.upstreamPort;
        s.upstreamTls = reach.upstreamTls;
        s.ssh = reach.ssh;
        s.meta = { ...s.meta, via: reach.via };
      }
    }

    const pathAndQuery = suffixPath.startsWith('/') ? suffixPath : `/${suffixPath}`;
    const client = s.upstreamTls ? https : http;
    const headers: http.OutgoingHttpHeaders = { ...request.headers };
    const hostPort =
      (s.meta.tls && s.meta.port === 443) || (!s.meta.tls && s.meta.port === 80)
        ? s.meta.ip
        : `${s.meta.ip}:${s.meta.port}`;
    headers.host = hostPort;
    delete headers['accept-encoding'];
    delete headers['content-encoding'];
    delete headers.connection;
    delete headers['keep-alive'];
    delete headers['proxy-connection'];
    delete headers['transfer-encoding'];
    // Never let the browser keep a stale/corrupted proxied asset via 304.
    delete headers['if-modified-since'];
    delete headers['if-none-match'];
    // Vivo/Sophia (and similar) gate assets on Referer; map proxy Referer → CPE origin.
    headers.referer = this.rewriteRefererHeader(headers.referer, s.meta, hostPort);
    if (typeof headers.origin === 'string') {
      headers.origin = `${s.meta.tls ? 'https' : 'http'}://${hostPort}`;
    }

    // Replay CPE session cookies captured from prior Set-Cookie (frame navigations
    // sometimes drop browser cookies; jar keeps Vivo/Claro auth sticky).
    if (s.upstreamCookies.size > 0) {
      headers.cookie = mergeCookieHeader(headers.cookie, s.upstreamCookies);
    }

    // Embedded CPE CGIs often reject chunked request bodies — buffer and set Content-Length.
    const method = (request.method ?? 'GET').toUpperCase();
    const hasBody = !['GET', 'HEAD'].includes(method);
    const reqBody = hasBody ? await readIncomingBody(request) : null;
    if (reqBody) {
      headers['content-length'] = String(reqBody.length);
    } else {
      delete headers['content-length'];
    }

    await new Promise<void>((resolve) => {
      const proxyReq = client.request(
        {
          host: s!.upstreamHost,
          port: s!.upstreamPort,
          path: pathAndQuery || '/',
          method,
          headers,
          rejectUnauthorized: false,
          timeout: 30_000,
          // Vivo Sophia CGIs often end headers with bare LF ("Content-Type: text/html\n\n")
          // instead of CRLF — Node's strict parser returns 502 without this.
          insecureHTTPParser: true,
        },
        (proxyRes) => {
          const outHeaders: http.OutgoingHttpHeaders = { ...proxyRes.headers };
          if (typeof outHeaders.location === 'string') {
            outHeaders.location = this.rewriteLocation(s!.meta, outHeaders.location);
          }
          if (outHeaders['set-cookie']) {
            const cookies = Array.isArray(outHeaders['set-cookie'])
              ? outHeaders['set-cookie']
              : [outHeaders['set-cookie']];
            for (const c of cookies) rememberUpstreamCookie(s!.upstreamCookies, c);
            // Path without trailing slash so /proxy/:id and /proxy/:id/... both match.
            const cookiePath = s!.meta.proxyPath.replace(/\/$/, '') || '/';
            outHeaders['set-cookie'] = cookies.map((c) => rewriteSetCookie(c, cookiePath));
          }
          delete outHeaders['content-security-policy'];
          delete outHeaders['x-frame-options'];
          delete outHeaders['content-encoding'];
          delete outHeaders['transfer-encoding'];
          // Proxied CPE UIs must not be cached — a prior rewrite bug poisoned jQuery in
          // browser disk cache; 304 would keep serving the bad body forever.
          delete outHeaders['etag'];
          delete outHeaders['last-modified'];
          outHeaders['cache-control'] = 'no-store, no-cache, must-revalidate';
          outHeaders.pragma = 'no-cache';
          outHeaders.expires = '0';

          const ctype = String(outHeaders['content-type'] ?? '').toLowerCase();
          const pathBinary = isBinaryAssetPath(pathAndQuery);
          const maybeText =
            !pathBinary &&
            (!ctype ||
              ctype.includes('text/') ||
              ctype.includes('javascript') ||
              ctype.includes('json') ||
              ctype.includes('xml') ||
              ctype.includes('urlencoded'));

          // Many CPE CGIs (Vivo Sophia) omit Content-Type — must buffer + sniff HTML
          // or frame/src absolute paths never get rewritten.
          // Vivo also serves WOFF/TTF as text/plain — never UTF-8 round-trip those.
          if (maybeText) {
            const chunks: Buffer[] = [];
            proxyRes.on('data', (chunk) => chunks.push(chunk));
            proxyRes.on('end', () => {
              const raw = Buffer.concat(chunks);
              if (looksLikeBinaryBuffer(raw)) {
                const fixedType = contentTypeForBinaryPath(pathAndQuery);
                if (fixedType) outHeaders['content-type'] = fixedType;
                outHeaders['content-length'] = String(raw.length);
                response.writeHead(proxyRes.statusCode ?? 502, outHeaders);
                response.end(raw);
                resolve();
                return;
              }
              const asText = raw.toString('utf8');
              // Prefer path/ctype over body sniffing — jQuery etc. embed "<!doctype html>"
              // strings and must never get HTML <script> injection.
              const pathIsJs = /\.m?js(\?|$)/i.test(pathAndQuery);
              const pathIsCss = /\.css(\?|$)/i.test(pathAndQuery);
              const ctypeJs = ctype.includes('javascript') || ctype.includes('ecmascript');
              const ctypeCss = ctype.includes('text/css');
              const ctypeHtml = ctype.includes('text/html') || ctype.includes('xhtml');
              const looksJs =
                ctypeJs || pathIsJs || (!ctype && !pathIsCss && looksLikeJs(asText, pathAndQuery));
              const looksCss =
                ctypeCss || pathIsCss || (!ctype && !looksJs && looksLikeCss(asText));
              const looksHtml =
                !looksJs && !looksCss && (ctypeHtml || isHtmlPayload(ctype, asText));

              let body = asText;
              if (looksHtml) {
                body = this.rewriteHtml(body, s!, pathAndQuery);
                if (!ctype) outHeaders['content-type'] = 'text/html; charset=utf-8';
              } else if (looksCss) {
                body = this.rewriteCssUrls(body, s!.meta.proxyPath);
                if (!ctype) outHeaders['content-type'] = 'text/css; charset=utf-8';
              } else if (looksJs || ctype.includes('json')) {
                body = this.rewriteJsRootPaths(body, s!.meta);
              } else {
                body = this.rewriteJsRootPaths(body, s!.meta);
              }

              const buf = Buffer.from(body, 'utf8');
              outHeaders['content-length'] = String(buf.length);
              response.writeHead(proxyRes.statusCode ?? 502, outHeaders);
              response.end(buf);
              resolve();
            });
            proxyRes.on('error', () => resolve());
            return;
          }

          if (pathBinary) {
            const fixedType = contentTypeForBinaryPath(pathAndQuery);
            if (fixedType) outHeaders['content-type'] = fixedType;
          }
          delete outHeaders['content-length'];
          response.writeHead(proxyRes.statusCode ?? 502, outHeaders);
          proxyRes.pipe(response);
          proxyRes.on('end', () => resolve());
          proxyRes.on('error', () => resolve());
        },
      );
      proxyReq.on('error', (error) => {
        if (!response.headersSent) {
          response.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
          response.end(`CPE proxy error: ${error.message}`);
        }
        resolve();
      });
      if (reqBody && reqBody.length > 0) {
        proxyReq.end(reqBody);
      } else if (hasBody) {
        proxyReq.end();
      } else {
        proxyReq.end();
      }
    });
  }

  private async restoreFromStore(): Promise<void> {
    const rows = await this.store.list();
    if (rows.length === 0) return;
    this.logger.info({ count: rows.length }, 'Restoring CPE access sessions');
    for (const row of rows) {
      if (this.sessions.has(row.id)) continue;
      const password = this.decryptPassword(row.passwordEnc);
      const reach = await this.establishReachability(row.ip, row.port, row.tls);
      if (!reach.ok) {
        this.logger.warn(
          { id: row.id, ip: row.ip, error: reach.error },
          'CPE session retained in DB but not reachable yet',
        );
        // Keep a stub so list/close still work; proxy will retry tunnel.
        const proxyPath = `/api/admin/cpe/proxy/${row.id}/`;
        this.sessions.set(row.id, {
          meta: {
            id: row.id,
            ip: row.ip,
            port: row.port,
            tls: row.tls,
            label: row.label,
            username: row.username,
            via: row.via,
            proxyPath,
            openUrl: proxyPath,
            createdAt: row.createdAt.toISOString(),
            expiresAt: null,
          },
          upstreamHost: row.ip,
          upstreamPort: row.port,
          upstreamTls: row.tls,
          password,
          autoLogin: row.autoLoginPending,
          upstreamCookies: new Map(),
        });
        continue;
      }
      const proxyPath = `/api/admin/cpe/proxy/${row.id}/`;
      this.sessions.set(row.id, {
        meta: {
          id: row.id,
          ip: row.ip,
          port: row.port,
          tls: row.tls,
          label: row.label,
          username: row.username,
          via: reach.via,
          proxyPath,
          openUrl: proxyPath,
          createdAt: row.createdAt.toISOString(),
          expiresAt: null,
        },
        upstreamHost: reach.upstreamHost,
        upstreamPort: reach.upstreamPort,
        upstreamTls: reach.upstreamTls,
        password,
        autoLogin: row.autoLoginPending,
        upstreamCookies: new Map(),
        ssh: reach.ssh,
      });
      if (reach.via !== row.via) {
        await this.store.upsert({ ...row, via: reach.via, passwordEnc: row.passwordEnc });
      }
    }
  }

  private async establishReachability(
    ip: string,
    port: number,
    tls: boolean,
  ): Promise<
    | {
        ok: true;
        via: CpeAccessSession['via'];
        upstreamHost: string;
        upstreamPort: number;
        upstreamTls: boolean;
        ssh?: ChildProcess;
      }
    | { ok: false; error: string; hint?: string }
  > {
    const directOk = await this.canConnect(ip, port, tls);
    if (directOk) {
      return { ok: true, via: 'direct', upstreamHost: ip, upstreamPort: port, upstreamTls: tls };
    }
    if (!this.pfsenseTunnelAvailable()) {
      return {
        ok: false,
        error: `cannot reach ${ip}:${port} from this agent`,
        hint: 'Set PFSENSE_URL + PFSENSE_SSH_PASSWORD to tunnel WAN CPE admin UIs via pfSense.',
      };
    }
    try {
      const tun = await this.startPfSenseTunnel(ip, port);
      return {
        ok: true,
        via: 'pfsense-tunnel',
        upstreamHost: '127.0.0.1',
        upstreamPort: tun.localPort,
        upstreamTls: tls,
        ssh: tun.ssh,
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        hint: 'CPE unreachable from this agent and pfSense SSH tunnel failed. Check PFSENSE_SSH_* / WAN routing.',
      };
    }
  }

  private encryptPassword(password: string): string {
    return this.cipher ? this.cipher.encrypt(password) : password;
  }

  private decryptPassword(stored: string): string {
    if (!stored) return '';
    if (this.cipher && isEncryptedSecret(stored)) return this.cipher.decrypt(stored);
    if (this.cipher && !isEncryptedSecret(stored)) {
      try {
        return this.cipher.decrypt(stored);
      } catch {
        return stored;
      }
    }
    return stored;
  }

  private pfsenseTunnelAvailable(): boolean {
    return Boolean(
      resolvePfSenseSshHost(this.config.PFSENSE_URL) && this.config.PFSENSE_SSH_PASSWORD?.trim(),
    );
  }

  private canConnect(host: string, port: number, tls: boolean): Promise<boolean> {
    return new Promise((resolve) => {
      const sock: Socket = tls
        ? tlsConnect({ host, port, rejectUnauthorized: false, servername: host })
        : netConnect({ host, port });
      const finish = (ok: boolean) => {
        clearTimeout(timer);
        sock.removeAllListeners();
        try {
          sock.destroy();
        } catch {
          /* ignore */
        }
        resolve(ok);
      };
      const timer = setTimeout(() => finish(false), PROBE_MS);
      sock.once('connect', () => finish(true));
      sock.once('secureConnect', () => finish(true));
      sock.once('error', () => finish(false));
      sock.once('timeout', () => finish(false));
    });
  }

  private startPfSenseTunnel(
    cpeHost: string,
    cpePort: number,
  ): Promise<{ localPort: number; ssh: ChildProcess }> {
    const pfHost = resolvePfSenseSshHost(this.config.PFSENSE_URL);
    if (!pfHost) return Promise.reject(new Error('PFSENSE_URL not configured'));
    const password = this.config.PFSENSE_SSH_PASSWORD?.trim();
    if (!password) return Promise.reject(new Error('PFSENSE_SSH_PASSWORD not configured'));
    const username = this.config.PFSENSE_SSH_USER?.trim() || 'admin';
    const pfPort = this.config.PFSENSE_SSH_PORT || 22;

    return new Promise((resolve, reject) => {
      reserveLocalPort()
        .then((localPort) => {
          const ssh = spawn(
            'sshpass',
            [
              '-e',
              'ssh',
              '-p',
              String(pfPort),
              '-o',
              'StrictHostKeyChecking=accept-new',
              '-o',
              'ExitOnForwardFailure=yes',
              '-o',
              'ServerAliveInterval=30',
              '-N',
              '-L',
              `127.0.0.1:${localPort}:${cpeHost}:${cpePort}`,
              `${username}@${pfHost}`,
            ],
            {
              stdio: ['ignore', 'ignore', 'pipe'],
              env: { ...process.env, SSHPASS: password },
            },
          );
          let stderr = '';
          let settled = false;
          const settle = (fn: () => void) => {
            if (settled) return;
            settled = true;
            clearTimeout(failTimer);
            fn();
          };
          ssh.stderr?.on('data', (c: Buffer) => {
            stderr += c.toString();
          });
          const failTimer = setTimeout(() => {
            if (ssh.exitCode == null && !ssh.killed) {
              settle(() => resolve({ localPort, ssh }));
            }
          }, 1_200);
          ssh.once('error', (error) => settle(() => reject(error)));
          ssh.once('exit', (code) => {
            settle(() =>
              reject(new Error(`ssh tunnel exited (${code}): ${stderr.slice(0, 240)}`)),
            );
          });
          setTimeout(() => {
            const test = netConnect({ host: '127.0.0.1', port: localPort });
            test.setTimeout(1_500);
            test.once('connect', () => {
              test.destroy();
              settle(() => resolve({ localPort, ssh }));
            });
            test.once('error', () => {
              /* wait */
            });
          }, 500);
        })
        .catch(reject);
    });
  }

  private rewriteHtml(html: string, session: ActiveSession, requestPath: string): string {
    const meta = session.meta;
    const proxyPath = meta.proxyPath;
    const baseHref = proxyBaseHref(proxyPath, requestPath);
    const fragment = isHtmlFragment(html);
    let out = html;
    out = out.replace(
      /\b(src|href|action|poster|data)\s*=\s*(["'])\/(?!\/)/gi,
      (match, attr: string, quote: string) => {
        const after = match.slice(match.indexOf(quote) + 1);
        if (after.startsWith(proxyPath) || after.startsWith('/api/admin/cpe/proxy/')) return match;
        return `${attr}=${quote}${proxyPath}`;
      },
    );
    out = this.rewriteCssUrls(out, proxyPath);
    // Inline JS often assigns frame/iframe src to absolute CPE paths (Vivo Sophia).
    out = this.rewriteJsRootPaths(out, meta);
    out = this.rewriteLoginTopRedirects(out, meta);
    out = this.rewriteSafeParentFrameCalls(out);
    const originRe = new RegExp(
      `(["'])https?:\\/\\/${escapeRegExp(meta.ip)}(?::${meta.port})?\\/`,
      'gi',
    );
    out = out.replace(originRe, `$1${proxyPath}`);

    // Bust browser disk cache for assets previously poisoned by HTML-inject-into-JS.
    out = this.bustCachedAssetUrls(out);
    // <base href=".../cgi-bin/"> makes href="#" navigate to cgi-bin/# (kills accordion,
    // Salvar, Cancelar, tabs, etc. mid-handler).
    out = this.rewriteHashHrefs(out);

    // AJAX fragments (SelectIndex, mac lists, etc.) must NOT get <base>/fetch patches —
    // jQuery .load() injects them into the DOM and a leading <script> breaks the UI.
    if (fragment) return out;

    out = this.injectBaseHref(out, baseHref);
    out = this.injectFetchPatch(out, meta);
    // Always offer auto-login on login pages while we have stored credentials.
    // Browser sessionStorage prevents repeat submit loops; Open UI in a new tab retries.
    if (session.password && looksLikeLoginPage(out)) {
      out = this.injectAutoLogin(out, meta.username, session.password, meta.id);
      if (session.autoLogin) {
        session.autoLogin = false;
        void this.store.updateAutoLogin(meta.id, false);
      }
    }
    return out;
  }

  private rewriteRefererHeader(
    referer: string | string[] | undefined,
    meta: CpeAccessSession,
    hostPort: string,
  ): string {
    const origin = `${meta.tls ? 'https' : 'http'}://${hostPort}`;
    const value = Array.isArray(referer) ? referer[0] : referer;
    if (!value) return `${origin}/`;
    try {
      const u = new URL(value);
      const marker = '/api/admin/cpe/proxy/';
      const idx = u.pathname.indexOf(marker);
      if (idx >= 0) {
        const after = u.pathname.slice(idx + marker.length);
        const slash = after.indexOf('/');
        const rest = slash >= 0 ? after.slice(slash) : '/';
        return `${origin}${rest || '/'}${u.search}`;
      }
      return value;
    } catch {
      return `${origin}/`;
    }
  }

  private injectFetchPatch(html: string, meta: CpeAccessSession): string {
    const prefix = meta.proxyPath.replace(/\/$/, '');
    const origins = JSON.stringify([
      `http://${meta.ip}`,
      `https://${meta.ip}`,
      `http://${meta.ip}:${meta.port}`,
      `https://${meta.ip}:${meta.port}`,
    ]);
    // URL rewriting for XHR/fetch/frame src + Vivo frameset shims:
    // - unnest sophia_index if it lands in menufrm (breaks target=basefrm)
    // - retarget menu links to top.document's basefrm frame element
    // - mark ns-in-frame so we can hide duplicate nav chrome inside basefrm
    // - never let parent.frames["menufrm"].MenuMask* throw (blocks Salvar / $.post)
    const script = `<script>(function(){var P=${JSON.stringify(prefix)};var O=${origins};function fix(u){if(typeof u!=="string"||!u)return u;if(u.charAt(0)==="/"&&u.charAt(1)!=="/"&&u.indexOf(P)!==0)return P+u;for(var i=0;i<O.length;i++){if(u.indexOf(O[i])===0)return P+u.slice(O[i].length);}return u;}try{var wn0=String(window.name||"");var href0=String(location.href||"");if(wn0==="menufrm"&&/sophia_index\\.cgi/i.test(href0)){location.replace(P+"/cgi-bin/sophia_menu.cgi");return;}if(wn0==="header"&&/sophia_index\\.cgi/i.test(href0)){location.replace(P+"/cgi-bin/sophia_header.cgi");return;}if(wn0==="basefrm"&&/sophia_index\\.cgi/i.test(href0)){location.replace(P+"/cgi-bin/sophia_info.cgi");return;}}catch(e0){}function nsUnnest(){try{var wn=String(window.name||"");if(!wn||wn==="")return;if(!document.getElementsByTagName("frameset").length)return;if(wn==="menufrm")location.replace(P+"/cgi-bin/sophia_menu.cgi");else if(wn==="header")location.replace(P+"/cgi-bin/sophia_header.cgi");else if(wn==="basefrm")location.replace(P+"/cgi-bin/sophia_info.cgi");else if(wn==="left"||wn==="right")location.replace(P+"/cgi-bin/html_sophia/sophia_side.html");}catch(e){}}if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",nsUnnest);else nsUnnest();var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(u);return xo.apply(this,arguments);};if(window.fetch){var f=window.fetch;window.fetch=function(i,init){if(typeof i==="string")i=fix(i);else if(i&&typeof i.url==="string")i=new Request(fix(i.url),i);return f.call(this,i,init);};}var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){n=String(n);if(n==="src"||n==="href"||n==="action")v=fix(String(v));return sa.call(this,n,v);};try{var desc=Object.getOwnPropertyDescriptor(HTMLFrameElement.prototype,"src")||Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,"src");if(desc&&desc.set){var set=desc.set;Object.defineProperty(HTMLFrameElement.prototype,"src",{configurable:true,enumerable:true,get:desc.get,set:function(v){return set.call(this,fix(String(v)));}});Object.defineProperty(HTMLIFrameElement.prototype,"src",{configurable:true,enumerable:true,get:desc.get,set:function(v){return set.call(this,fix(String(v)));}});}var la=Location.prototype.assign;Location.prototype.assign=function(u){return la.call(this,fix(String(u)));};var lr=Location.prototype.replace;Location.prototype.replace=function(u){return lr.call(this,fix(String(u)));};}catch(e){}try{document.addEventListener("click",function(ev){try{var el=ev.target;while(el&&el.nodeType===1&&String(el.tagName||"").toUpperCase()!=="A")el=el.parentElement;if(!el||!el.getAttribute)return;var href=String(el.getAttribute("href")||"");if(href==="#"||href===""){ev.preventDefault();}if(href.indexOf("javascript:")===0){ev.preventDefault();}if(String(el.getAttribute("target")||"")!=="basefrm")return;if(!href||href.charAt(0)==="#"||href.indexOf("javascript:")===0)return;var list=window.top.document.getElementsByName("basefrm");if(!list||!list.length)return;ev.preventDefault();ev.stopPropagation();var abs=el.href||href;list[0].setAttribute("src",fix(String(abs)));}catch(eC){}},true);}catch(eClick){}try{if(window.top!==window.self&&String(window.name||"")==="basefrm"){document.documentElement.classList.add("ns-in-frame");var st=document.createElement("style");st.textContent="html.ns-in-frame #accordion,html.ns-in-frame body>#menu,html.ns-in-frame .ns-hide-when-framed{display:none!important;}html.ns-in-frame #content{margin-left:0!important;width:auto!important;}";(document.head||document.documentElement).appendChild(st);} }catch(e){}try{var NOP={MenuMaskopen:function(){},MenuMaskclose:function(){}};function mask(w){try{if(!w)return NOP;if(typeof w.MenuMaskopen!=="function")w.MenuMaskopen=NOP.MenuMaskopen;if(typeof w.MenuMaskclose!=="function")w.MenuMaskclose=NOP.MenuMaskclose;return w;}catch(e){return NOP;}}if(window.parent&&window.parent!==window){var pf=window.parent.frames;if(pf){["menufrm","header","left","right","basefrm"].forEach(function(n){try{if(!pf[n]){try{pf[n]=NOP;}catch(e2){}}else mask(pf[n]);}catch(e3){}});var _menufrm;try{_menufrm=pf.menufrm||pf["menufrm"];}catch(e4){_menufrm=null;}if(!_menufrm){try{Object.defineProperty(pf,"menufrm",{configurable:true,get:function(){return NOP;}});}catch(e5){}}}}}catch(e6){}})();</script>`;
    if (/<head[^>]*>/i.test(html)) {
      return html.replace(/<head([^>]*)>/i, `<head$1>${script}`);
    }
    return `${script}${html}`;
  }

  /** Vivo content pages call parent.frames["menufrm"].MenuMask* before $.post — must not throw. */
  private rewriteSafeParentFrameCalls(body: string): string {
    return body.replace(
      /parent\.frames\s*\[\s*(["'])(menufrm|header|left|right|basefrm)\1\s*\]\s*\.\s*(MenuMask(?:open|close))\s*\(\s*\)/gi,
      (_m, quote: string, frame: string, method: string) =>
        `(()=>{try{var f=parent.frames[${quote}${frame}${quote}];if(f&&typeof f.${method}==="function")f.${method}();}catch(e){}})()`,
    );
  }

  private bustCachedAssetUrls(html: string): string {
    const v = 'nsv=4';
    return html.replace(
      /\b(src|href)\s*=\s*(["'])([^"']+\.(?:m?js|css))(?:\?[^"']*)?\2/gi,
      (_m, attr: string, quote: string, path: string) => {
        const bare = path.split('?')[0] ?? path;
        if (/\bnsv=\d+\b/.test(path)) {
          return `${attr}=${quote}${path.replace(/\bnsv=\d+\b/, 'nsv=4')}${quote}`;
        }
        return `${attr}=${quote}${bare}?${v}${quote}`;
      },
    );
  }

  /** Any href="#" + <base href=".../cgi-bin/"> navigates the frame away mid-click. */
  private rewriteHashHrefs(html: string): string {
    return html.replace(/\bhref\s*=\s*(["'])#\1/gi, 'href="javascript:void(0)"');
  }

  /**
   * Login / language helpers often do parent.location = "sophia_index.cgi".
   * Inside a nested frame that loads the full frameset into menufrm and breaks menus.
   */
  private rewriteLoginTopRedirects(body: string, meta: CpeAccessSession): string {
    const prefix = meta.proxyPath.replace(/\/$/, '');
    const absIndex = `${prefix}/cgi-bin/sophia_index.cgi`;
    return body
      .replace(
        /\b(?:window\.)?parent\.location(?:\.href)?\s*=\s*(["'])([^"']*sophia_index\.cgi[^"']*)\1/gi,
        (_m, quote: string) => `window.top.location.href=${quote}${absIndex}${quote}`,
      )
      .replace(
        /\b(?:window\.)?parent\.location\.reload\s*\(\s*\)/gi,
        'window.top.location.reload()',
      )
      .replace(
        /(["'])(?:https?:\/\/[^"']+)?(?:\/api\/admin\/cpe\/proxy\/[^/"']+)?\/cgi-bin\/html_sophia\/sophia_index\.cgi\1/gi,
        `$1${absIndex}$1`,
      );
  }

  private rewriteJsRootPaths(body: string, meta: CpeAccessSession): string {
    const proxyPath = meta.proxyPath;
    return body.replace(
      /(["'])\/((?:js|css|img|images|static|html|cgi-bin|api|authenticate|login|modals|ws|websocket|lua|ubus)[^"']*)\1/gi,
      (match, quote: string, path: string) => {
        if (path.startsWith(proxyPath.replace(/^\//, '')) || match.includes('/api/admin/cpe/proxy/')) {
          return match;
        }
        return `${quote}${proxyPath}${path}${quote}`;
      },
    );
  }

  private injectBaseHref(html: string, proxyPath: string): string {
    // Preserve existing base attributes (Vivo header uses <base target="_top">).
    if (/<base\s/i.test(html)) {
      return html.replace(/<base\s([^>]*)>/i, (_m, attrs: string) => {
        let next = String(attrs).trim();
        if (/\bhref\s*=/i.test(next)) {
          next = next.replace(/\bhref\s*=\s*(["'])[\s\S]*?\1/i, `href="${proxyPath}"`);
        } else {
          next = `href="${proxyPath}" ${next}`;
        }
        return `<base ${next}>`;
      });
    }
    if (/<head[^>]*>/i.test(html)) {
      return html.replace(/<head([^>]*)>/i, `<head$1><base href="${proxyPath}">`);
    }
    return `<base href="${proxyPath}">${html}`;
  }

  private injectAutoLogin(
    html: string,
    username: string,
    password: string,
    sessionId: string,
  ): string {
    // Vivo: clicklogin() hashes into LoginPasswordValue — must form.submit() after.
    // Claro: #btnApply jQuery handler runs SRP — must .trigger("click"), never form.submit().
    // Cooldown (not one-shot): login may reappear in a frame if the CPE session lapsed.
    const script = `<script>(function(){var u=${JSON.stringify(username)};var p=${JSON.stringify(password)};var sk=${JSON.stringify(`nsCpeAl:${sessionId}`)};try{var last=Number(sessionStorage.getItem(sk)||0);if(Date.now()-last<12000)return;sessionStorage.setItem(sk,String(Date.now()));}catch(e){}function fill(user,pass){user.value=u;pass.value=p;try{user.dispatchEvent(new Event("input",{bubbles:true}));pass.dispatchEvent(new Event("input",{bubbles:true}));user.dispatchEvent(new Event("change",{bubbles:true}));pass.dispatchEvent(new Event("change",{bubbles:true}));}catch(e){}}function submitLogin(btn,form){try{if(typeof window.clicklogin==="function"){window.clicklogin(1);if(form)form.submit();return;}if(btn&&btn.id==="btnApply"&&window.jQuery){window.jQuery(btn).trigger("click");return;}if(btn){btn.click();return;}if(form)form.submit();}catch(e){try{if(btn)btn.click();else if(form)form.submit();}catch(e2){}}}function go(n){var user=document.getElementById("username")||document.getElementById("Loginuser")||document.querySelector("input[name=Login],input[name=Loginuser],input[name=username],input[type=text]");var pass=document.getElementById("password")||document.getElementById("LoginPassword")||document.querySelector("input[name=Password],input[name=LoginPassword],input[type=password]");var btn=document.getElementById("btnApply")||document.getElementById("acceptLogin")||document.querySelector("button[type=submit],input[type=submit],button.button");var form=document.getElementById("login")||document.forms.passWarning||document.forms.login||(user&&user.form)||null;var needJQ=!!document.getElementById("btnApply");if(needJQ&&!window.jQuery){if(n<120)setTimeout(function(){go(n+1);},100);return;}if(user&&pass&&(btn||form)){fill(user,pass);setTimeout(function(){submitLogin(btn,form);},700);return;}if(n<120)setTimeout(function(){go(n+1);},100);}if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",function(){go(0);});else go(0);})();</script>`;
    if (/<\/body>/i.test(html)) {
      return html.replace(/<\/body>/i, `${script}</body>`);
    }
    return `${html}${script}`;
  }

  private rewriteCssUrls(css: string, proxyPath: string): string {
    return css.replace(/url\(\s*(['"]?)(\/(?!\/)[^)'"]*)(['"]?)\s*\)/gi, (match, q1: string, path: string, q2: string) => {
      if (path.startsWith(proxyPath) || path.startsWith('/api/admin/cpe/proxy/')) return match;
      return `url(${q1}${proxyPath}${path.slice(1)}${q2})`;
    });
  }

  private rewriteLocation(meta: CpeAccessSession, location: string): string {
    try {
      const base = `${meta.tls ? 'https' : 'http'}://${meta.ip}:${meta.port}/`;
      const abs = new URL(location, base);
      if (abs.hostname === meta.ip) {
        return `${meta.proxyPath}${abs.pathname.replace(/^\//, '')}${abs.search}${abs.hash}`;
      }
      return location;
    } catch {
      if (location.startsWith('/')) return `${meta.proxyPath}${location.slice(1)}`;
      return location;
    }
  }
}

function rewriteSetCookie(cookie: string, cookiePath: string): string {
  let next = cookie.replace(/;\s*Domain=[^;]*/gi, '');
  next = next.replace(/;\s*Secure/gi, '');
  if (/;\s*Path=/i.test(next)) {
    next = next.replace(/;\s*Path=[^;]*/i, `; Path=${cookiePath}`);
  } else {
    next = `${next}; Path=${cookiePath}`;
  }
  if (/;\s*SameSite=/i.test(next)) {
    next = next.replace(/;\s*SameSite=[^;]*/i, '; SameSite=Lax');
  } else {
    next = `${next}; SameSite=Lax`;
  }
  return next;
}

function rememberUpstreamCookie(jar: Map<string, string>, setCookie: string): void {
  const first = setCookie.split(';')[0] ?? '';
  const eq = first.indexOf('=');
  if (eq <= 0) return;
  const name = first.slice(0, eq).trim();
  const value = first.slice(eq + 1).trim();
  if (!name) return;
  const expired =
    value === '' ||
    /;\s*Max-Age=\s*0\b/i.test(setCookie) ||
    /;\s*Expires=[^;]*(1970|1 Jan 1970)/i.test(setCookie);
  if (expired) jar.delete(name);
  else jar.set(name, value);
}

function mergeCookieHeader(
  existing: string | string[] | undefined,
  jar: Map<string, string>,
): string {
  const map = new Map<string, string>();
  const raw = Array.isArray(existing) ? existing.join('; ') : (existing ?? '');
  for (const part of raw.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    map.set(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim());
  }
  for (const [name, value] of jar) map.set(name, value);
  return [...map.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function readIncomingBody(request: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function proxyBaseHref(proxyPath: string, requestPath: string): string {
  const pathOnly = (requestPath.split('?')[0] || '/').split('#')[0] || '/';
  const lastSlash = pathOnly.lastIndexOf('/');
  const dir = lastSlash <= 0 ? '/' : pathOnly.slice(0, lastSlash + 1);
  if (dir === '/') return proxyPath;
  return `${proxyPath}${dir.replace(/^\//, '')}`;
}

function isBinaryAssetPath(pathAndQuery: string): boolean {
  return /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|webp|ico|bmp|mp3|mp4|webm|wasm|zip|gz|pdf|swf)(\?|#|$)/i.test(
    pathAndQuery,
  );
}

function contentTypeForBinaryPath(pathAndQuery: string): string | null {
  const path = pathAndQuery.split('?')[0]?.split('#')[0] ?? '';
  if (/\.woff2$/i.test(path)) return 'font/woff2';
  if (/\.woff$/i.test(path)) return 'font/woff';
  if (/\.ttf$/i.test(path)) return 'font/ttf';
  if (/\.otf$/i.test(path)) return 'font/otf';
  if (/\.eot$/i.test(path)) return 'application/vnd.ms-fontobject';
  if (/\.png$/i.test(path)) return 'image/png';
  if (/\.jpe?g$/i.test(path)) return 'image/jpeg';
  if (/\.gif$/i.test(path)) return 'image/gif';
  if (/\.webp$/i.test(path)) return 'image/webp';
  if (/\.ico$/i.test(path)) return 'image/x-icon';
  return null;
}

function looksLikeBinaryBuffer(buf: Buffer): boolean {
  if (buf.length >= 4) {
    const mag = buf.toString('ascii', 0, 4);
    if (mag === 'wOFF' || mag === 'wOF2' || mag === 'OTTO' || mag === 'ttcf') return true;
    if (buf[0] === 0x00 && buf[1] === 0x01 && buf[2] === 0x00 && buf[3] === 0x00) return true; // TTF
    if (buf[0] === 0x89 && mag.startsWith('PNG')) return true;
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return true; // JPEG
    if (mag.startsWith('GIF8')) return true;
  }
  const sample = buf.subarray(0, Math.min(512, buf.length));
  return sample.includes(0);
}

function isHtmlFragment(html: string): boolean {
  const trimmed = html.trimStart();
  if (!trimmed) return true;
  const head = trimmed.slice(0, 800).toLowerCase();
  if (
    head.includes('<!doctype') ||
    head.includes('<html') ||
    head.includes('<frameset') ||
    head.startsWith('<head')
  ) {
    return false;
  }
  // Full pages usually open with <html>/<head>/<body>; Sophia AJAX snippets start with
  // <script>, <select>, <option>, bare <body> fragments, etc.
  const hasHead = /<head[\s>]/i.test(trimmed.slice(0, 4000));
  const hasBody = /<body[\s>]/i.test(trimmed.slice(0, 8000));
  if (hasHead && hasBody) return false;
  if (hasBody && /<div[\s>]/i.test(trimmed.slice(0, 8000))) return false;
  return true;
}

function isHtmlPayload(ctype: string, body: string): boolean {
  if (ctype.includes('text/html') || ctype.includes('xhtml')) return true;
  const head = body.slice(0, 800).toLowerCase();
  // Do NOT sniff on bare "<script" — minified JS (jQuery) embeds that string.
  return (
    head.includes('<html') ||
    head.includes('<!doctype html') ||
    head.includes('<frameset') ||
    /<frame[\s>]/i.test(head) ||
    /<head[\s>]/i.test(head) ||
    /<body[\s>]/i.test(head)
  );
}

function looksLikeCss(body: string): boolean {
  const head = body.slice(0, 400);
  return /\{[^}]*[a-z-]+\s*:/.test(head) || head.includes('@media') || head.includes('@font-face');
}

function looksLikeJs(body: string, path: string): boolean {
  if (/\.js(\?|$)/i.test(path)) return true;
  const head = body.slice(0, 200).trimStart();
  return (
    head.startsWith('function') ||
    head.startsWith('var ') ||
    head.startsWith('let ') ||
    head.startsWith('const ') ||
    head.startsWith('(function') ||
    head.startsWith('/*!')
  );
}

function looksLikeLoginPage(html: string): boolean {
  const lower = html.toLowerCase();
  if (!lower.includes('password') && !lower.includes('senha') && !lower.includes('loginpassword')) {
    return false;
  }
  return (
    /id\s*=\s*["']username["']/i.test(html) ||
    /id\s*=\s*["']loginuser["']/i.test(html) ||
    /id\s*=\s*["']btnapply["']/i.test(html) ||
    /id\s*=\s*["']acceptlogin["']/i.test(html) ||
    /name\s*=\s*["']login["']/i.test(html) ||
    /srp-min\.js/i.test(html) ||
    /sign-me-in/i.test(html) ||
    /conecte-se/i.test(html) ||
    /entrar/i.test(html) ||
    /login\.cgi/i.test(html) ||
    /autentica/i.test(html)
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function reserveLocalPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server: NetServer = createServer();
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      server.close((err) => {
        if (err) reject(err);
        else if (!addr || typeof addr === 'string') reject(new Error('no local port'));
        else resolve(addr.port);
      });
    });
    server.on('error', reject);
  });
}
