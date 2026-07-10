import type { Logger } from '@netscanner/logger';
import { spawn } from 'node:child_process';
import {
  NS_ALIAS_AUTOBLOCK,
  NS_ALIAS_BLOCK,
  NS_ALIAS_DNS_BLOCK,
  NS_ALIAS_DNS_SRC,
  NS_ALIAS_DEST_BLOCK,
  NS_ALIAS_DEST_SRC,
  NS_ALIAS_PAUSED,
  NS_ALIAS_ROUTE_LB,
  NS_ALIAS_ROUTE_VPN,
  NS_ALIAS_ROUTE_WAN,
  routeAliasForGateway,
  type ControlBootstrap,
  type ControlVerifyCheck,
  type ControlVerifyResult,
  type DhcpReservationRequest,
} from '@netscanner/contracts';
import { PfSenseHttpClient, type PfSenseHttpConfig } from './pfsense-http-client.js';

export type AliasName = string;

export interface PfSenseControlSshConfig {
  host: string;
  port?: number;
  username?: string;
  password?: string;
}

const BOOTSTRAP_ALIASES: Array<{ name: string; type: 'host' | 'network' | 'port' }> = [
  { name: NS_ALIAS_BLOCK, type: 'host' },
  { name: NS_ALIAS_PAUSED, type: 'host' },
  { name: NS_ALIAS_AUTOBLOCK, type: 'host' },
  // pfSense REST only allows host|network|port — FQDNs go in a host alias (resolved by pfSense).
  { name: NS_ALIAS_DNS_BLOCK, type: 'host' },
  { name: NS_ALIAS_DNS_SRC, type: 'host' },
  { name: NS_ALIAS_DEST_BLOCK, type: 'network' },
  { name: NS_ALIAS_DEST_SRC, type: 'host' },
  { name: NS_ALIAS_ROUTE_WAN, type: 'host' },
  { name: NS_ALIAS_ROUTE_LB, type: 'host' },
  { name: NS_ALIAS_ROUTE_VPN, type: 'host' },
];

/** pfSense REST write operations for NetScanner network control. */
export class PfSenseRestControlAdapter {
  readonly client: PfSenseHttpClient;

  constructor(
    config: PfSenseHttpConfig,
    private readonly logger: Logger,
    private readonly ssh?: PfSenseControlSshConfig | null,
  ) {
    this.client = new PfSenseHttpClient(config);
  }

  async checkBootstrap(): Promise<ControlBootstrap> {
    const aliases: Record<string, boolean> = {};
    for (const { name } of BOOTSTRAP_ALIASES) {
      aliases[name] = await this.aliasExists(name);
    }
    const ready = Boolean(aliases[NS_ALIAS_BLOCK] && aliases[NS_ALIAS_PAUSED]);
    const limiters: Record<string, boolean> = {
      NS_LIMIT: await this.limiterExists('NS_LIMIT'),
      NS_LIMIT_IN: await this.limiterExists('NS_LIMIT_IN'),
      NS_LIMIT_OUT: await this.limiterExists('NS_LIMIT_OUT'),
      NS_IN: await this.limiterExists('NS_IN'),
      NS_OUT: await this.limiterExists('NS_OUT'),
    };
    return {
      ready,
      aliases,
      limiters,
      schedules: (await this.listSchedules()).length,
      message: ready ? undefined : 'Run POST /api/control/bootstrap to create NetScanner aliases',
    };
  }

  /** Probe IP in RFC 5737 documentation range — safe for alias round-trip tests. */
  private static readonly VERIFY_PROBE_IP = '198.18.0.254';

  async verify(): Promise<ControlVerifyResult> {
    const checks: ControlVerifyCheck[] = [];
    const ranAt = new Date().toISOString();
    const push = (check: ControlVerifyCheck) => checks.push(check);

    let rules: Record<string, unknown>[] = [];
    try {
      rules = this.client.extractArray(await this.client.get('/api/v2/firewall/rules'));
      push({ id: 'api', label: 'pfSense API reachable', status: 'pass' });
    } catch (error) {
      push({
        id: 'api',
        label: 'pfSense API reachable',
        status: 'fail',
        detail: error instanceof Error ? error.message : String(error),
      });
      return { ok: false, checks, ranAt };
    }

    for (const name of [NS_ALIAS_BLOCK, NS_ALIAS_PAUSED, NS_ALIAS_AUTOBLOCK, 'NS_LIMIT']) {
      const exists = await this.aliasExists(name);
      push({
        id: `alias-${name}`,
        label: `Alias ${name}`,
        status: exists ? 'pass' : 'fail',
        detail: exists ? undefined : 'Run bootstrap or create manually in pfSense',
      });
    }

    this.verifyBlockRule(rules, push);
    this.verifyAliasRule(rules, 'PAUSE', NS_ALIAS_PAUSED, push);
    this.verifyAliasRule(rules, 'AUTOBLOCK', NS_ALIAS_AUTOBLOCK, push);
    this.verifyDnsBlockRule(rules, push);
    this.verifyDestBlockRule(rules, push);
    this.verifyRouteRules(rules, push);
    this.verifyBandwidthRules(rules, push);
    await this.verifyLimiters(push);
    await this.verifyAliasWrite(push);

    const ok = !checks.some((c) => c.status === 'fail');
    return { ok, checks, ranAt };
  }

  async bootstrap(): Promise<ControlBootstrap> {
    const errors: string[] = [];
    for (const { name, type } of BOOTSTRAP_ALIASES) {
      try {
        if (!(await this.aliasExists(name))) {
          await this.client.post('/api/v2/firewall/alias', {
            name,
            type,
            address: [],
            descr: `NetScanner ${name}`,
          });
          this.logger.info({ name, type }, 'created pfSense alias');
        }
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        errors.push(`${name}: ${msg}`);
        this.logger.warn({ name, type, error: msg }, 'alias bootstrap failed');
      }
    }
    if (!(await this.limiterExists('NS_LIMIT'))) {
      try {
        await this.client.post('/api/v2/firewall/traffic_shaper/limiter', {
          name: 'NS_LIMIT',
          enabled: true,
          bandwidth: [{ bw: '1', bwscale: 'Mbit', bwsched: 'none' }],
          queue: [],
        });
      } catch (error) {
        this.logger.warn({ error }, 'limiter bootstrap skipped (may need manual shaper setup)');
      }
    }
    try {
      await this.ensureAllPolicyRules();
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      errors.push(`rules: ${msg}`);
      this.logger.warn({ error: msg }, 'policy rule bootstrap failed');
    }
    const result = await this.checkBootstrap();
    if (errors.length) {
      return {
        ...result,
        message: `Bootstrap partial: ${errors.slice(0, 3).join('; ')}${errors.length > 3 ? '…' : ''}`,
      };
    }
    return result;
  }

  /** Ensure floating block rules for DNS/dest aliases exist. */
  async ensureDnsDestRules(): Promise<void> {
    await this.ensureAllPolicyRules();
  }

  /** Ensure all NetScanner floating rules for known aliases. */
  async ensureAllPolicyRules(): Promise<void> {
    const ifaces = ['opt3', 'opt4', 'opt5', 'opt6'];
    await this.ensureFloatingRule({
      type: 'block',
      descr: 'NetScanner BLOCK',
      src: NS_ALIAS_BLOCK,
      dst: 'any',
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'block',
      descr: 'NetScanner PAUSE',
      src: NS_ALIAS_PAUSED,
      dst: 'any',
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'block',
      descr: 'NetScanner AUTOBLOCK',
      src: NS_ALIAS_AUTOBLOCK,
      dst: 'any',
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'block',
      descr: 'NetScanner DNS BLOCK',
      src: NS_ALIAS_DNS_SRC,
      dst: NS_ALIAS_DNS_BLOCK,
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'block',
      descr: 'NetScanner DEST BLOCK',
      src: NS_ALIAS_DEST_SRC,
      dst: NS_ALIAS_DEST_BLOCK,
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'pass',
      descr: 'NetScanner ROUTE WAN_DHCP',
      src: NS_ALIAS_ROUTE_WAN,
      dst: 'any',
      gateway: 'WAN_DHCP',
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'pass',
      descr: 'NetScanner ROUTE LB_WAN',
      src: NS_ALIAS_ROUTE_LB,
      dst: 'any',
      gateway: 'LB_WAN',
      interfaces: ifaces,
    });
    await this.ensureFloatingRule({
      type: 'pass',
      descr: 'NetScanner ROUTE SSVPN_Failover',
      src: NS_ALIAS_ROUTE_VPN,
      dst: 'any',
      gateway: 'SSVPN_Failover',
      interfaces: ifaces,
    });
  }

  /**
   * Ensure host alias + floating pass rule with Gateway column for policy routing.
   * Returns whether a new floating rule had to be created (needs full filter reload).
   */
  async ensureRouteGateway(gatewayName: string): Promise<{ alias: string; ruleCreated: boolean }> {
    const alias = routeAliasForGateway(gatewayName);
    await this.ensureHostAlias(alias, `NetScanner route → ${gatewayName}`);
    const ruleCreated = await this.ensureFloatingRule({
      type: 'pass',
      descr: `NetScanner ROUTE ${gatewayName}`,
      src: alias,
      dst: 'any',
      gateway: gatewayName,
    });
    return { alias, ruleCreated };
  }

  async ensureHostAlias(name: string, descr: string): Promise<void> {
    if (await this.aliasExists(name)) return;
    await this.client.post('/api/v2/firewall/alias', {
      name,
      type: 'host',
      address: [],
      descr,
    });
    this.logger.info({ name }, 'created pfSense route alias');
  }

  /** List all NetScanner route aliases (NS_RT_* and legacy NS_ROUTE_*). */
  async listRouteAliases(): Promise<string[]> {
    const rows = this.client.extractArray(await this.client.get('/api/v2/firewall/aliases'));
    return rows
      .map((r) => String(r.name ?? ''))
      .filter((n) => n.startsWith('NS_RT_') || n.startsWith('NS_ROUTE_'));
  }

  private async ensureFloatingRule(opts: {
    type: 'block' | 'pass';
    descr: string;
    src: string;
    dst: string;
    gateway?: string;
    interfaces?: string[];
  }): Promise<boolean> {
    let rules: Record<string, unknown>[] = [];
    try {
      rules = this.client.extractArray(await this.client.get('/api/v2/firewall/rules?limit=200'));
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : error, descr: opts.descr },
        'could not list firewall rules — will try create anyway',
      );
    }
    const existing = rules.find(
      (r) =>
        String(r.descr ?? '') === opts.descr ||
        (String(r.descr ?? '').includes(opts.descr.replace(/^NetScanner\s+/i, '')) &&
          String(r.source ?? r.src ?? '') === opts.src),
    );
    // Policy routing (Gateway column) only works on inbound floating rules.
    const direction = opts.gateway ? 'in' : 'any';
    if (existing) {
      const id = existing.id;
      const gw = String(existing.gateway ?? '');
      const dir = String(existing.direction ?? '');
      const needsPatch =
        id != null &&
        ((opts.gateway && gw !== opts.gateway) || (opts.gateway && dir !== 'in'));
      if (needsPatch) {
        try {
          await this.client.patch('/api/v2/firewall/rule', {
            id,
            direction: 'in',
            ...(opts.gateway ? { gateway: opts.gateway } : {}),
          }, false);
          this.logger.info(
            { descr: opts.descr, id, gateway: opts.gateway, previousDirection: dir },
            'updated floating route rule direction/gateway',
          );
          return true;
        } catch (error) {
          this.logger.warn(
            {
              descr: opts.descr,
              error: error instanceof Error ? error.message : error,
            },
            'failed to patch floating route rule',
          );
        }
      } else if (opts.gateway && gw && gw !== opts.gateway) {
        this.logger.warn(
          { descr: opts.descr, existingGateway: gw, wanted: opts.gateway },
          'route rule exists with different gateway — leaving as-is',
        );
      }
      return false;
    }
    const interfaces = opts.interfaces?.length ? opts.interfaces : ['opt3', 'opt4', 'opt5', 'opt6'];
    const body: Record<string, unknown> = {
      type: opts.type,
      floating: true,
      quick: true,
      interface: interfaces,
      direction,
      ipprotocol: 'inet',
      // Omit protocol — pfSense REST rejects "any"; null/omit means all protocols.
      source: opts.src,
      destination: opts.dst,
      descr: opts.descr,
      disabled: false,
      log: false,
    };
    if (opts.gateway) body.gateway = opts.gateway;
    try {
      // apply=false — caller reloads once (full filter load is expensive).
      await this.client.post('/api/v2/firewall/rule', body, false);
      this.logger.info({ descr: opts.descr, gateway: opts.gateway }, 'created pfSense floating rule');
      return true;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (/already exists|duplicate|unique constraint/i.test(msg)) {
        this.logger.info({ descr: opts.descr }, 'floating rule already present');
        return false;
      }
      this.logger.warn(
        { descr: opts.descr, error: msg },
        'failed to create floating rule — create manually in pfSense',
      );
      throw error instanceof Error ? error : new Error(msg);
    }
  }

  /**
   * Push alias membership into the live pf table without regenerating the whole
   * ruleset. This is what makes route changes take effect immediately.
   */
  async syncHostAliasTable(alias: string, addresses: string[]): Promise<boolean> {
    if (!this.ssh?.host || !this.ssh.password) return false;
    const list = addresses.map((a) => JSON.stringify(a)).join(' ');
    const cmd =
      addresses.length === 0
        ? `pfctl -t ${JSON.stringify(alias)} -T flush 2>&1; echo NS_TBL_OK`
        : `pfctl -t ${JSON.stringify(alias)} -T replace ${list} 2>&1; echo NS_TBL_OK`;
    const out = await this.sshExec(cmd, 12_000);
    const ok = Boolean(out?.includes('NS_TBL_OK'));
    if (ok) this.logger.info({ alias, addresses }, 'synced live pf alias table');
    else this.logger.warn({ alias, out: out?.slice(0, 200) }, 'live pf alias table sync failed');
    return ok;
  }

  /** Remove a single address from a live pf table (no full flush). */
  async deleteFromHostAliasTable(alias: string, address: string): Promise<boolean> {
    if (!this.ssh?.host || !this.ssh.password) return false;
    const out = await this.sshExec(
      `pfctl -t ${JSON.stringify(alias)} -T delete ${JSON.stringify(address)} 2>&1; echo NS_TBL_OK`,
      8_000,
    );
    const ok = Boolean(out?.includes('NS_TBL_OK'));
    if (ok) this.logger.info({ alias, address }, 'deleted address from live pf alias table');
    return ok;
  }

  /**
   * Drop pf states for a source IP so a new gateway / block policy takes effect
   * immediately.
   */
  async killStatesForSource(ip: string): Promise<{ killed: boolean; via: 'rest' | 'ssh' | 'none' }> {
    if (this.ssh?.host && this.ssh.password) {
      const ok = await this.sshExec(
        `pfctl -k ${JSON.stringify(ip)} 2>&1; pfctl -k 0.0.0.0/0 -k ${JSON.stringify(ip)} 2>&1; echo OK`,
        12_000,
      );
      if (ok?.includes('OK')) {
        this.logger.info({ ip }, 'killed pfSense states via SSH pfctl');
        return { killed: true, via: 'ssh' };
      }
    }

    const queries = [
      `/api/v2/firewall/states?source__startswith=${encodeURIComponent(ip)}`,
      `/api/v2/firewall/states?source=${encodeURIComponent(ip)}`,
    ];
    for (const path of queries) {
      try {
        await this.client.delete(path, false);
        this.logger.info({ ip, path }, 'killed pfSense states for source');
        return { killed: true, via: 'rest' };
      } catch {
        /* try next */
      }
    }

    this.logger.warn(
      { ip },
      'could not kill pfSense states — reconnect device or reset states manually',
    );
    return { killed: false, via: 'none' };
  }

  /**
   * Force the generated ruleset into live pf. Only needed when a new floating
   * rule is created — membership changes use syncHostAliasTable instead.
   */
  async reloadFilter(): Promise<boolean> {
    if (!this.ssh?.host || !this.ssh.password) {
      this.logger.warn('filter reload: no SSH configured — live pf may stay stale');
      return false;
    }
    // Skip REST /firewall/apply — it often hangs when pfSense is busy.
    const out = await this.sshExec(
      [
        'php -r \'require_once("/etc/inc/config.inc"); require_once("/etc/inc/filter.inc"); filter_configure();\'',
        'pfctl -nf /tmp/rules.debug >/tmp/ns-pf-check.txt 2>&1',
        'if [ $? -eq 0 ]; then pfctl -f /tmp/rules.debug >/tmp/ns-pf-load.txt 2>&1 && echo NS_PF_OK; else echo NS_PF_BAD; cat /tmp/ns-pf-check.txt; fi',
      ].join('; '),
      25_000,
    );
    const ok = Boolean(out?.includes('NS_PF_OK'));
    if (ok) this.logger.info('pfSense filter reloaded into live pf');
    else this.logger.warn({ out: out?.slice(0, 400) }, 'pfSense filter reload failed');
    return ok;
  }

  private sshExec(remoteCmd: string, timeoutMs = 15_000): Promise<string | null> {
    if (!this.ssh?.host || !this.ssh.password) return Promise.resolve(null);
    const host = this.ssh.host;
    const port = this.ssh.port && this.ssh.port > 0 ? this.ssh.port : 22;
    const username = this.ssh.username?.trim() || 'admin';
    const password = this.ssh.password;
    const sshTail = [
      '-o',
      'StrictHostKeyChecking=accept-new',
      '-o',
      'ConnectTimeout=8',
      '-p',
      String(port),
      `${username}@${host}`,
      remoteCmd,
    ];

    return new Promise((resolve) => {
      const proc = spawn('sshpass', ['-e', 'ssh', '-o', 'BatchMode=no', ...sshTail], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, SSHPASS: password },
      });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try {
          proc.kill('SIGTERM');
        } catch {
          /* ignore */
        }
        this.logger.warn({ timeoutMs }, 'pfSense SSH command timed out');
        resolve(null);
      }, timeoutMs);
      proc.stdout?.setEncoding('utf8');
      proc.stdout?.on('data', (c: string) => {
        stdout += c;
      });
      proc.stderr?.setEncoding('utf8');
      proc.stderr?.on('data', (c: string) => {
        stderr += c;
      });
      proc.on('exit', (code) => {
        clearTimeout(timer);
        if (code !== 0 && !stdout) {
          this.logger.warn({ code, stderr: stderr.slice(0, 200) }, 'pfSense SSH command failed');
          resolve(null);
          return;
        }
        resolve(stdout);
      });
      proc.on('error', () => {
        clearTimeout(timer);
        resolve(null);
      });
    });
  }

  async addToAlias(alias: AliasName, address: string): Promise<void> {
    const entry = await this.getAlias(alias);
    if (!entry) throw new Error(`alias ${alias} not found — run bootstrap first`);
    const addresses = this.aliasAddresses(entry);
    if (addresses.includes(address)) return;
    await this.patchAliasAddresses(entry, [...addresses, address]);
    this.logger.info({ alias, address }, 'pfSense alias updated');
  }

  async removeFromAlias(alias: AliasName, address: string): Promise<void> {
    const entry = await this.getAlias(alias);
    if (!entry) return;
    const next = this.aliasAddresses(entry).filter((a) => a !== address);
    await this.patchAliasAddresses(entry, next);
    this.logger.info({ alias, address }, 'pfSense alias entry removed');
  }

  async listAliasAddresses(alias: AliasName): Promise<string[]> {
    const entry = await this.getAlias(alias);
    return entry ? this.aliasAddresses(entry) : [];
  }

  /** Replace alias contents (used when syncing policy maps). */
  async setAliasAddresses(alias: AliasName, addresses: string[]): Promise<void> {
    const entry = await this.getAlias(alias);
    if (!entry) throw new Error(`alias ${alias} not found — run bootstrap first`);
    const unique = [...new Set(addresses.map((a) => a.trim()).filter(Boolean))];
    await this.patchAliasAddresses(entry, unique);
    this.logger.info({ alias, count: unique.length }, 'pfSense alias synced');
  }

  /**
   * Sinkhole domains in Unbound (DNS Resolver) so clients that use pfSense DNS
   * get 0.0.0.0. Firewall IP aliases alone miss CDN / Private Relay traffic.
   */
  async syncDnsSinkholes(domains: string[]): Promise<void> {
    const wanted = new Set<string>();
    for (const raw of domains) {
      const d = normalizeDomain(raw);
      if (!d) continue;
      wanted.add(d);
      if (!d.startsWith('www.')) wanted.add(`www.${d}`);
    }

    let existing: Record<string, unknown>[] = [];
    try {
      existing = this.client.extractArray(
        await this.client.get('/api/v2/services/dns_resolver/host_overrides'),
      );
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'could not list DNS host overrides',
      );
      return;
    }

    const ours = existing.filter((r) => /NetScanner DNS block/i.test(String(r.descr ?? '')));
    const have = new Set(ours.map((r) => overrideFqdn(r)));

    for (const row of ours) {
      const fqdn = overrideFqdn(row);
      if (fqdn && !wanted.has(fqdn) && row.id != null) {
        try {
          await this.client.delete(
            `/api/v2/services/dns_resolver/host_override?id=${encodeURIComponent(String(row.id))}`,
            false,
          );
          have.delete(fqdn);
        } catch (error) {
          this.logger.warn(
            { fqdn, error: error instanceof Error ? error.message : error },
            'failed to remove DNS sinkhole',
          );
        }
      }
    }

    for (const fqdn of wanted) {
      if (have.has(fqdn)) continue;
      const parts = splitFqdn(fqdn);
      if (!parts) continue;
      try {
        await this.client.post(
          '/api/v2/services/dns_resolver/host_override',
          {
            host: parts.host,
            domain: parts.domain,
            ip: ['0.0.0.0'],
            descr: 'NetScanner DNS block',
          },
          true,
          20_000,
        );
        this.logger.info({ fqdn }, 'created DNS sinkhole host override');
      } catch (error) {
        this.logger.warn(
          { fqdn, error: error instanceof Error ? error.message : error },
          'failed to create DNS sinkhole',
        );
      }
    }

    try {
      await this.client.post('/api/v2/services/dns_resolver/apply', {});
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'DNS resolver apply failed — overrides may need manual apply',
      );
    }
  }

  async createDhcpReservation(req: DhcpReservationRequest): Promise<Record<string, unknown>> {
    const raw = await this.client.post('/api/v2/services/dhcp_server/static_mapping', {
      mac: req.mac,
      ipaddr: req.ip,
      hostname: req.hostname ?? '',
      descr: req.description ?? 'NetScanner reservation',
      interface: req.interface,
    });
    return this.client.extractObject(raw) ?? {};
  }

  async deleteDhcpReservation(id: string | number): Promise<void> {
    await this.client.delete(`/api/v2/services/dhcp_server/static_mapping/${id}`);
  }

  async listDhcpReservations(): Promise<Record<string, unknown>[]> {
    return this.client.extractArray(await this.client.get('/api/v2/services/dhcp_server/static_mappings'));
  }

  async createSchedule(name: string, weekdays: number[], start: string, end: string): Promise<Record<string, unknown>> {
    const raw = await this.client.post('/api/v2/firewall/schedule', {
      name,
      descr: `NetScanner parental ${name}`,
      timerange: [{ position: 1, month: '', day: weekdays.join(','), hour: `${start}-${end}` }],
    });
    return this.client.extractObject(raw) ?? { name };
  }

  async listSchedules(): Promise<Record<string, unknown>[]> {
    return this.client.extractArray(await this.client.get('/api/v2/firewall/schedules'));
  }

  private async aliasExists(name: string): Promise<boolean> {
    return (await this.getAlias(name)) != null;
  }

  private async limiterExists(name: string): Promise<boolean> {
    const rows = this.client.extractArray(await this.client.get('/api/v2/firewall/traffic_shaper/limiters'));
    return rows.some((r) => String(r.name ?? r.descr) === name);
  }

  private async getAlias(name: string): Promise<(Record<string, unknown> & { id: string | number }) | null> {
    const rows = this.client.extractArray(await this.client.get('/api/v2/firewall/aliases'));
    const hit = rows.find((r) => String(r.name) === name);
    if (!hit?.id) return null;
    return hit as Record<string, unknown> & { id: string | number };
  }

  private aliasAddresses(entry: Record<string, unknown>): string[] {
    const raw = entry.address ?? entry.addresses;
    if (Array.isArray(raw)) return raw.map(String);
    if (typeof raw === 'string') return raw.split('\n').map((s) => s.trim()).filter(Boolean);
    return [];
  }

  /** pfREST v2: PATCH /api/v2/firewall/alias with id in body (not /alias/{id}). */
  private async patchAliasAddresses(
    entry: Record<string, unknown> & { id: string | number },
    addresses: string[],
  ): Promise<void> {
    const hasFqdn = addresses.some((a) => !isIpOrCidr(a));
    await this.client.patch(
      '/api/v2/firewall/alias',
      {
        id: entry.id,
        name: entry.name,
        type: entry.type,
        descr: entry.descr ?? '',
        address: addresses,
        detail: entry.detail ?? [],
      },
      // FQDN host aliases need apply so filterdns expands names → IPs.
      hasFqdn,
      hasFqdn ? 20_000 : undefined,
    );
    const name = String(entry.name ?? '');
    // Never pfctl-replace FQDN host aliases — that wipes filterdns IP expansion.
    if (name && !hasFqdn) {
      await this.syncHostAliasTable(name, addresses).catch(() => false);
    }
  }

  private verifyBlockRule(rules: Record<string, unknown>[], push: (c: ControlVerifyCheck) => void): void {
    const matches = rules.filter(
      (r) => r.type === 'block' && /NetScanner\s+BLOCK/i.test(String(r.descr ?? '')),
    );
    if (!matches.length) {
      push({
        id: 'rule-block',
        label: 'Block rule (NS_BLOCK)',
        status: 'fail',
        detail: 'No floating block rule named "NetScanner BLOCK"',
      });
      return;
    }
    const rule = matches[0];
    if (!rule) return;
    const src = String(rule.source ?? '');
    if (src === `!${NS_ALIAS_BLOCK}`) {
      push({
        id: 'rule-block',
        label: 'Block rule (NS_BLOCK)',
        status: 'fail',
        detail: 'Source is inverted (!NS_BLOCK) — blocks everyone except listed hosts',
      });
    } else if (src === 'any') {
      push({
        id: 'rule-block',
        label: 'Block rule (NS_BLOCK)',
        status: 'fail',
        detail: 'Source is "any" — alias is not used',
      });
    } else if (src === NS_ALIAS_BLOCK) {
      push({ id: 'rule-block', label: 'Block rule (NS_BLOCK)', status: 'pass' });
    } else {
      push({
        id: 'rule-block',
        label: 'Block rule (NS_BLOCK)',
        status: 'warn',
        detail: `Unexpected source: ${src}`,
      });
    }
    if (rule.protocol && rule.protocol !== 'any') {
      push({
        id: 'rule-block-proto',
        label: 'Block rule protocol',
        status: 'warn',
        detail: `Protocol is ${String(rule.protocol)} — use "any" for full block`,
      });
    }
    if (rule.disabled) {
      push({ id: 'rule-block-disabled', label: 'Block rule enabled', status: 'fail', detail: 'Rule is disabled' });
    }
    if (rule.floating && rule.quick !== true) {
      push({
        id: 'rule-block-quick',
        label: 'Block rule quick',
        status: 'fail',
        detail: 'Floating rule must have Quick enabled — otherwise interface pass rules run first and block is ignored',
      });
    }
  }

  private verifyAliasRule(
    rules: Record<string, unknown>[],
    descrToken: string,
    alias: string,
    push: (c: ControlVerifyCheck) => void,
  ): void {
    const id = `rule-${alias.toLowerCase()}`;
    const matches = rules.filter(
      (r) => r.type === 'block' && String(r.descr ?? '').toUpperCase().includes(descrToken),
    );
    if (!matches.length) {
      push({
        id,
        label: `${descrToken} rule (${alias})`,
        status: 'fail',
        detail: `No block rule referencing ${alias}`,
      });
      return;
    }
    const rule = matches[0];
    if (!rule) return;
    const src = String(rule.source ?? '');
    if (src === alias) {
      push({ id, label: `${descrToken} rule (${alias})`, status: 'pass' });
    } else if (src === `!${alias}` || src === 'any') {
      push({
        id,
        label: `${descrToken} rule (${alias})`,
        status: 'fail',
        detail: `Source is "${src}" — expected ${alias}`,
      });
    } else {
      push({ id, label: `${descrToken} rule (${alias})`, status: 'warn', detail: `Source: ${src}` });
    }
    if (rule.floating && rule.quick !== true) {
      push({
        id: `${id}-quick`,
        label: `${descrToken} rule quick`,
        status: 'fail',
        detail: 'Enable Quick on this floating block rule',
      });
    }
  }

  private verifyDnsBlockRule(rules: Record<string, unknown>[], push: (c: ControlVerifyCheck) => void): void {
    const matches = rules.filter(
      (r) =>
        r.type === 'block' &&
        /NetScanner\s+DNS/i.test(String(r.descr ?? '')) &&
        String(r.destination ?? '').includes(NS_ALIAS_DNS_BLOCK),
    );
    if (!matches.length) {
      push({
        id: 'rule-dns-block',
        label: 'DNS block rule (NS_DNS_BLOCK)',
        status: 'warn',
        detail:
          'Create floating block: source NS_DNS_SRC (or any), destination NS_DNS_BLOCK, Quick enabled. FQDN aliases refresh periodically.',
      });
      return;
    }
    const rule = matches[0];
    if (!rule) return;
    push({
      id: 'rule-dns-block',
      label: 'DNS block rule (NS_DNS_BLOCK)',
      status: 'pass',
      detail: `Source ${String(rule.source ?? 'any')}`,
    });
  }

  private verifyDestBlockRule(rules: Record<string, unknown>[], push: (c: ControlVerifyCheck) => void): void {
    const matches = rules.filter(
      (r) =>
        r.type === 'block' &&
        /NetScanner\s+DEST/i.test(String(r.descr ?? '')) &&
        String(r.destination ?? '').includes(NS_ALIAS_DEST_BLOCK),
    );
    if (!matches.length) {
      push({
        id: 'rule-dest-block',
        label: 'Dest block rule (NS_DEST_BLOCK)',
        status: 'warn',
        detail: 'Create floating block: source NS_DEST_SRC, destination NS_DEST_BLOCK',
      });
      return;
    }
    push({ id: 'rule-dest-block', label: 'Dest block rule (NS_DEST_BLOCK)', status: 'pass' });
  }

  private verifyRouteRules(rules: Record<string, unknown>[], push: (c: ControlVerifyCheck) => void): void {
    const routeRules = rules.filter(
      (r) =>
        r.type === 'pass' &&
        /NetScanner\s+ROUTE/i.test(String(r.descr ?? '')) &&
        Boolean(r.gateway),
    );
    if (!routeRules.length) {
      push({
        id: 'rule-route',
        label: 'Route policy rules (NS_RT_*)',
        status: 'warn',
        detail: 'No NetScanner ROUTE pass rules yet — assigning a gateway in Policy will create them',
      });
      return;
    }
    push({
      id: 'rule-route',
      label: 'Route policy rules (NS_RT_*)',
      status: 'pass',
      detail: routeRules.map((r) => `${String(r.gateway)} ← ${String(r.source ?? r.src)}`).join('; '),
    });
  }

  private verifyBandwidthRules(rules: Record<string, unknown>[], push: (c: ControlVerifyCheck) => void): void {
    const limitRules = rules.filter((r) => String(r.source ?? '') === 'NS_LIMIT');
    const inRule = limitRules.find((r) => r.direction === 'in' && r.dnpipe);
    const outRule = limitRules.find((r) => r.direction === 'out' && r.dnpipe);
    if (inRule && outRule) {
      push({
        id: 'rule-limit',
        label: 'Bandwidth rules (NS_LIMIT)',
        status: 'pass',
        detail: `IN→${String(inRule.dnpipe)} OUT→${String(outRule.dnpipe)}`,
      });
    } else if (limitRules.length === 0) {
      push({
        id: 'rule-limit',
        label: 'Bandwidth rules (NS_LIMIT)',
        status: 'warn',
        detail: 'No pass rules with source NS_LIMIT — per-device bandwidth will not shape traffic',
      });
    } else {
      push({
        id: 'rule-limit',
        label: 'Bandwidth rules (NS_LIMIT)',
        status: 'warn',
        detail: 'Missing IN/OUT floating pass rules with direction and pipe (dnpipe)',
      });
    }
  }

  private async verifyLimiters(push: (c: ControlVerifyCheck) => void): Promise<void> {
    const rows = this.client.extractArray(await this.client.get('/api/v2/firewall/traffic_shaper/limiters'));
    const ns = rows.filter((r) => /^(NS_LIMIT|NS_IN|NS_OUT)/i.test(String(r.name ?? '')));
    if (!ns.length) {
      push({
        id: 'limiter',
        label: 'Traffic shaper limiters',
        status: 'warn',
        detail: 'No NS_IN/NS_OUT (or NS_LIMIT*) limiters — create in Firewall → Traffic Shaper → Limiters',
      });
      return;
    }
    const enabled = ns.filter((r) => r.enabled);
    push({
      id: 'limiter',
      label: 'Traffic shaper limiters',
      status: enabled.length ? 'pass' : 'warn',
      detail: enabled.map((r) => String(r.name)).join(', ') || 'All NS_LIMIT* limiters disabled',
    });
  }

  private async verifyAliasWrite(push: (c: ControlVerifyCheck) => void): Promise<void> {
    const probe = PfSenseRestControlAdapter.VERIFY_PROBE_IP;
    if (!(await this.aliasExists(NS_ALIAS_BLOCK))) {
      push({ id: 'write-block', label: 'Alias write test (NS_BLOCK)', status: 'skip', detail: 'Alias missing' });
      return;
    }
    try {
      await this.addToAlias(NS_ALIAS_BLOCK, probe);
      const addrs = await this.listAliasAddresses(NS_ALIAS_BLOCK);
      if (!addrs.includes(probe)) {
        push({
          id: 'write-block',
          label: 'Alias write test (NS_BLOCK)',
          status: 'fail',
          detail: `${probe} not visible after PATCH`,
        });
        return;
      }
      await this.removeFromAlias(NS_ALIAS_BLOCK, probe);
      push({
        id: 'write-block',
        label: 'Alias write test (NS_BLOCK)',
        status: 'pass',
        detail: `Round-trip with ${probe} OK`,
      });
    } catch (error) {
      push({
        id: 'write-block',
        label: 'Alias write test (NS_BLOCK)',
        status: 'fail',
        detail: error instanceof Error ? error.message : String(error),
      });
    }
  }
}

function normalizeDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!d || !d.includes('.')) return null;
  return d;
}

function splitFqdn(fqdn: string): { host: string; domain: string } | null {
  const parts = fqdn.split('.').filter(Boolean);
  if (parts.length < 2) return null;
  if (parts.length === 2) return { host: parts[0]!, domain: parts[1]! };
  return { host: parts[0]!, domain: parts.slice(1).join('.') };
}

function overrideFqdn(row: Record<string, unknown>): string {
  const host = String(row.host ?? '').trim().toLowerCase();
  const domain = String(row.domain ?? '').trim().toLowerCase();
  if (!host || !domain) return '';
  return `${host}.${domain}`;
}

function isIpOrCidr(value: string): boolean {
  return (
    /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(value) ||
    (value.includes(':') && !value.includes('.'))
  );
}
