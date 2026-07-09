import type { Logger } from '@netscanner/logger';
import {
  NS_ALIAS_AUTOBLOCK,
  NS_ALIAS_BLOCK,
  NS_ALIAS_PAUSED,
  type ControlBootstrap,
  type ControlVerifyCheck,
  type ControlVerifyResult,
  type DhcpReservationRequest,
} from '@netscanner/contracts';
import { PfSenseHttpClient, type PfSenseHttpConfig } from './pfsense-http-client.js';

export type AliasName = typeof NS_ALIAS_BLOCK | typeof NS_ALIAS_PAUSED | typeof NS_ALIAS_AUTOBLOCK | 'NS_LIMIT';

/** pfSense REST write operations for NetScanner network control. */
export class PfSenseRestControlAdapter {
  readonly client: PfSenseHttpClient;

  constructor(
    config: PfSenseHttpConfig,
    private readonly logger: Logger,
  ) {
    this.client = new PfSenseHttpClient(config);
  }

  async checkBootstrap(): Promise<ControlBootstrap> {
    const aliases: Record<string, boolean> = {};
    for (const name of [NS_ALIAS_BLOCK, NS_ALIAS_PAUSED, NS_ALIAS_AUTOBLOCK]) {
      aliases[name] = await this.aliasExists(name);
    }
    const ready = Boolean(aliases[NS_ALIAS_BLOCK] && aliases[NS_ALIAS_PAUSED]);
    const limiters: Record<string, boolean> = {
      NS_LIMIT: await this.limiterExists('NS_LIMIT'),
      NS_LIMIT_IN: await this.limiterExists('NS_LIMIT_IN'),
      NS_LIMIT_OUT: await this.limiterExists('NS_LIMIT_OUT'),
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
    this.verifyBandwidthRules(rules, push);
    await this.verifyLimiters(push);
    await this.verifyAliasWrite(push);

    const ok = !checks.some((c) => c.status === 'fail');
    return { ok, checks, ranAt };
  }

  async bootstrap(): Promise<ControlBootstrap> {
    for (const name of [NS_ALIAS_BLOCK, NS_ALIAS_PAUSED, NS_ALIAS_AUTOBLOCK]) {
      if (!(await this.aliasExists(name))) {
        await this.client.post('/api/v2/firewall/alias', {
          name,
          type: 'host',
          address: [],
          descr: `NetScanner ${name}`,
        });
        this.logger.info({ name }, 'created pfSense alias');
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
    return this.checkBootstrap();
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
    await this.client.patch('/api/v2/firewall/alias', {
      id: entry.id,
      name: entry.name,
      type: entry.type,
      descr: entry.descr ?? '',
      address: addresses,
      detail: entry.detail ?? [],
    });
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
    const ns = rows.filter((r) => /^NS_LIMIT/i.test(String(r.name ?? '')));
    if (!ns.length) {
      push({
        id: 'limiter',
        label: 'Traffic shaper limiters',
        status: 'warn',
        detail: 'No NS_LIMIT* limiters — create in Firewall → Traffic Shaper → Limiters',
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
