import type { Logger } from '@netscanner/logger';
import { LuciClient } from './luci-client.js';
import { resolveLuciAuthMode } from './luci-auth-mode.js';
import type { OpenWrtScrapeTarget } from './openwrt-wireless-probe.js';
import { formatCompalUptime } from './compal-status.js';

export type CompalStepLevel = 'info' | 'warn' | 'success' | 'error';

export interface CompalStep {
  level: CompalStepLevel;
  message: string;
  at: string;
}

export type CompalStepFn = (step: CompalStep) => void;

export interface CompalAdminDevice {
  url: string;
  host: string;
  ok: boolean;
  error?: string;
  meshEnabled: boolean | null;
  ssids: string[];
  ssidRows: Array<{
    device: string;
    ifname: string;
    ssid: string;
    up: boolean;
    mode?: string;
    channel?: number | string;
    disabled?: boolean;
  }>;
  uptimeSec?: number;
  uptimeLabel?: string;
  localtime?: string;
}

function clientFor(target: OpenWrtScrapeTarget): LuciClient {
  if (target.kind !== 'compal') throw new Error('Not a Compal target');
  if (!target.username || !target.password) throw new Error('Missing Compal credentials');
  return new LuciClient({
    baseUrl: target.baseUrl,
    username: target.username,
    password: target.password,
    insecureTls: true,
    auth: resolveLuciAuthMode({ kind: target.kind, username: target.username }),
  });
}

function step(fn: CompalStepFn | undefined, level: CompalStepLevel, message: string): void {
  fn?.({ level, message, at: new Date().toISOString() });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function probeCompalAdmin(
  targets: OpenWrtScrapeTarget[],
  logger: Logger,
): Promise<CompalAdminDevice[]> {
  const compal = targets.filter((t) => t.kind === 'compal');
  const results: CompalAdminDevice[] = [];
  for (const target of compal) {
    const host = safeHost(target.baseUrl);
    if (!target.username || !target.password) {
      results.push({
        url: target.baseUrl,
        host,
        ok: false,
        error: 'missing credentials',
        meshEnabled: null,
        ssids: [],
        ssidRows: [],
      });
      continue;
    }
    try {
      const client = clientFor(target);
      // Single LuCI session, sequential reads — parallel logins destabilize Compal APs.
      const system = await client.getCompalSystemStatus().catch(() => null);
      const ssidRows = await client.getWirelessSsids().catch(() => []);
      const meshEnabled = await client.getCompalMeshEnabled();
      const ssids = [...new Set(ssidRows.map((s) => s.ssid).filter(Boolean))];
      logger.info({ url: target.baseUrl, meshEnabled, ssids: ssids.length }, 'Compal admin probe');
      results.push({
        url: target.baseUrl,
        host,
        ok: true,
        meshEnabled,
        ssids,
        ssidRows: ssidRows.map((s) => ({
          device: s.device,
          ifname: s.ifname,
          ssid: s.ssid,
          up: s.up,
          mode: s.mode,
          channel: s.channel,
          disabled: s.disabled,
        })),
        uptimeSec: system?.uptimeSec,
        uptimeLabel: system ? formatCompalUptime(system.uptimeSec) : undefined,
        localtime: system?.localtime,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      logger.warn({ url: target.baseUrl, error: msg }, 'Compal admin probe failed');
      results.push({
        url: target.baseUrl,
        host,
        ok: false,
        error: msg,
        meshEnabled: null,
        ssids: [],
        ssidRows: [],
      });
    }
  }
  return results;
}

export async function setCompalMeshForTarget(
  target: OpenWrtScrapeTarget,
  enabled: boolean,
  logger: Logger,
  onStep?: CompalStepFn,
): Promise<{ meshEnabled: boolean | null; uptimeSec?: number }> {
  const client = clientFor(target);
  step(onStep, 'info', `Conectando a ${safeHost(target.baseUrl)} (LuCI RSA)…`);
  const before = await client.getCompalMeshEnabled().catch(() => null);
  step(
    onStep,
    'info',
    before == null ? 'Estado mesh atual: desconhecido' : `Estado mesh atual: ${before ? 'ligado' : 'desligado'}`,
  );
  step(onStep, 'info', `Enviando formulário mesh_wifi (${enabled ? 'ligar' : 'desligar'})…`);
  await client.setCompalMeshEnabled(enabled);
  step(onStep, 'info', 'Aguardando aplicação no rádio Wi‑Fi (~5s)…');
  await sleep(5000);
  step(onStep, 'info', 'Verificando estado mesh…');
  const meshEnabled = await client.getCompalMeshEnabled().catch(() => null);
  const system = await client.getCompalSystemStatus().catch(() => null);
  if (meshEnabled === enabled) {
    step(onStep, 'success', `Mesh ${enabled ? 'ligado' : 'desligado'} com sucesso.`);
  } else if (meshEnabled == null) {
    step(onStep, 'warn', 'Comando enviado — mesh não confirmado (AP ocupado ou reiniciando rádio).');
  } else {
    step(onStep, 'warn', `Mesh reportado como ${meshEnabled ? 'ligado' : 'desligado'} (esperado ${enabled ? 'ligado' : 'desligado'}).`);
  }
  if (system) {
    step(onStep, 'info', `AP online há ${formatCompalUptime(system.uptimeSec)}.`);
  }
  logger.info({ url: target.baseUrl, enabled, meshEnabled }, 'Compal mesh updated');
  return { meshEnabled, uptimeSec: system?.uptimeSec };
}

/** True when post-reboot uptime indicates a fresh boot vs the reading before reboot. */
export function isCompalRebootConfirmed(
  beforeUptimeSec: number | undefined,
  afterUptimeSec: number,
): boolean {
  if (afterUptimeSec < 600) return true;
  if (beforeUptimeSec != null && afterUptimeSec < beforeUptimeSec - 120) return true;
  return false;
}

export async function rebootCompalTarget(
  target: OpenWrtScrapeTarget,
  logger: Logger,
  onStep?: CompalStepFn,
): Promise<{ uptimeSec?: number }> {
  const client = clientFor(target);
  step(onStep, 'info', `Conectando a ${safeHost(target.baseUrl)}…`);
  const before = await client.getCompalSystemStatus().catch(() => null);
  const beforeUptime = before?.uptimeSec;
  if (before) {
    step(onStep, 'info', `Uptime antes do reboot: ${formatCompalUptime(before.uptimeSec)}.`);
  }
  step(onStep, 'info', 'Enviando reboot (LuCI GET /admin/system/reboot?reboot=1)…');
  const sentAt = Date.now();
  await client.rebootCompal();
  step(onStep, 'warn', 'Comando enviado — aguardando AP desligar (Wi‑Fi ficará offline ~1–2 min).');
  logger.info({ url: target.baseUrl }, 'Compal reboot requested');

  let offlineSeen = false;
  while (Date.now() - sentAt < 45_000) {
    await sleep(3000);
    try {
      const system = await clientFor(target).getCompalSystemStatus();
      if (system && isCompalRebootConfirmed(beforeUptime, system.uptimeSec)) {
        step(
          onStep,
          'success',
          `Reinício confirmado — uptime ${formatCompalUptime(system.uptimeSec)}.`,
        );
        return { uptimeSec: system.uptimeSec };
      }
      if (Date.now() - sentAt > 20_000) {
        step(
          onStep,
          'error',
          `Reboot não executado — AP ainda responde com uptime ${formatCompalUptime(system?.uptimeSec ?? beforeUptime ?? 0)}.`,
        );
        throw new Error('Compal reboot not confirmed: uptime unchanged');
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes('not confirmed')) throw error;
      offlineSeen = true;
      step(onStep, 'info', 'AP offline — reboot em andamento.');
      break;
    }
  }

  if (!offlineSeen) {
    step(onStep, 'error', 'Reboot não confirmado — AP não desligou após o comando.');
    throw new Error('Compal reboot not confirmed: device stayed online');
  }

  const deadline = Date.now() + 180_000;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt += 1;
    await sleep(5000);
    step(onStep, 'info', `Aguardando AP voltar (${attempt})…`);
    try {
      const system = await clientFor(target).getCompalSystemStatus();
      if (system && isCompalRebootConfirmed(beforeUptime, system.uptimeSec)) {
        step(
          onStep,
          'success',
          `AP online — uptime ${formatCompalUptime(system.uptimeSec)} (reinício confirmado).`,
        );
        return { uptimeSec: system.uptimeSec };
      }
      if (system) {
        step(
          onStep,
          'warn',
          `AP respondeu mas uptime ainda alto (${formatCompalUptime(system.uptimeSec)}) — aguardando…`,
        );
      }
    } catch {
      step(onStep, 'info', 'AP ainda offline…');
    }
  }
  step(onStep, 'error', 'Timeout — AP não respondeu em 3 minutos.');
  throw new Error('Compal AP did not come back online within 3 minutes');
}

function safeHost(baseUrl: string): string {
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return baseUrl;
  }
}
