import type { ICommandRunner } from './command-runner.js';
import { currentPlatform } from './platform.js';

/** Read mDNSResponder/dscacheutil cached name for an IP (macOS only). */
export async function lookupMacDnsCache(runner: ICommandRunner, ip: string): Promise<string | null> {
  if (currentPlatform() !== 'darwin') return null;
  if (!(await runner.which('dscacheutil'))) return null;

  const res = await runner.run('dscacheutil', ['-q', 'host', '-a', `ip_address=${ip}`], {
    timeoutMs: 3000,
  });
  if (res.code !== 0 || !res.stdout.trim()) return null;

  const name = /^name:\s*(.+)$/im.exec(res.stdout)?.[1]?.trim();
  if (!name || name === ip) return null;
  return name.replace(/\.$/, '');
}
