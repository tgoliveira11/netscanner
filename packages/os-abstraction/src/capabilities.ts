import { type ICommandRunner } from './command-runner.js';
import { isElevated } from './platform.js';

export interface ScanCapabilities {
  nmap: boolean;
  elevated: boolean;
  /** Set when nmap is off — helps distinguish config vs missing binary. */
  nmapOffReason?: 'disabled-by-config' | 'not-in-path';
}

export function resolveNmapCapability(
  disableNmap: boolean,
  nmapInstalled: boolean,
): Pick<ScanCapabilities, 'nmap' | 'nmapOffReason'> {
  if (disableNmap) return { nmap: false, nmapOffReason: 'disabled-by-config' };
  if (!nmapInstalled) return { nmap: false, nmapOffReason: 'not-in-path' };
  return { nmap: true };
}

/**
 * Detect runtime scanning capabilities so the engine can degrade gracefully:
 * nmap availability enables deep fingerprinting; elevation enables OS detection.
 */
export async function detectCapabilities(
  runner: ICommandRunner,
  disableNmap = false,
): Promise<ScanCapabilities> {
  const installed = disableNmap ? false : await runner.which('nmap');
  const nmapCap = resolveNmapCapability(disableNmap, installed);
  return { ...nmapCap, elevated: isElevated() };
}
