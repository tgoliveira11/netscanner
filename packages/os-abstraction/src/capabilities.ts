import { type ICommandRunner } from './command-runner.js';
import { isElevated } from './platform.js';

export interface ScanCapabilities {
  nmap: boolean;
  elevated: boolean;
}

/**
 * Detect runtime scanning capabilities so the engine can degrade gracefully:
 * nmap availability enables deep fingerprinting; elevation enables OS detection.
 */
export async function detectCapabilities(
  runner: ICommandRunner,
  disableNmap = false,
): Promise<ScanCapabilities> {
  const nmap = disableNmap ? false : await runner.which('nmap');
  return { nmap, elevated: isElevated() };
}
