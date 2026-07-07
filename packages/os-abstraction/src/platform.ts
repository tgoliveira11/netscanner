export type OsPlatform = 'darwin' | 'linux' | 'win32' | 'unknown';

export function currentPlatform(): OsPlatform {
  switch (process.platform) {
    case 'darwin':
      return 'darwin';
    case 'linux':
      return 'linux';
    case 'win32':
      return 'win32';
    default:
      return 'unknown';
  }
}

/** Best-effort check for elevated privileges (needed for nmap OS detection). */
export function isElevated(): boolean {
  if (process.platform === 'win32') {
    // Heuristic: real check requires a native call; assume non-elevated.
    return false;
  }
  return typeof process.getuid === 'function' && process.getuid() === 0;
}
