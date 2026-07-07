import type { SecurityFlag, ServiceInfo } from '@netscanner/contracts';

const RULES: { port: number; code: string; severity: SecurityFlag['severity']; message: string }[] = [
  { port: 23, code: 'telnet-open', severity: 'high', message: 'Telnet (23) is open — credentials sent in cleartext.' },
  { port: 21, code: 'ftp-open', severity: 'medium', message: 'FTP (21) is open — often unencrypted.' },
  { port: 445, code: 'smb-exposed', severity: 'medium', message: 'SMB (445) is exposed to the LAN.' },
  { port: 3389, code: 'rdp-exposed', severity: 'medium', message: 'RDP (3389) is exposed — common attack target.' },
  { port: 5900, code: 'vnc-open', severity: 'medium', message: 'VNC (5900) is open.' },
  { port: 1900, code: 'upnp-open', severity: 'low', message: 'UPnP (1900) is enabled.' },
];

/**
 * Derives security findings from a host's open services. Pure domain logic,
 * decoupled from classification so security policy can evolve independently (SRP).
 */
export class SecurityAnalyzer {
  analyze(services: ServiceInfo[]): SecurityFlag[] {
    const open = new Set(services.filter((s) => s.state === 'open').map((s) => s.port));
    const flags: SecurityFlag[] = [];
    for (const rule of RULES) {
      if (open.has(rule.port)) {
        flags.push({ code: rule.code, severity: rule.severity, message: rule.message });
      }
    }
    return flags;
  }
}
