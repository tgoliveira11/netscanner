import { spawn } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { SpeedTestMeasurement } from '../domain/speed-test.js';

export interface PfSshWanSpeedTestOptions {
  host: string;
  port?: number;
  username?: string;
  password?: string;
  hwif: string;
  baseUrl: string;
  downloadBytes: number;
  uploadBytes: number;
  timeoutMs?: number;
}

/** Runs Cloudflare speed test on pfSense bound to a WAN interface (no VPN/policy route). */
export class PfSshWanSpeedTester {
  constructor(private readonly logger: Logger) {}

  async run(options: PfSshWanSpeedTestOptions): Promise<SpeedTestMeasurement> {
    const base = options.baseUrl.replace(/\/$/, '');
    const dl = Math.max(0, options.downloadBytes);
    const ul = Math.max(0, options.uploadBytes);
    const ulChunks = Math.max(1, Math.ceil(ul / 1_048_576));
    const remoteCmd = buildRemoteScript(options.hwif, base, dl, ul, ulChunks);
    const stdout = await this.runRemote(options, remoteCmd);
    if (!stdout) return emptyMeasurement('pfSense SSH speed test failed');

    try {
      const line = stdout.trim().split('\n').filter(Boolean).pop() ?? '';
      const parsed = JSON.parse(line) as {
        latencyMs?: number | null;
        downloadMbps?: number | null;
        uploadMbps?: number | null;
        downloadBytes?: number | null;
        uploadBytes?: number | null;
      };
      const errors: string[] = [];
      if (parsed.downloadMbps == null && dl > 0) errors.push('download failed');
      if (parsed.uploadMbps == null && ul > 0) errors.push('upload failed');
      this.logger.info(
        { hwif: options.hwif, downloadMbps: parsed.downloadMbps, uploadMbps: parsed.uploadMbps },
        'wan speed test completed',
      );
      return {
        downloadMbps: parsed.downloadMbps ?? null,
        uploadMbps: parsed.uploadMbps ?? null,
        latencyMs: parsed.latencyMs ?? null,
        downloadBytes: parsed.downloadBytes ?? dl,
        uploadBytes: parsed.uploadBytes ?? ul,
        server: 'cloudflare@pfsense',
        error: errors.length ? errors.join('; ') : null,
      };
    } catch {
      this.logger.warn({ stdout: stdout.slice(0, 200), hwif: options.hwif }, 'wan speed test parse failed');
      return emptyMeasurement('invalid speed test output from pfSense');
    }
  }

  private runRemote(options: PfSshWanSpeedTestOptions, remoteCmd: string): Promise<string | null> {
    const port = options.port && options.port > 0 ? options.port : 22;
    const username = options.username?.trim() || 'admin';
    const timeoutMs = options.timeoutMs ?? 180_000;
    const sshTail = ['-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', `${username}@${options.host}`, remoteCmd];

    return new Promise((resolve) => {
      const proc = options.password
        ? spawn('sshpass', ['-e', 'ssh', '-p', String(port), '-o', 'BatchMode=no', ...sshTail], {
            stdio: ['ignore', 'pipe', 'pipe'],
            env: { ...process.env, SSHPASS: options.password },
          })
        : spawn('ssh', ['-p', String(port), '-o', 'BatchMode=yes', ...sshTail], { stdio: ['ignore', 'pipe', 'pipe'] });

      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try {
          proc.kill('SIGTERM');
        } catch {
          /* ignore */
        }
        this.logger.warn({ hwif: options.hwif, timeoutMs }, 'wan speed test SSH timed out');
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
        if (code !== 0) {
          this.logger.warn(
            { hwif: options.hwif, code, stderr: stderr.slice(0, 300) },
            'wan speed test SSH failed',
          );
          resolve(null);
          return;
        }
        resolve(stdout);
      });
      proc.on('error', (err) => {
        clearTimeout(timer);
        this.logger.warn(
          { hwif: options.hwif, error: err.message },
          'wan speed test SSH spawn failed',
        );
        resolve(null);
      });
    });
  }
}

function buildRemoteScript(hwif: string, base: string, dl: number, ul: number, ulChunks: number): string {
  const q = (s: string) => `'${s.replace(/'/g, `'\"'\"'`)}'`;
  return [
    `IF=${q(hwif)}`,
    `BASE=${q(base)}`,
    `DL=${dl}`,
    `UL=${ul}`,
    `LAT=$(curl -sS --interface "$IF" --max-time 25 -o /dev/null -w '%{time_total}' "$BASE/__down?bytes=0" 2>/dev/null || echo "")`,
    `DLS=$(curl -sS --interface "$IF" --max-time 120 -o /dev/null -w '%{speed_download}' "$BASE/__down?bytes=$DL" 2>/dev/null || echo "")`,
    `ULS=$(dd if=/dev/zero bs=1048576 count=${ulChunks} 2>/dev/null | curl -sS --interface "$IF" --max-time 120 -X POST -H 'Content-Type: application/octet-stream' --data-binary @- -o /dev/null -w '%{speed_upload}' "$BASE/__up" 2>/dev/null || echo "")`,
    `export LAT DLS ULS DL=${dl} UL=${ul}`,
    `php -r ' $lat=getenv("LAT"); $dls=getenv("DLS"); $uls=getenv("ULS"); $dl=(int)getenv("DL"); $ul=(int)getenv("UL"); echo json_encode(["latencyMs"=>($lat!==""&&is_numeric($lat)?(int)round((float)$lat*1000):null),"downloadMbps"=>($dls!==""&&is_numeric($dls)?round((float)$dls*8/1e6,1):null),"uploadMbps"=>($uls!==""&&is_numeric($uls)?round((float)$uls*8/1e6,1):null),"downloadBytes"=>$dl,"uploadBytes"=>$ul]); '`,
  ].join(' && ');
}

function emptyMeasurement(error: string): SpeedTestMeasurement {
  return {
    downloadMbps: null,
    uploadMbps: null,
    latencyMs: null,
    downloadBytes: null,
    uploadBytes: null,
    server: 'cloudflare@pfsense',
    error,
  };
}
