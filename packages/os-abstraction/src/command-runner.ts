import { execFile } from 'node:child_process';

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number;
  timedOut: boolean;
}

export interface RunOptions {
  timeoutMs?: number;
  /** Max buffer for stdout/stderr in bytes. */
  maxBuffer?: number;
}

/**
 * Port for executing external processes. Abstracting this lets every OS-specific
 * adapter (arp/ping/nmap) depend on an interface instead of child_process,
 * making them unit-testable with a fake runner (DIP).
 */
export interface ICommandRunner {
  run(command: string, args: string[], options?: RunOptions): Promise<CommandResult>;
  /** Whether an executable is resolvable on PATH. */
  which(command: string): Promise<boolean>;
}

/** Production adapter built on child_process.execFile (no shell = injection-safe). */
export class NodeCommandRunner implements ICommandRunner {
  run(command: string, args: string[], options: RunOptions = {}): Promise<CommandResult> {
    const { timeoutMs = 15000, maxBuffer = 8 * 1024 * 1024 } = options;
    return new Promise((resolve) => {
      const child = execFile(
        command,
        args,
        { timeout: timeoutMs, maxBuffer, windowsHide: true },
        (error, stdout, stderr) => {
          const timedOut = Boolean(
            error && (error as NodeJS.ErrnoException & { killed?: boolean }).killed,
          );
          resolve({
            stdout: stdout?.toString() ?? '',
            stderr: stderr?.toString() ?? '',
            code: error && typeof error.code === 'number' ? error.code : error ? 1 : 0,
            timedOut,
          });
        },
      );
      child.on('error', () => {
        /* handled via callback */
      });
    });
  }

  async which(command: string): Promise<boolean> {
    const probe = process.platform === 'win32' ? 'where' : 'which';
    const res = await this.run(probe, [command], { timeoutMs: 3000 });
    return res.code === 0 && res.stdout.trim().length > 0;
  }
}
