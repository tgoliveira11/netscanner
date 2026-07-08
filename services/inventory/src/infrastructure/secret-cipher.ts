import { createDecipheriv, createCipheriv, randomBytes, scryptSync } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

const PREFIX = 'enc:v1:';
const ALGO = 'aes-256-gcm';
const IV_LEN = 12;

export function isEncryptedSecret(value: string | null | undefined): boolean {
  return Boolean(value?.startsWith(PREFIX));
}

function deriveKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (/^[0-9a-f]{64}$/i.test(trimmed)) return Buffer.from(trimmed, 'hex');
  const fromB64 = Buffer.from(trimmed, 'base64');
  if (fromB64.length === 32) return fromB64;
  return scryptSync(trimmed, 'netscanner-agent-v1', 32);
}

function defaultKeyFile(): string {
  return path.join(homedir(), '.netscanner', '.encryption-key');
}

function readOrCreateKeyFile(filePath: string): string | null {
  try {
    if (existsSync(filePath)) {
      const key = readFileSync(filePath, 'utf8').trim();
      return key || null;
    }
    mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const key = randomBytes(32).toString('hex');
    writeFileSync(filePath, `${key}\n`, { encoding: 'utf8', mode: 0o600 });
    chmodSync(filePath, 0o600);
    return key;
  } catch {
    return null;
  }
}

export interface SecretCipherOptions {
  envKey?: string | null;
  keyFile?: string;
}

/** AES-256-GCM for secrets at rest (router panel passwords, etc.). */
export class SecretCipher {
  private readonly key: Buffer;

  constructor(keyMaterial: string) {
    this.key = deriveKey(keyMaterial);
  }

  static resolve(options: SecretCipherOptions = {}): SecretCipher | null {
    const fromEnv = options.envKey?.trim();
    if (fromEnv) return new SecretCipher(fromEnv);
    const file = options.keyFile ?? defaultKeyFile();
    const fromFile = readOrCreateKeyFile(file);
    return fromFile ? new SecretCipher(fromFile) : null;
  }

  encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGO, this.key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${PREFIX}${Buffer.concat([iv, tag, enc]).toString('base64')}`;
  }

  decrypt(stored: string): string {
    if (!stored.startsWith(PREFIX)) return stored;
    const raw = Buffer.from(stored.slice(PREFIX.length), 'base64');
    const iv = raw.subarray(0, IV_LEN);
    const tag = raw.subarray(IV_LEN, IV_LEN + 16);
    const data = raw.subarray(IV_LEN + 16);
    const decipher = createDecipheriv(ALGO, this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  }
}
