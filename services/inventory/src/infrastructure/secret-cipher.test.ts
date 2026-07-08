import { describe, expect, it } from 'vitest';
import { isEncryptedSecret, SecretCipher } from './secret-cipher.js';

describe('SecretCipher', () => {
  const cipher = new SecretCipher('a'.repeat(64));

  it('round-trips encrypt/decrypt', () => {
    const enc = cipher.encrypt('super-secret-pass');
    expect(isEncryptedSecret(enc)).toBe(true);
    expect(cipher.decrypt(enc)).toBe('super-secret-pass');
  });

  it('produces distinct ciphertext per call', () => {
    const a = cipher.encrypt('same');
    const b = cipher.encrypt('same');
    expect(a).not.toBe(b);
  });
});
