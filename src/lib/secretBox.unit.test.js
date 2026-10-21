import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { encryptSecret, decryptSecret } from './secretBox.js';

const ORIGINAL_KEY = process.env.MFA_ENCRYPTION_KEY;
const SEED = 'JBSWY3DPEHPK3PXP';
const DECRYPT_FAILED = expect.objectContaining({ code: 'SECRET_DECRYPT_FAILED' });

beforeEach(() => {
  process.env.MFA_ENCRYPTION_KEY = randomBytes(32).toString('base64');
});

afterEach(() => {
  if (ORIGINAL_KEY === undefined) {
    delete process.env.MFA_ENCRYPTION_KEY;
  } else {
    process.env.MFA_ENCRYPTION_KEY = ORIGINAL_KEY;
  }
});

describe('secretBox', () => {
  it('round-trips a secret for the same context', () => {
    expect(decryptSecret(encryptSecret(SEED, 'user:7'), 'user:7')).toBe(SEED);
  });

  it('never stores the plaintext', () => {
    const stored = encryptSecret(SEED, 'user:7');
    expect(stored).not.toContain(SEED);
    expect(stored.startsWith('v1:')).toBe(true);
  });

  it('produces a different ciphertext every time (random IV)', () => {
    expect(encryptSecret(SEED, 'user:7')).not.toBe(encryptSecret(SEED, 'user:7'));
  });

  it('rejects a value copied to another user', () => {
    expect(() => decryptSecret(encryptSecret(SEED, 'user:7'), 'user:8')).toThrow(DECRYPT_FAILED);
  });

  it('rejects tampered ciphertext', () => {
    const [v, iv, tag, data] = encryptSecret(SEED, 'user:7').split(':');
    const bytes = Buffer.from(data, 'base64url');
    bytes[0] ^= 1;
    expect(() => decryptSecret([v, iv, tag, bytes.toString('base64url')].join(':'), 'user:7')).toThrow(DECRYPT_FAILED);
  });

  it('rejects decryption with a different key', () => {
    const stored = encryptSecret(SEED, 'user:7');
    process.env.MFA_ENCRYPTION_KEY = randomBytes(32).toString('base64');
    expect(() => decryptSecret(stored, 'user:7')).toThrow(DECRYPT_FAILED);
  });

  it.each([null, '', 'garbage', 'v2:a:b:c'])('rejects malformed value %j', (stored) => {
    expect(() => decryptSecret(stored, 'user:7')).toThrow(DECRYPT_FAILED);
  });

  it('fails fast when the key is missing or has the wrong size', () => {
    delete process.env.MFA_ENCRYPTION_KEY;
    expect(() => encryptSecret(SEED, 'user:7')).toThrow(/not set/);
    process.env.MFA_ENCRYPTION_KEY = randomBytes(16).toString('base64');
    expect(() => encryptSecret(SEED, 'user:7')).toThrow(/32 bytes/);
  });
});