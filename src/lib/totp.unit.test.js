import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createSecret, buildOtpauthUrl, verifyCode } from './totp.js';

const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const RFC_VECTORS = [
  [59, '287082'],
  [1111111109, '081804'],
  [1234567890, '005924'],
  [2000000000, '279037'],
];
const STEP_AT_1234567890 = Math.floor(1234567890 / 30);

function setClock(unixSeconds) {
  vi.setSystemTime(unixSeconds * 1000);
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('createSecret', () => {
  it('returns a 20-byte secret encoded as Base32', () => {
    const secret = createSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
  });

  it('returns a different secret every time', () => {
    expect(createSecret()).not.toBe(createSecret());
  });
});

describe('buildOtpauthUrl', () => {
  it('builds an otpauth URI with issuer, label and secret', () => {
    const url = buildOtpauthUrl('demo.user', RFC_SECRET);
    expect(url).toBe(
      `otpauth://totp/Library%20Portal:demo.user?secret=${RFC_SECRET}&issuer=Library%20Portal`,
    );
  });
});

describe('verifyCode', () => {
  it.each(RFC_VECTORS)('accepts the RFC 6238 code at t=%i', async (time, code) => {
    setClock(time);
    expect(await verifyCode(RFC_SECRET, code)).toBe(Math.floor(time / 30));
  });

  it('accepts a code from the previous or next step (clock drift)', async () => {
    setClock(1234567890 + 30);
    expect(await verifyCode(RFC_SECRET, '005924')).toBe(STEP_AT_1234567890);
    setClock(1234567890 - 30);
    expect(await verifyCode(RFC_SECRET, '005924')).toBe(STEP_AT_1234567890);
  });

  it('rejects a code two steps away', async () => {
    setClock(1234567890 + 61);
    expect(await verifyCode(RFC_SECRET, '005924')).toBeNull();
  });

  it('rejects a wrong code', async () => {
    setClock(1234567890);
    expect(await verifyCode(RFC_SECRET, '123456')).toBeNull();
  });

  it('rejects a code already used (replay)', async () => {
    setClock(1234567890);
    expect(await verifyCode(RFC_SECRET, '005924', STEP_AT_1234567890)).toBeNull();
  });

  it('accepts a newer code after a used step', async () => {
    setClock(1234567890);
    expect(await verifyCode(RFC_SECRET, '005924', STEP_AT_1234567890 - 1)).toBe(STEP_AT_1234567890);
  });

  it.each([undefined, null, 5924, '', '12345', '1234567', '12345a', ' 005924'])(
    'rejects malformed input %j without throwing',
    async (code) => {
      setClock(1234567890);
      expect(await verifyCode(RFC_SECRET, code)).toBeNull();
    },
  );
});
