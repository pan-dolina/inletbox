/**
 * TOTP (RFC 6238) on top of HOTP (RFC 4226), implemented with node:crypto only.
 * Defaults match Google Authenticator / Aegis / 1Password: SHA-1, 6 digits, 30 s.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str: string): Buffer {
  const clean = str.toUpperCase().replace(/[=\s-]/g, '');
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export interface TotpOptions { digits?: number; stepSeconds?: number; algorithm?: 'sha1' | 'sha256' | 'sha512' }

const DEFAULTS: Required<TotpOptions> = { digits: 6, stepSeconds: 30, algorithm: 'sha1' };

/** 160-bit secret, as recommended by RFC 4226 for HMAC-SHA1. */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function hotp(secretBase32: string, counter: number, opts: TotpOptions = {}): string {
  const { digits, algorithm } = { ...DEFAULTS, ...opts };
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(algorithm, base32Decode(secretBase32)).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const code = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(code % 10 ** digits).padStart(digits, '0');
}

export function totpStep(nowMs = Date.now(), stepSeconds = DEFAULTS.stepSeconds): number {
  return Math.floor(nowMs / 1000 / stepSeconds);
}

export function totp(secretBase32: string, nowMs = Date.now(), opts: TotpOptions = {}): string {
  return hotp(secretBase32, totpStep(nowMs, opts.stepSeconds ?? DEFAULTS.stepSeconds), opts);
}

/**
 * Verifies a code within ±`window` steps of the current time and returns the
 * matched step, or null. Callers must reject steps <= the last accepted step
 * to prevent replay of a code within its validity window.
 */
export function verifyTotp(secretBase32: string, code: string, opts: TotpOptions & { window?: number; nowMs?: number; minStep?: number | null } = {}): number | null {
  const { digits, stepSeconds } = { ...DEFAULTS, ...opts };
  const clean = code.replace(/\s+/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(clean)) return null;
  const window = opts.window ?? 1;
  const current = totpStep(opts.nowMs ?? Date.now(), stepSeconds);
  const given = Buffer.from(clean);
  let matched: number | null = null;
  // Check every candidate (no early exit) so timing does not reveal which step matched.
  for (let step = current - window; step <= current + window; step++) {
    const expected = Buffer.from(hotp(secretBase32, step, opts));
    if (expected.length === given.length && timingSafeEqual(expected, given)) {
      if (opts.minStep == null || step > opts.minStep) matched = step;
    }
  }
  return matched;
}

export function otpauthUri(params: { secret: string; account: string; issuer: string }): string {
  const label = encodeURIComponent(`${params.issuer}:${params.account}`);
  const q = new URLSearchParams({ secret: params.secret, issuer: params.issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${label}?${q.toString()}`;
}

/** Human-friendly one-time recovery codes: 10 base32 characters, shown as xxxxx-xxxxx. */
export function generateRecoveryCodes(count = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = base32Encode(randomBytes(7)).slice(0, 10).toLowerCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

export function normalizeRecoveryCode(code: string): string {
  return code.toLowerCase().replace(/[^a-z2-7]/g, '');
}
