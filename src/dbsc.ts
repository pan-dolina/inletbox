/**
 * Device Bound Session Credentials (W3C webappsec-dbsc, shipped in Chrome): the
 * browser keeps a private key in the TPM / Secure Enclave and proves it holds it
 * whenever the short-lived session cookie has to be renewed. A stolen cookie is
 * then good for minutes, and the key cannot be copied off the device.
 *
 * This file is only the cryptography: reading the proof the browser sends in the
 * `Secure-Session-Response` header, a compact JWS with `typ: dbsc+jwt`. ES256 and
 * RS256 are what browsers offer; `none` is refused, an unsigned proof proves nothing.
 */
import { createPublicKey, verify, type KeyObject } from 'node:crypto';

/** The public half of a device key, as the browser sends it. */
export type JsonWebKey = { kty: 'EC'; crv: 'P-256'; x: string; y: string } | { kty: 'RSA'; n: string; e: string };

export const DBSC_ALGS = ['ES256', 'RS256'] as const;
export type DbscAlg = (typeof DBSC_ALGS)[number];

export class DbscError extends Error {}

export interface DbscProof {
  alg: DbscAlg;
  /** The key from the JWT header (registration only). */
  jwk?: JsonWebKey;
  /** The challenge the proof answers. */
  jti: string;
}

/** `Secure-Session-Response` is a structured-field string: the JWT, in quotes. */
export function proofFromHeader(raw: string | string[] | undefined): string | null {
  const v = Array.isArray(raw) ? raw[0] : raw;
  if (!v) return null;
  const s = v.trim();
  const m = /^"([A-Za-z0-9_.-]+)"$/.exec(s) ?? /^([A-Za-z0-9_.-]+)$/.exec(s);
  return m && m[1]!.length <= 8192 ? m[1]! : null;
}

function part(s: string): Record<string, unknown> {
  try {
    const v = JSON.parse(Buffer.from(s, 'base64url').toString('utf8')) as unknown;
    if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  } catch { /* fall through */ }
  throw new DbscError('malformed JWT');
}

/** Only the public members of a key we can use: anything else in the JWK is dropped. */
export function publicJwk(jwk: unknown): JsonWebKey {
  if (!jwk || typeof jwk !== 'object') throw new DbscError('missing key');
  const k = jwk as Record<string, unknown>;
  if (k.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string' && k.d === undefined) return { kty: 'EC', crv: 'P-256', x: k.x, y: k.y };
  if (k.kty === 'RSA' && typeof k.n === 'string' && typeof k.e === 'string' && k.d === undefined) return { kty: 'RSA', n: k.n, e: k.e };
  throw new DbscError('unsupported key');
}

function keyFor(alg: DbscAlg, jwk: JsonWebKey): KeyObject {
  let key: KeyObject;
  try { key = createPublicKey({ key: jwk, format: 'jwk' }); } catch { throw new DbscError('unreadable key'); }
  if (alg === 'ES256' && !(key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1')) throw new DbscError('key does not match ES256');
  if (alg === 'RS256' && !(key.asymmetricKeyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048)) throw new DbscError('key does not match RS256');
  return key;
}

/**
 * Verifies a proof. At registration the key comes from the JWT itself (`jwk` header);
 * at refresh it must be the key stored at registration, passed as `knownKey`.
 */
export function verifyProof(jwt: string, knownKey?: { alg: DbscAlg; jwk: JsonWebKey }): DbscProof {
  const pieces = jwt.split('.');
  if (pieces.length !== 3) throw new DbscError('malformed JWT');
  const [h, p, sig] = pieces as [string, string, string];
  const header = part(h);
  const payload = part(p);
  if (header.typ !== 'dbsc+jwt') throw new DbscError('wrong typ');
  const alg = header.alg;
  if (alg !== 'ES256' && alg !== 'RS256') throw new DbscError('unsupported alg');
  let jwk: JsonWebKey;
  if (knownKey) {
    if (alg !== knownKey.alg) throw new DbscError('alg differs from the registered key');
    jwk = knownKey.jwk;
  } else {
    jwk = publicJwk(header.jwk);
  }
  const key = keyFor(alg, jwk);
  const signed = Buffer.from(`${h}.${p}`, 'ascii');
  const signature = Buffer.from(sig, 'base64url');
  // JWS ES256 is the raw r||s pair, not DER.
  const ok = alg === 'ES256'
    ? verify('sha256', signed, { key, dsaEncoding: 'ieee-p1363' }, signature)
    : verify('sha256', signed, key, signature);
  if (!ok) throw new DbscError('bad signature');
  if (typeof payload.jti !== 'string' || !payload.jti) throw new DbscError('missing jti');
  return { alg, jwk: knownKey ? undefined : jwk, jti: payload.jti };
}
