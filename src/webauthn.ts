/**
 * WebAuthn (passkeys) on node:crypto alone, the way totp.ts does TOTP.
 *
 * Registration asks for attestation "none": we do not care which company made the
 * authenticator, so there is no certificate chain to check and no CBOR to decode.
 * The browser hands over the credential's public key as SPKI (`getPublicKey()`),
 * which node:crypto imports directly. What we verify is what matters for a second
 * factor: the ceremony was made for this site (origin, RP id hash), answers our
 * one-time challenge, involved the user (UP flag), and — at sign-in — is signed by
 * the key registered earlier.
 */
import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';

/** COSE algorithm ids we accept: EdDSA (Ed25519), ES256 (P-256), RS256. */
export const COSE_ALGS = [-8, -7, -257] as const;
export type CoseAlg = (typeof COSE_ALGS)[number];

export class WebAuthnError extends Error {}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

export function b64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

/** Strict base64url: anything else is a malformed request, not a key. */
export function fromB64url(s: string, what: string): Buffer {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length === 0 || s.length > 16_384) throw new WebAuthnError(`malformed ${what}`);
  return Buffer.from(s, 'base64url');
}

export interface Expected {
  /** The challenge we issued, base64url. */
  challenge: string;
  /** PUBLIC_URL's origin, e.g. https://drop.example.com */
  origin: string;
  /** PUBLIC_URL's host name. */
  rpId: string;
}

export interface AuthData { rpIdHash: Buffer; flags: number; signCount: number; credentialId?: Buffer }

export function parseAuthData(data: Buffer): AuthData {
  if (data.length < 37) throw new WebAuthnError('authenticator data too short');
  const flags = data[32]!;
  const out: AuthData = { rpIdHash: data.subarray(0, 32), flags, signCount: data.readUInt32BE(33) };
  if (flags & FLAG_AT) {
    // aaguid (16) + credentialIdLength (2) + credentialId + COSE key (not needed: the key arrives as SPKI)
    if (data.length < 55) throw new WebAuthnError('attested credential data too short');
    const len = data.readUInt16BE(53);
    if (data.length < 55 + len) throw new WebAuthnError('credential id truncated');
    out.credentialId = data.subarray(55, 55 + len);
  }
  return out;
}

function checkClientData(clientDataJSON: Buffer, type: 'webauthn.create' | 'webauthn.get', exp: Expected): void {
  let cd: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try { cd = JSON.parse(clientDataJSON.toString('utf8')); } catch { throw new WebAuthnError('client data is not JSON'); }
  if (cd.type !== type) throw new WebAuthnError('wrong ceremony type');
  // Compare decoded bytes: base64url padding and alphabet quirks must not decide.
  if (typeof cd.challenge !== 'string' || !fromB64url(cd.challenge, 'challenge').equals(fromB64url(exp.challenge, 'challenge'))) throw new WebAuthnError('challenge mismatch');
  if (cd.origin !== exp.origin) throw new WebAuthnError('origin mismatch');
  if (cd.crossOrigin === true) throw new WebAuthnError('cross-origin ceremony');
}

function checkAuthData(ad: AuthData, exp: Expected): void {
  if (!ad.rpIdHash.equals(createHash('sha256').update(exp.rpId, 'utf8').digest())) throw new WebAuthnError('RP id mismatch');
  if (!(ad.flags & FLAG_UP)) throw new WebAuthnError('user not present');
}

/** Imports a credential key and checks it matches the algorithm it claims. */
export function importCredentialKey(spki: Buffer, alg: number): KeyObject {
  let key: KeyObject;
  try { key = createPublicKey({ key: spki, format: 'der', type: 'spki' }); } catch { throw new WebAuthnError('unreadable public key'); }
  const d = key.asymmetricKeyDetails ?? {};
  const ok = (alg === -8 && key.asymmetricKeyType === 'ed25519')
    || (alg === -7 && key.asymmetricKeyType === 'ec' && d.namedCurve === 'prime256v1')
    || (alg === -257 && key.asymmetricKeyType === 'rsa' && (d.modulusLength ?? 0) >= 2048);
  if (!ok) throw new WebAuthnError('unsupported key type');
  return key;
}

export interface RegistrationInput { clientDataJSON: string; authenticatorData: string; publicKey: string; algorithm: number; credentialId: string }
export interface VerifiedRegistration { credentialId: string; publicKey: string; algorithm: CoseAlg; signCount: number; userVerified: boolean }

export function verifyRegistration(input: RegistrationInput, exp: Expected): VerifiedRegistration {
  checkClientData(fromB64url(input.clientDataJSON, 'client data'), 'webauthn.create', exp);
  const ad = parseAuthData(fromB64url(input.authenticatorData, 'authenticator data'));
  checkAuthData(ad, exp);
  if (!ad.credentialId) throw new WebAuthnError('no credential in authenticator data');
  const credId = fromB64url(input.credentialId, 'credential id');
  if (!credId.equals(ad.credentialId) || credId.length > 1023) throw new WebAuthnError('credential id mismatch');
  if (!(COSE_ALGS as readonly number[]).includes(input.algorithm)) throw new WebAuthnError('unsupported algorithm');
  const spki = fromB64url(input.publicKey, 'public key');
  importCredentialKey(spki, input.algorithm);
  return { credentialId: b64url(credId), publicKey: b64url(spki), algorithm: input.algorithm as CoseAlg, signCount: ad.signCount, userVerified: (ad.flags & FLAG_UV) !== 0 };
}

export interface AssertionInput { clientDataJSON: string; authenticatorData: string; signature: string }
export interface StoredCredential { publicKey: string; algorithm: number; signCount: number }

/** Verifies a sign-in assertion against a stored credential; returns the new signature counter. */
export function verifyAssertion(input: AssertionInput, cred: StoredCredential, exp: Expected): { signCount: number; userVerified: boolean } {
  const clientData = fromB64url(input.clientDataJSON, 'client data');
  const authData = fromB64url(input.authenticatorData, 'authenticator data');
  const signature = fromB64url(input.signature, 'signature');
  checkClientData(clientData, 'webauthn.get', exp);
  const ad = parseAuthData(authData);
  checkAuthData(ad, exp);
  const key = importCredentialKey(Buffer.from(cred.publicKey, 'base64url'), cred.algorithm);
  const signed = Buffer.concat([authData, createHash('sha256').update(clientData).digest()]);
  // ES256 signatures arrive DER-encoded, which is node's default for EC keys.
  const ok = cred.algorithm === -8 ? verify(null, signed, key, signature) : verify('sha256', signed, key, signature);
  if (!ok) throw new WebAuthnError('bad signature');
  // A counter that goes backwards means a cloned authenticator. Zero means "no counter" (most passkeys).
  if ((ad.signCount !== 0 || cred.signCount !== 0) && ad.signCount <= cred.signCount) throw new WebAuthnError('signature counter went backwards');
  return { signCount: ad.signCount, userVerified: (ad.flags & FLAG_UV) !== 0 };
}
