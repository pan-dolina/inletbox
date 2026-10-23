/**
 * Passkeys (WebAuthn credentials) as a second factor next to the password, and as a
 * way to confirm a sensitive action. The ceremony's challenge lives on the session
 * row that asked for it, with its purpose and a deadline, and is used once.
 */
import { randomBytes } from 'node:crypto';
import type { Db } from '../db.js';
import { now, transaction } from '../db.js';
import { newId, sha256Hex } from '../crypto.js';
import { b64url, verifyAssertion, verifyRegistration, WebAuthnError, type AssertionInput, type Expected, type RegistrationInput } from '../webauthn.js';
import { completeSecondFactor, dropRecoveryCodesIfUnused, type Admin } from './auth.js';

export type CeremonyPurpose = 'register' | 'login' | 'confirm';
export const CEREMONY_TTL_MS = 5 * 60_000;
export const MAX_PASSKEYS = 10;
export const PASSKEY_NAME_MAX = 64;

export interface Passkey { id: string; name: string; created_at: string; last_used_at: string | null }

export function listPasskeys(db: Db, adminId: string): Passkey[] {
  return db.prepare('SELECT id, name, created_at, last_used_at FROM admin_passkeys WHERE admin_id = ? ORDER BY created_at').all(adminId) as unknown as Passkey[];
}

/** Starts a ceremony for this session: a fresh 32-byte challenge, replacing any pending one. */
export function beginCeremony(db: Db, sessionId: string, purpose: CeremonyPurpose): string {
  const challenge = b64url(randomBytes(32));
  db.prepare('UPDATE sessions SET webauthn_challenge = ?, webauthn_purpose = ?, webauthn_expires_at = ? WHERE id_hash = ?')
    .run(challenge, purpose, new Date(Date.now() + CEREMONY_TTL_MS).toISOString(), sha256Hex(sessionId));
  return challenge;
}

/** Takes the pending challenge off the session (whatever the outcome, it is not reusable). */
function takeChallenge(db: Db, idHash: string, purpose: CeremonyPurpose): string {
  const row = db.prepare('SELECT webauthn_challenge, webauthn_purpose, webauthn_expires_at FROM sessions WHERE id_hash = ?').get(idHash) as
    { webauthn_challenge: string | null; webauthn_purpose: string | null; webauthn_expires_at: string | null } | undefined;
  db.prepare('UPDATE sessions SET webauthn_challenge = NULL, webauthn_purpose = NULL, webauthn_expires_at = NULL WHERE id_hash = ?').run(idHash);
  if (!row?.webauthn_challenge || row.webauthn_purpose !== purpose || !row.webauthn_expires_at || row.webauthn_expires_at <= now()) {
    throw new WebAuthnError('no pending challenge');
  }
  return row.webauthn_challenge;
}

/** Credential ids of the account, for `allowCredentials` / `excludeCredentials`. */
export function credentialIds(db: Db, adminId: string): string[] {
  return (db.prepare('SELECT credential_id FROM admin_passkeys WHERE admin_id = ?').all(adminId) as Array<{ credential_id: string }>).map((r) => r.credential_id);
}

/** Saves a new passkey after checking the browser's answer to our challenge. */
export function registerPasskey(db: Db, sessionId: string, adminId: string, name: string, input: RegistrationInput, exp: Omit<Expected, 'challenge'>): Passkey {
  return transaction(db, () => {
    const challenge = takeChallenge(db, sha256Hex(sessionId), 'register');
    const reg = verifyRegistration(input, { ...exp, challenge });
    const count = (db.prepare('SELECT COUNT(*) AS n FROM admin_passkeys WHERE admin_id = ?').get(adminId) as { n: number }).n;
    if (count >= MAX_PASSKEYS) throw new WebAuthnError('too many passkeys');
    if (db.prepare('SELECT 1 FROM admin_passkeys WHERE credential_id = ?').get(reg.credentialId)) throw new WebAuthnError('passkey already registered');
    const pk: Passkey = { id: newId('pk'), name: name.trim().slice(0, PASSKEY_NAME_MAX) || 'Passkey', created_at: now(), last_used_at: null };
    db.prepare('INSERT INTO admin_passkeys (id, admin_id, credential_id, public_key, algorithm, sign_count, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(pk.id, adminId, reg.credentialId, reg.publicKey, reg.algorithm, reg.signCount, pk.name, pk.created_at);
    // This session just proved the new factor.
    db.prepare('UPDATE sessions SET totp_verified = 1 WHERE id_hash = ?').run(sha256Hex(sessionId));
    return pk;
  });
}

interface CredentialRow { id: string; public_key: string; algorithm: number; sign_count: number }

/** Checks an assertion made by one of the account's passkeys and records its use. */
function checkAssertion(db: Db, idHash: string, adminId: string, purpose: CeremonyPurpose, credentialId: string, input: AssertionInput, exp: Omit<Expected, 'challenge'>): void {
  const challenge = takeChallenge(db, idHash, purpose);
  const cred = db.prepare('SELECT id, public_key, algorithm, sign_count FROM admin_passkeys WHERE credential_id = ? AND admin_id = ?').get(credentialId, adminId) as CredentialRow | undefined;
  if (!cred) throw new WebAuthnError('unknown passkey');
  const { signCount } = verifyAssertion(input, { publicKey: cred.public_key, algorithm: cred.algorithm, signCount: cred.sign_count }, { ...exp, challenge });
  db.prepare('UPDATE admin_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?').run(signCount, now(), cred.id);
}

/** Second step of the login with a passkey: replaces the pending session with a full one. */
export function verifyPasskeyLogin(db: Db, sessionId: string, admin: Admin, ttlMs: number, credentialId: string, input: AssertionInput, exp: Omit<Expected, 'challenge'>): { sessionId: string; csrfToken: string } {
  const idHash = sha256Hex(sessionId);
  // A failed check must still consume the challenge, so the transaction commits either way.
  let error: unknown;
  const fresh = transaction(db, () => {
    try {
      checkAssertion(db, idHash, admin.id, 'login', credentialId, input, exp);
    } catch (err) {
      error = err;
      return null;
    }
    return completeSecondFactor(db, idHash, admin, ttlMs, 'passkey');
  });
  if (!fresh) throw error;
  return fresh;
}

/** A passkey confirms a sensitive action for this (already complete) session. */
export function verifyPasskeyConfirm(db: Db, sessionId: string, adminId: string, credentialId: string, input: AssertionInput, exp: Omit<Expected, 'challenge'>): void {
  let error: unknown;
  transaction(db, () => {
    try { checkAssertion(db, sha256Hex(sessionId), adminId, 'confirm', credentialId, input, exp); } catch (err) { error = err; }
  });
  if (error) throw error;
}

/**
 * Removes a passkey. Every other session of the account ends, as when TOTP is turned
 * off: a pending session must never be upgraded by a factor going away.
 */
export function removePasskey(db: Db, adminId: string, passkeyId: string, keepSessionId: string): Passkey | null {
  return transaction(db, () => {
    const pk = db.prepare('SELECT id, name, created_at, last_used_at FROM admin_passkeys WHERE id = ? AND admin_id = ?').get(passkeyId, adminId) as Passkey | undefined;
    if (!pk) return null;
    db.prepare('DELETE FROM admin_passkeys WHERE id = ?').run(pk.id);
    dropRecoveryCodesIfUnused(db, adminId);
    db.prepare('DELETE FROM sessions WHERE admin_id = ? AND id_hash != ?').run(adminId, sha256Hex(keepSessionId));
    return pk;
  });
}

