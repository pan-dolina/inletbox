import type { Db } from '../db.js';
import { now, transaction } from '../db.js';
import { hashPassword, newCsrfToken, newId, newSessionId, sha256Hex, verifyPassword } from '../crypto.js';
import { generateRecoveryCodes, generateTotpSecret, normalizeRecoveryCode, verifyTotp } from '../totp.js';

export interface Admin { id: string; username: string; created_at: string; totp_enabled: boolean }
export interface Session {
  admin: Admin;
  csrfToken: string;
  expiresAt: string;
  /** True once the second factor was verified (or none is required). */
  totpVerified: boolean;
  totpAttempts: number;
}

const USERNAME_RE = /^[a-zA-Z0-9._@-]{2,64}$/;
export const MIN_PASSWORD_LENGTH = 12;
/** Wrong second-factor codes per session before the session is destroyed. */
export const MAX_TOTP_ATTEMPTS = 5;
export const TOTP_ISSUER = 'inletbox';

interface AdminRow { id: string; username: string; password_hash: string; created_at: string; totp_secret: string | null; totp_enabled_at: string | null; totp_last_step: number | null }

function toAdmin(r: AdminRow): Admin {
  return { id: r.id, username: r.username, created_at: r.created_at, totp_enabled: r.totp_enabled_at != null };
}

function adminRow(db: Db, where: 'id' | 'username', value: string): AdminRow | undefined {
  return db.prepare(`SELECT id, username, password_hash, created_at, totp_secret, totp_enabled_at, totp_last_step FROM admins WHERE ${where} = ?`).get(value) as AdminRow | undefined;
}

export function createAdmin(db: Db, username: string, password: string): Admin {
  if (!USERNAME_RE.test(username)) throw new Error('Username must be 2-64 chars: letters, digits, . _ @ -');
  if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  const admin: Admin = { id: newId('a'), username, created_at: now(), totp_enabled: false };
  db.prepare('INSERT INTO admins (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)')
    .run(admin.id, username, hashPassword(password), admin.created_at);
  return admin;
}

export function countAdmins(db: Db): number {
  return (db.prepare('SELECT COUNT(*) AS n FROM admins').get() as { n: number }).n;
}

export function getAdmin(db: Db, id: string): Admin | null {
  const r = adminRow(db, 'id', id);
  return r ? toAdmin(r) : null;
}

export function setAdminPassword(db: Db, username: string, password: string): boolean {
  if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  const res = db.prepare('UPDATE admins SET password_hash = ? WHERE username = ?').run(hashPassword(password), username);
  // Password change invalidates existing sessions of that admin.
  db.prepare('DELETE FROM sessions WHERE admin_id IN (SELECT id FROM admins WHERE username = ?)').run(username);
  return res.changes > 0;
}

const DUMMY_HASH = hashPassword('dummy-password-for-timing');

/** Always runs the password hash, so unknown usernames take as long as wrong passwords. */
export function authenticate(db: Db, username: string, password: string): Admin | null {
  const row = adminRow(db, 'username', username);
  const ok = verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
  if (!row || !ok) return null;
  return toAdmin(row);
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export function createSession(db: Db, admin: Admin, ttlMs: number): { sessionId: string; csrfToken: string } {
  const sessionId = newSessionId();
  const csrfToken = newCsrfToken();
  const ts = now();
  db.prepare('INSERT INTO sessions (id_hash, admin_id, csrf_token, created_at, last_seen_at, expires_at, totp_verified, totp_attempts) VALUES (?, ?, ?, ?, ?, ?, ?, 0)')
    .run(sha256Hex(sessionId), admin.id, csrfToken, ts, ts, new Date(Date.now() + ttlMs).toISOString(), admin.totp_enabled ? 0 : 1);
  return { sessionId, csrfToken };
}

export function getSession(db: Db, sessionId: string): Session | null {
  if (!sessionId || sessionId.length > 128) return null;
  const idHash = sha256Hex(sessionId);
  const row = db.prepare(
    `SELECT s.csrf_token, s.expires_at, s.totp_verified, s.totp_attempts, a.id, a.username, a.created_at, a.totp_enabled_at
     FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.id_hash = ?`,
  ).get(idHash) as { csrf_token: string; expires_at: string; totp_verified: number; totp_attempts: number; id: string; username: string; created_at: string; totp_enabled_at: string | null } | undefined;
  if (!row) return null;
  if (row.expires_at <= now()) {
    db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
    return null;
  }
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(now(), idHash);
  const totpEnabled = row.totp_enabled_at != null;
  return {
    admin: { id: row.id, username: row.username, created_at: row.created_at, totp_enabled: totpEnabled },
    csrfToken: row.csrf_token,
    expiresAt: row.expires_at,
    // An admin who enabled TOTP after this session started is still fully verified for it:
    // they proved the second factor when enabling it in this very session.
    totpVerified: !totpEnabled || row.totp_verified === 1,
    totpAttempts: row.totp_attempts,
  };
}

export function destroySession(db: Db, sessionId: string): void {
  db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(sha256Hex(sessionId));
}

export function destroyOtherSessions(db: Db, adminId: string, keepSessionId: string): void {
  db.prepare('DELETE FROM sessions WHERE admin_id = ? AND id_hash != ?').run(adminId, sha256Hex(keepSessionId));
}

export function purgeExpiredSessions(db: Db): number {
  return Number(db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now()).changes);
}

// ---------------------------------------------------------------------------
// TOTP second factor
// ---------------------------------------------------------------------------

export type TotpLoginResult = 'ok' | 'invalid' | 'locked';

/**
 * Verifies the second factor for a pending session. Accepts a TOTP code or an
 * unused recovery code. Wrong attempts are counted per session; after
 * MAX_TOTP_ATTEMPTS the session is destroyed ('locked') and the admin must log
 * in again with the password.
 */
export function verifySessionTotp(db: Db, sessionId: string, code: string, nowMs = Date.now()): TotpLoginResult {
  const idHash = sha256Hex(sessionId);
  return transaction(db, () => {
    const s = db.prepare('SELECT admin_id, totp_attempts FROM sessions WHERE id_hash = ?').get(idHash) as { admin_id: string; totp_attempts: number } | undefined;
    if (!s) return 'locked';
    const admin = adminRow(db, 'id', s.admin_id);
    if (!admin?.totp_secret || !admin.totp_enabled_at) return 'invalid';

    const step = verifyTotp(admin.totp_secret, code, { nowMs, minStep: admin.totp_last_step });
    let ok = step != null;
    if (ok) {
      db.prepare('UPDATE admins SET totp_last_step = ? WHERE id = ?').run(step, admin.id);
    } else {
      ok = consumeRecoveryCode(db, admin.id, code);
    }
    if (ok) {
      db.prepare('UPDATE sessions SET totp_verified = 1, totp_attempts = 0 WHERE id_hash = ?').run(idHash);
      return 'ok';
    }
    const attempts = s.totp_attempts + 1;
    if (attempts >= MAX_TOTP_ATTEMPTS) {
      db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
      return 'locked';
    }
    db.prepare('UPDATE sessions SET totp_attempts = ? WHERE id_hash = ?').run(attempts, idHash);
    return 'invalid';
  });
}

function consumeRecoveryCode(db: Db, adminId: string, code: string): boolean {
  const norm = normalizeRecoveryCode(code);
  if (norm.length !== 10) return false;
  const res = db.prepare('UPDATE admin_recovery_codes SET used_at = ? WHERE admin_id = ? AND code_hash = ? AND used_at IS NULL').run(now(), adminId, sha256Hex(norm));
  return res.changes > 0;
}

/** Step 1 of enrolment: a new pending secret (not yet enabled). Re-running replaces the pending secret. */
export function beginTotpEnrolment(db: Db, adminId: string): { secret: string } {
  const admin = adminRow(db, 'id', adminId);
  if (!admin) throw new Error('admin not found');
  if (admin.totp_enabled_at) throw new Error('TOTP is already enabled');
  const secret = generateTotpSecret();
  db.prepare('UPDATE admins SET totp_secret = ?, totp_last_step = NULL WHERE id = ?').run(secret, adminId);
  return { secret };
}

export function pendingTotpSecret(db: Db, adminId: string): string | null {
  const admin = adminRow(db, 'id', adminId);
  return admin && !admin.totp_enabled_at ? admin.totp_secret : null;
}

/** Step 2: the admin proves they hold the secret by entering a current code. Returns recovery codes (shown once). */
export function confirmTotpEnrolment(db: Db, adminId: string, code: string, nowMs = Date.now()): string[] | null {
  return transaction(db, () => {
    const admin = adminRow(db, 'id', adminId);
    if (!admin?.totp_secret || admin.totp_enabled_at) return null;
    const step = verifyTotp(admin.totp_secret, code, { nowMs });
    if (step == null) return null;
    db.prepare('UPDATE admins SET totp_enabled_at = ?, totp_last_step = ? WHERE id = ?').run(now(), step, adminId);
    db.prepare('UPDATE sessions SET totp_verified = 1 WHERE admin_id = ?').run(adminId);
    return replaceRecoveryCodes(db, adminId);
  });
}

function replaceRecoveryCodes(db: Db, adminId: string): string[] {
  db.prepare('DELETE FROM admin_recovery_codes WHERE admin_id = ?').run(adminId);
  const codes = generateRecoveryCodes();
  const ins = db.prepare('INSERT INTO admin_recovery_codes (admin_id, code_hash) VALUES (?, ?)');
  for (const c of codes) ins.run(adminId, sha256Hex(normalizeRecoveryCode(c)));
  return codes;
}

export function regenerateRecoveryCodes(db: Db, adminId: string, code: string, nowMs = Date.now()): string[] | null {
  return transaction(db, () => {
    const admin = adminRow(db, 'id', adminId);
    if (!admin?.totp_secret || !admin.totp_enabled_at) return null;
    const step = verifyTotp(admin.totp_secret, code, { nowMs, minStep: admin.totp_last_step });
    if (step == null) return null;
    db.prepare('UPDATE admins SET totp_last_step = ? WHERE id = ?').run(step, adminId);
    return replaceRecoveryCodes(db, adminId);
  });
}

export function remainingRecoveryCodes(db: Db, adminId: string): number {
  return (db.prepare('SELECT COUNT(*) AS n FROM admin_recovery_codes WHERE admin_id = ? AND used_at IS NULL').get(adminId) as { n: number }).n;
}

/** Disabling requires a current code (a stolen cookie alone must not be able to weaken the account). */
export function disableTotp(db: Db, adminId: string, code: string, nowMs = Date.now()): boolean {
  return transaction(db, () => {
    const admin = adminRow(db, 'id', adminId);
    if (!admin?.totp_secret || !admin.totp_enabled_at) return false;
    const step = verifyTotp(admin.totp_secret, code, { nowMs, minStep: admin.totp_last_step });
    if (step == null && !consumeRecoveryCode(db, adminId, code)) return false;
    forceDisableTotp(db, adminId);
    return true;
  });
}

/** Operator escape hatch (CLI): removes the second factor without a code. */
export function forceDisableTotp(db: Db, adminId: string): void {
  db.prepare('UPDATE admins SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = ?').run(adminId);
  db.prepare('DELETE FROM admin_recovery_codes WHERE admin_id = ?').run(adminId);
  db.prepare('UPDATE sessions SET totp_verified = 1 WHERE admin_id = ?').run(adminId);
}

export function findAdminByUsername(db: Db, username: string): Admin | null {
  const r = adminRow(db, 'username', username);
  return r ? toAdmin(r) : null;
}

export { TOTP_ISSUER as totpIssuer };
