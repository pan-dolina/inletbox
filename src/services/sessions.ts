/**
 * What an account can see and do about its own sessions, and the server side of
 * device-bound sessions (DBSC; the JWT checks are in ../dbsc.ts).
 */
import { randomBytes } from 'node:crypto';
import type { Db } from '../db.js';
import { now, transaction } from '../db.js';
import { newId, safeEqual, sha256Hex } from '../crypto.js';
import { DbscError, verifyProof, type DbscAlg, type JsonWebKey } from '../dbsc.js';
import type { SecondFactor } from './auth.js';

export interface SessionSummary {
  public_id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip: string | null;
  user_agent: string | null;
  second_factor: SecondFactor | null;
  /** Still waiting for the second factor: someone got past the password. */
  pending: boolean;
  /** Bound to a key held by the device (DBSC). */
  bound: boolean;
  current: boolean;
}

export function listSessions(db: Db, adminId: string, currentSessionId: string): SessionSummary[] {
  const currentHash = sha256Hex(currentSessionId);
  const rows = db.prepare(
    `SELECT s.id_hash, s.public_id, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent, s.second_factor, s.totp_verified,
            b.id AS binding
     FROM sessions s LEFT JOIN session_bindings b ON b.session_hash = s.id_hash
     WHERE s.admin_id = ? AND s.expires_at > ? ORDER BY s.last_seen_at DESC`,
  ).all(adminId, now()) as Array<Omit<SessionSummary, 'pending' | 'bound' | 'current'> & { id_hash: string; totp_verified: number; binding: string | null }>;
  return rows.map(({ id_hash, totp_verified, binding, ...r }) => ({ ...r, pending: totp_verified !== 1, bound: binding != null, current: id_hash === currentHash }));
}

/** Ends one of the account's own sessions by its public id. */
export function revokeSession(db: Db, adminId: string, publicId: string): boolean {
  return db.prepare('DELETE FROM sessions WHERE admin_id = ? AND public_id = ?').run(adminId, publicId).changes > 0;
}

// ---------------------------------------------------------------------------
// Device-bound sessions (DBSC)
// ---------------------------------------------------------------------------

/** How long a bound cookie lives before the browser has to prove the key again. */
export const BOUND_COOKIE_TTL_MS = 10 * 60_000;
/** Must outlive the cookie: the browser caches the challenge until the next refresh. */
export const DBSC_CHALLENGE_TTL_MS = 30 * 60_000;
/** Clock skew and in-flight requests: a just-rotated cookie stays acceptable this long. */
const GRACE_MS = 60_000;

function challenge(): string {
  return randomBytes(24).toString('base64url');
}

function inMs(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

/**
 * The registration offer for a complete session, made once: a challenge to put in the
 * `Secure-Session-Registration` header, or null when it was offered already or is bound.
 */
export function offerBinding(db: Db, sessionId: string): string | null {
  const idHash = sha256Hex(sessionId);
  return transaction(db, () => {
    const row = db.prepare('SELECT s.dbsc_offered_at, s.totp_verified, b.id AS binding FROM sessions s LEFT JOIN session_bindings b ON b.session_hash = s.id_hash WHERE s.id_hash = ?')
      .get(idHash) as { dbsc_offered_at: string | null; totp_verified: number; binding: string | null } | undefined;
    if (!row || row.dbsc_offered_at || row.binding || row.totp_verified !== 1) return null;
    const c = challenge();
    db.prepare('UPDATE sessions SET dbsc_challenge = ?, dbsc_offered_at = ? WHERE id_hash = ?').run(c, now(), idHash);
    return c;
  });
}

export interface IssuedCookie { bindingId: string; cookie: string; maxAgeSec: number; nextChallenge?: string }

/**
 * Registration: the browser answered our challenge with a proof signed by a fresh
 * device key. The session is bound to that key from now on.
 */
export function registerBinding(db: Db, sessionId: string, jwt: string): IssuedCookie {
  const idHash = sha256Hex(sessionId);
  const proof = verifyProof(jwt);
  return transaction(db, () => {
    const row = db.prepare('SELECT s.dbsc_challenge, s.totp_verified, b.id AS binding FROM sessions s LEFT JOIN session_bindings b ON b.session_hash = s.id_hash WHERE s.id_hash = ?')
      .get(idHash) as { dbsc_challenge: string | null; totp_verified: number; binding: string | null } | undefined;
    if (!row || row.totp_verified !== 1) throw new DbscError('no session');
    if (row.binding) throw new DbscError('session already bound');
    if (!row.dbsc_challenge || !safeEqual(proof.jti, row.dbsc_challenge)) throw new DbscError('challenge mismatch');
    const cookie = randomBytes(32).toString('base64url');
    const bindingId = newId('b');
    const ts = now();
    db.prepare(`INSERT INTO session_bindings (id, session_hash, alg, jwk, cookie_hash, cookie_expires_at, created_at, refreshed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(bindingId, idHash, proof.alg, JSON.stringify(proof.jwk), sha256Hex(cookie), inMs(BOUND_COOKIE_TTL_MS), ts, ts);
    db.prepare('UPDATE sessions SET dbsc_challenge = NULL WHERE id_hash = ?').run(idHash);
    return { bindingId, cookie, maxAgeSec: BOUND_COOKIE_TTL_MS / 1000 };
  });
}

interface BindingRow {
  id: string; session_hash: string; alg: DbscAlg; jwk: string; cookie_hash: string; cookie_expires_at: string;
  prev_cookie_hash: string | null; prev_cookie_expires_at: string | null; challenge: string | null; challenge_expires_at: string | null;
}

export type RefreshResult =
  /** The session is over (logged out, expired, disabled): the browser should drop the binding. */
  | { status: 'ended' }
  /** No proof, or a proof for a stale challenge: here is a fresh one, try again. */
  | { status: 'challenge'; bindingId: string; challenge: string }
  | { status: 'ok'; issued: IssuedCookie };

/** Refresh: the bound cookie expired, the browser proves it still holds the key. */
export function refreshBinding(db: Db, bindingId: string, jwt: string | null): RefreshResult {
  // Signature first, outside the transaction; the stored key decides.
  const b = db.prepare('SELECT * FROM session_bindings WHERE id = ?').get(bindingId) as BindingRow | undefined;
  if (!b) return { status: 'ended' };
  const session = db.prepare('SELECT s.expires_at, a.disabled_at FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.id_hash = ?').get(b.session_hash) as { expires_at: string; disabled_at: string | null } | undefined;
  if (!session || session.expires_at <= now() || session.disabled_at) return { status: 'ended' };

  const fresh = (): RefreshResult => {
    const c = challenge();
    db.prepare('UPDATE session_bindings SET challenge = ?, challenge_expires_at = ? WHERE id = ?').run(c, inMs(DBSC_CHALLENGE_TTL_MS), b.id);
    return { status: 'challenge', bindingId: b.id, challenge: c };
  };
  if (!jwt) return fresh();
  // A bad signature is not retriable: the key is wrong. verifyProof throws.
  const proof = verifyProof(jwt, { alg: b.alg, jwk: JSON.parse(b.jwk) as JsonWebKey });
  if (!b.challenge || !b.challenge_expires_at || b.challenge_expires_at <= now() || !safeEqual(proof.jti, b.challenge)) return fresh();

  const cookie = randomBytes(32).toString('base64url');
  const next = challenge();
  // The previous cookie stays good until it would have expired anyway: a request that
  // left before this refresh must not log the session out.
  db.prepare(`UPDATE session_bindings SET prev_cookie_hash = cookie_hash, prev_cookie_expires_at = cookie_expires_at,
              cookie_hash = ?, cookie_expires_at = ?, challenge = ?, challenge_expires_at = ?, refreshed_at = ? WHERE id = ?`)
    .run(sha256Hex(cookie), inMs(BOUND_COOKIE_TTL_MS), next, inMs(DBSC_CHALLENGE_TTL_MS), now(), b.id);
  return { status: 'ok', issued: { bindingId: b.id, cookie, maxAgeSec: BOUND_COOKIE_TTL_MS / 1000, nextChallenge: next } };
}

/**
 * For every request: an unbound session needs nothing more; a bound one only counts
 * together with a current bound cookie. A stolen session cookie alone is then useless
 * once the bound cookie it came with has expired.
 */
export function checkBoundCookie(db: Db, sessionId: string, boundCookie: string | undefined): 'unbound' | 'ok' | 'rejected' {
  const b = db.prepare('SELECT cookie_hash, cookie_expires_at, prev_cookie_hash, prev_cookie_expires_at FROM session_bindings WHERE session_hash = ?')
    .get(sha256Hex(sessionId)) as Pick<BindingRow, 'cookie_hash' | 'cookie_expires_at' | 'prev_cookie_hash' | 'prev_cookie_expires_at'> | undefined;
  if (!b) return 'unbound';
  if (!boundCookie || boundCookie.length > 128) return 'rejected';
  const h = sha256Hex(boundCookie);
  const cutoff = new Date(Date.now() - GRACE_MS).toISOString();
  if (safeEqual(h, b.cookie_hash) && b.cookie_expires_at > cutoff) return 'ok';
  if (b.prev_cookie_hash && b.prev_cookie_expires_at && safeEqual(h, b.prev_cookie_hash) && b.prev_cookie_expires_at > cutoff) return 'ok';
  return 'rejected';
}
