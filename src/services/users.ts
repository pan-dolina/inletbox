import type { Db } from '../db.js';
import { now, transaction } from '../db.js';
import { hashPassword, newTempPassword } from '../crypto.js';
import type { MessageKey } from '../i18n.js';
import { createAdmin, findAdminByUsername, forceDisableTotp, isValidUsername, ROLES, type Admin, type Role } from './auth.js';

/**
 * Accounts and who may work on which case.
 *
 *  - 'admin' sees every case, manages accounts and reads the audit log;
 *  - 'user' sees only the cases it is assigned to (`case_members`), and inside
 *    those may do everything an administrator can do with the case itself.
 *
 * Nobody changes their own account here: an administrator cannot demote,
 * disable or delete themselves, so the instance always keeps an administrator
 * who is signed in and able to undo a mistake. The service checks the same
 * "at least one active administrator" rule again, for callers other than the panel.
 */

/** A refusal the panel shows in the administrator's language. */
export class UserError extends Error {
  constructor(public readonly key: MessageKey, public readonly params: Record<string, string | number> = {}) {
    super(key);
    this.name = 'UserError';
  }
}

export interface UserSummary {
  id: string;
  username: string;
  role: Role;
  created_at: string;
  last_login_at: string | null;
  disabled_at: string | null;
  must_change_password: boolean;
  totp_enabled: boolean;
  case_count: number;
}

export interface CaseMember { id: string; username: string; role: Role; disabled_at: string | null }

/** Who is asking: enough of a session to decide what it may see. */
export type Viewer = Pick<Admin, 'id' | 'role'>;

export function isRole(v: unknown): v is Role {
  return typeof v === 'string' && (ROLES as readonly string[]).includes(v);
}

export function listUsers(db: Db): UserSummary[] {
  const rows = db.prepare(
    `SELECT a.id, a.username, a.role, a.created_at, a.last_login_at, a.disabled_at, a.must_change_password,
            a.totp_enabled_at IS NOT NULL AS totp_enabled,
            (SELECT COUNT(*) FROM case_members m WHERE m.admin_id = a.id) AS case_count
     FROM admins a ORDER BY a.disabled_at IS NOT NULL, a.role, a.username COLLATE NOCASE`,
  ).all() as Array<Omit<UserSummary, 'must_change_password' | 'totp_enabled'> & { must_change_password: number; totp_enabled: number }>;
  return rows.map((r) => ({ ...r, must_change_password: r.must_change_password === 1, totp_enabled: r.totp_enabled === 1 }));
}

export function getUser(db: Db, id: string): UserSummary | null {
  return listUsers(db).find((u) => u.id === id) ?? null;
}

function activeAdminsOtherThan(db: Db, id: string): number {
  return (db.prepare("SELECT COUNT(*) AS n FROM admins WHERE role = 'admin' AND disabled_at IS NULL AND id != ?").get(id) as { n: number }).n;
}

function requireUser(db: Db, actorId: string, id: string): UserSummary {
  const user = getUser(db, id);
  if (!user) throw new UserError('users.missing');
  if (user.id === actorId) throw new UserError('users.not_self');
  return user;
}

/**
 * A new account with a generated password, returned once for the administrator
 * to hand over. The owner has to replace it before they can do anything else.
 */
export function createUser(db: Db, input: { username: string; role: Role }): { user: Admin; password: string } {
  const username = input.username.trim();
  if (!isValidUsername(username)) throw new UserError('users.invalid_username');
  if (!isRole(input.role)) throw new UserError('users.invalid_role');
  if (findAdminByUsername(db, username)) throw new UserError('users.exists', { username });
  const password = newTempPassword();
  const user = createAdmin(db, username, password, { role: input.role, mustChangePassword: true });
  return { user, password };
}

export function setUserRole(db: Db, actorId: string, id: string, role: Role): UserSummary {
  if (!isRole(role)) throw new UserError('users.invalid_role');
  return transaction(db, () => {
    const user = requireUser(db, actorId, id);
    if (user.role === 'admin' && role !== 'admin' && activeAdminsOtherThan(db, id) === 0) throw new UserError('users.last_admin');
    db.prepare('UPDATE admins SET role = ? WHERE id = ?').run(role, id);
    // Case assignments are kept: demoting an administrator to a user leaves them
    // with whatever they were assigned, which is usually nothing — never more.
    return { ...user, role };
  });
}

/** A disabled account cannot sign in and every session it had ends now. Its history stays. */
export function setUserDisabled(db: Db, actorId: string, id: string, disabled: boolean): UserSummary {
  return transaction(db, () => {
    const user = requireUser(db, actorId, id);
    if (disabled && user.role === 'admin' && activeAdminsOtherThan(db, id) === 0) throw new UserError('users.last_admin');
    db.prepare('UPDATE admins SET disabled_at = ? WHERE id = ?').run(disabled ? now() : null, id);
    if (disabled) db.prepare('DELETE FROM sessions WHERE admin_id = ?').run(id);
    return { ...user, disabled_at: disabled ? now() : null };
  });
}

/** A new temporary password (returned once); the old one and every session stop working. */
export function resetUserPassword(db: Db, actorId: string, id: string): { user: UserSummary; password: string } {
  return transaction(db, () => {
    const user = requireUser(db, actorId, id);
    const password = newTempPassword();
    db.prepare('UPDATE admins SET password_hash = ?, must_change_password = 1 WHERE id = ?').run(hashPassword(password), id);
    db.prepare('DELETE FROM sessions WHERE admin_id = ?').run(id);
    return { user, password };
  });
}

/** For a lost authenticator: the second factor goes, and the owner enrols again after signing in. */
export function resetUserTotp(db: Db, actorId: string, id: string): UserSummary {
  const user = requireUser(db, actorId, id);
  forceDisableTotp(db, id);
  return user;
}

/**
 * Removes the account, its sessions and its case assignments. What it did stays
 * in the audit log under its id; files it published keep existing.
 */
export function deleteUser(db: Db, actorId: string, id: string): UserSummary {
  return transaction(db, () => {
    const user = requireUser(db, actorId, id);
    if (user.role === 'admin' && activeAdminsOtherThan(db, id) === 0) throw new UserError('users.last_admin');
    db.prepare('DELETE FROM admins WHERE id = ?').run(id);
    return user;
  });
}

// ---------------------------------------------------------------------------
// Case assignments
// ---------------------------------------------------------------------------

/** The one access rule: administrators see every case, users the ones they are assigned to. */
export function canAccessCase(db: Db, viewer: Viewer, caseId: string): boolean {
  if (viewer.role === 'admin') return true;
  return db.prepare('SELECT 1 FROM case_members WHERE case_id = ? AND admin_id = ?').get(caseId, viewer.id) !== undefined;
}

export function caseMembers(db: Db, caseId: string): CaseMember[] {
  return db.prepare(
    `SELECT a.id, a.username, a.role, a.disabled_at FROM case_members m JOIN admins a ON a.id = m.admin_id
     WHERE m.case_id = ? ORDER BY a.username COLLATE NOCASE`,
  ).all(caseId) as unknown as CaseMember[];
}

/** Accounts that could still be assigned to a case: active users not on it yet. */
export function assignableUsers(db: Db, caseId: string): CaseMember[] {
  return db.prepare(
    `SELECT a.id, a.username, a.role, a.disabled_at FROM admins a
     WHERE a.role = 'user' AND a.disabled_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM case_members m WHERE m.case_id = ? AND m.admin_id = a.id)
     ORDER BY a.username COLLATE NOCASE`,
  ).all(caseId) as unknown as CaseMember[];
}

/** Returns false when the account was already assigned. */
export function addCaseMember(db: Db, caseId: string, adminId: string): boolean {
  return db.prepare('INSERT OR IGNORE INTO case_members (case_id, admin_id, created_at) VALUES (?, ?, ?)').run(caseId, adminId, now()).changes > 0;
}

export function removeCaseMember(db: Db, caseId: string, adminId: string): boolean {
  return db.prepare('DELETE FROM case_members WHERE case_id = ? AND admin_id = ?').run(caseId, adminId).changes > 0;
}
