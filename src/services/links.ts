import type { Config } from '../config.js';
import type { Db } from '../db.js';
import { now } from '../db.js';
import { newId, newToken, sha256Hex, TOKEN_RE } from '../crypto.js';
import { getCase, type Case } from './cases.js';

export interface Link {
  id: string; case_id: string; label: string; token_hash: string; token_hint: string;
  expires_at: string | null; revoked_at: string | null;
  max_file_bytes: number | null; max_files: number | null; max_total_bytes: number | null;
  created_at: string; last_used_at: string | null;
}

export interface LinkUsage { file_count: number; used_bytes: number; reserved_bytes: number; uploading_count: number }

export interface EffectiveLimits {
  maxFileBytes: number;
  maxFiles: number | null;
  maxTotalBytes: number | null;
}

export type LinkState = 'active' | 'expired' | 'revoked' | 'case_closed';

export interface ResolvedLink { link: Link; case: Case; state: LinkState }

export interface CreateLinkInput {
  caseId: string;
  label: string;
  expiresAt?: Date | null;
  maxFileBytes?: number | null;
  maxFiles?: number | null;
  maxTotalBytes?: number | null;
}

export function createLink(db: Db, cfg: Config, input: CreateLinkInput): { link: Link; token: string; url: string } {
  const label = input.label.trim().slice(0, 200) || 'Odbiorca';
  if (input.maxFileBytes != null && (input.maxFileBytes < 1 || input.maxFileBytes > cfg.maxFileBytes)) {
    throw new Error(`Per-link file size limit must be between 1 and the global limit (${cfg.maxFileBytes} bytes)`);
  }
  if (input.maxFiles != null && (input.maxFiles < 1 || !Number.isInteger(input.maxFiles))) throw new Error('max files must be a positive integer');
  if (input.maxTotalBytes != null && input.maxTotalBytes < 1) throw new Error('max total bytes must be positive');
  if (input.expiresAt && input.expiresAt.getTime() <= Date.now()) throw new Error('Expiry must be in the future');
  if (!getCase(db, input.caseId)) throw new Error('Case not found');

  const token = newToken();
  const link: Link = {
    id: newId('l'), case_id: input.caseId, label, token_hash: sha256Hex(token), token_hint: token.slice(0, 6),
    expires_at: input.expiresAt ? input.expiresAt.toISOString() : null, revoked_at: null,
    max_file_bytes: input.maxFileBytes ?? null, max_files: input.maxFiles ?? null, max_total_bytes: input.maxTotalBytes ?? null,
    created_at: now(), last_used_at: null,
  };
  db.prepare(
    `INSERT INTO links (id, case_id, label, token_hash, token_hint, expires_at, revoked_at, max_file_bytes, max_files, max_total_bytes, created_at, last_used_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(link.id, link.case_id, link.label, link.token_hash, link.token_hint, link.expires_at, link.revoked_at,
    link.max_file_bytes, link.max_files, link.max_total_bytes, link.created_at, link.last_used_at);
  // The clear-text token exists only in this return value; the database keeps its SHA-256.
  return { link, token, url: linkUrl(cfg, token) };
}

export function linkUrl(cfg: Config, token: string): string {
  return `${cfg.publicUrl}/u/${token}`;
}

export function getLink(db: Db, id: string): Link | null {
  return (db.prepare('SELECT * FROM links WHERE id = ?').get(id) as Link | undefined) ?? null;
}

export function listLinksForCase(db: Db, caseId: string): Array<Link & LinkUsage> {
  return db.prepare(
    `SELECT l.*,
       (SELECT COUNT(*) FROM files f WHERE f.link_id = l.id AND f.status = 'complete') AS file_count,
       (SELECT COALESCE(SUM(size), 0) FROM files f WHERE f.link_id = l.id AND f.status = 'complete') AS used_bytes,
       (SELECT COALESCE(SUM(reserved_bytes), 0) FROM files f WHERE f.link_id = l.id AND f.status = 'uploading') AS reserved_bytes,
       (SELECT COUNT(*) FROM files f WHERE f.link_id = l.id AND f.status = 'uploading') AS uploading_count
     FROM links l WHERE l.case_id = ? ORDER BY l.created_at DESC`,
  ).all(caseId) as unknown as Array<Link & LinkUsage>;
}

export function revokeLink(db: Db, id: string): boolean {
  const res = db.prepare('UPDATE links SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now(), id);
  return res.changes > 0;
}

export function linkState(link: Link, c: Case): LinkState {
  if (link.revoked_at) return 'revoked';
  if (link.expires_at && link.expires_at <= now()) return 'expired';
  if (c.status !== 'open') return 'case_closed';
  return 'active';
}

/** Looks a link up by its clear-text token. Returns null for unknown tokens. */
export function resolveToken(db: Db, token: string): ResolvedLink | null {
  if (!TOKEN_RE.test(token)) return null;
  const link = db.prepare('SELECT * FROM links WHERE token_hash = ?').get(sha256Hex(token)) as Link | undefined;
  if (!link) return null;
  const c = getCase(db, link.case_id);
  if (!c) return null;
  return { link, case: c, state: linkState(link, c) };
}

export function touchLink(db: Db, id: string): void {
  db.prepare('UPDATE links SET last_used_at = ? WHERE id = ?').run(now(), id);
}

export function effectiveLimits(cfg: Config, link: Link): EffectiveLimits {
  return {
    maxFileBytes: Math.min(cfg.maxFileBytes, link.max_file_bytes ?? cfg.maxFileBytes),
    maxFiles: link.max_files,
    maxTotalBytes: link.max_total_bytes,
  };
}

export function linkUsage(db: Db, linkId: string): LinkUsage {
  return db.prepare(
    `SELECT
       (SELECT COUNT(*) FROM files WHERE link_id = ? AND status = 'complete') AS file_count,
       (SELECT COALESCE(SUM(size), 0) FROM files WHERE link_id = ? AND status = 'complete') AS used_bytes,
       (SELECT COALESCE(SUM(reserved_bytes), 0) FROM files WHERE link_id = ? AND status = 'uploading') AS reserved_bytes,
       (SELECT COUNT(*) FROM files WHERE link_id = ? AND status = 'uploading') AS uploading_count`,
  ).get(linkId, linkId, linkId, linkId) as unknown as LinkUsage;
}
