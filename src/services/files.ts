import type { Config } from '../config.js';
import type { Db } from '../db.js';
import { now, transaction } from '../db.js';
import { newId } from '../crypto.js';
import { effectiveLimits, linkUsage, type Link } from './links.js';

export type FileStatus = 'uploading' | 'complete' | 'aborted' | 'expired' | 'missing' | 'deleted';

export interface FileRow {
  id: string; case_id: string; link_id: string; original_name: string; upload_kind: 'tus' | 'direct'; status: FileStatus;
  declared_size: number | null; reserved_bytes: number; size: number | null; sha256: string | null; client_ip: string | null;
  created_at: string; completed_at: string | null; deleted_at: string | null;
}

export type LimitCode = 'file_too_large' | 'too_many_files' | 'quota_exceeded';

export class LimitError extends Error {
  constructor(public readonly code: LimitCode, message: string, public readonly limit: number) {
    super(message);
    this.name = 'LimitError';
  }
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;

/**
 * Normalises a client-supplied file name so it is safe to store, display and
 * send back in Content-Disposition. It is NEVER used to build a storage path.
 */
export function sanitizeFilename(raw: string | undefined | null): string {
  let name = (raw ?? '').normalize('NFC');
  // Drop any path component (both separators) and NUL / control characters.
  name = name.split(/[\\/]/).pop() ?? '';
  name = name.replace(CONTROL_CHARS, '');
  name = name.trim().replace(/^\.+$/, '');
  if (name.length > 255) {
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 && name.length - dot <= 16 ? name.slice(dot) : '';
    name = name.slice(0, 255 - ext.length) + ext;
  }
  return name || 'unnamed';
}

export interface ReserveInput {
  link: Link;
  originalName: string;
  uploadKind: 'tus' | 'direct';
  /** Size announced by the client, or null when unknown (chunked request). */
  declaredSize: number | null;
  clientIp?: string | null;
  /** Optional pre-generated id (used when the id is chosen by the tus naming function). */
  id?: string;
}

/**
 * Atomically checks every limit and reserves quota for a new upload.
 * Runs inside BEGIN IMMEDIATE, so concurrent requests are serialised and can
 * never jointly exceed the per-link quota.
 *
 * When the size is unknown, the reservation is the maximum this upload could
 * legally be (min(per-file cap, remaining quota)); the surplus is released on
 * completion.
 */
export function reserveUpload(db: Db, cfg: Config, input: ReserveInput): { file: FileRow; maxBytes: number } {
  const limits = effectiveLimits(cfg, input.link);
  if (input.declaredSize != null && (!Number.isSafeInteger(input.declaredSize) || input.declaredSize < 0)) {
    throw new Error('invalid declared size');
  }
  return transaction(db, () => {
    const usage = linkUsage(db, input.link.id);
    if (limits.maxFiles != null && usage.file_count + usage.uploading_count >= limits.maxFiles) {
      throw new LimitError('too_many_files', `This link accepts at most ${limits.maxFiles} files`, limits.maxFiles);
    }
    if (input.declaredSize != null && input.declaredSize > limits.maxFileBytes) {
      throw new LimitError('file_too_large', `File exceeds the maximum size of ${limits.maxFileBytes} bytes`, limits.maxFileBytes);
    }
    let maxBytes = limits.maxFileBytes;
    if (limits.maxTotalBytes != null) {
      const remaining = limits.maxTotalBytes - usage.used_bytes - usage.reserved_bytes;
      if (input.declaredSize != null && input.declaredSize > remaining) {
        throw new LimitError('quota_exceeded', `This link has ${Math.max(remaining, 0)} bytes of quota left`, limits.maxTotalBytes);
      }
      if (remaining <= 0) throw new LimitError('quota_exceeded', 'This link has no quota left', limits.maxTotalBytes);
      maxBytes = Math.min(maxBytes, remaining);
    }
    const reserved = input.declaredSize ?? maxBytes;
    const file: FileRow = {
      id: input.id ?? newId('f'), case_id: input.link.case_id, link_id: input.link.id,
      original_name: sanitizeFilename(input.originalName), upload_kind: input.uploadKind, status: 'uploading',
      declared_size: input.declaredSize, reserved_bytes: reserved, size: null, sha256: null, client_ip: input.clientIp ?? null,
      created_at: now(), completed_at: null, deleted_at: null,
    };
    db.prepare(
      `INSERT INTO files (id, case_id, link_id, original_name, upload_kind, status, declared_size, reserved_bytes, size, sha256, client_ip, created_at, completed_at, deleted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(file.id, file.case_id, file.link_id, file.original_name, file.upload_kind, file.status, file.declared_size, file.reserved_bytes,
      file.size, file.sha256, file.client_ip, file.created_at, file.completed_at, file.deleted_at);
    return { file, maxBytes: input.declaredSize ?? maxBytes };
  });
}

/** Idempotent: only an 'uploading' row transitions to 'complete'. Returns false if it already was. */
export function completeUpload(db: Db, fileId: string, size: number, sha256?: string | null): boolean {
  const res = db.prepare(
    `UPDATE files SET status = 'complete', size = ?, sha256 = COALESCE(?, sha256), reserved_bytes = 0, completed_at = ?
     WHERE id = ? AND status = 'uploading'`,
  ).run(size, sha256 ?? null, now(), fileId);
  return res.changes > 0;
}

export function failUpload(db: Db, fileId: string, status: 'aborted' | 'expired'): boolean {
  const res = db.prepare(`UPDATE files SET status = ?, reserved_bytes = 0 WHERE id = ? AND status = 'uploading'`).run(status, fileId);
  return res.changes > 0;
}

export function markMissing(db: Db, fileId: string): void {
  db.prepare(`UPDATE files SET status = 'missing' WHERE id = ? AND status = 'complete'`).run(fileId);
}

export function markDeleted(db: Db, fileId: string): boolean {
  const res = db.prepare(`UPDATE files SET status = 'deleted', reserved_bytes = 0, deleted_at = ? WHERE id = ? AND status IN ('complete', 'missing')`).run(now(), fileId);
  return res.changes > 0;
}

export function getFile(db: Db, id: string): FileRow | null {
  return (db.prepare('SELECT * FROM files WHERE id = ?').get(id) as FileRow | undefined) ?? null;
}

/** What an uploader may see about their own link: only their files, no storage details. */
export interface PublicFileView { id: string; name: string; size: number | null; status: 'uploading' | 'complete'; created_at: string; completed_at: string | null }

export function listFilesForLink(db: Db, linkId: string): PublicFileView[] {
  const rows = db.prepare(
    `SELECT id, original_name, size, declared_size, status, created_at, completed_at FROM files
     WHERE link_id = ? AND status IN ('uploading', 'complete') ORDER BY created_at DESC`,
  ).all(linkId) as unknown as Array<{ id: string; original_name: string; size: number | null; declared_size: number | null; status: 'uploading' | 'complete'; created_at: string; completed_at: string | null }>;
  return rows.map((r) => ({ id: r.id, name: r.original_name, size: r.size ?? r.declared_size, status: r.status, created_at: r.created_at, completed_at: r.completed_at }));
}

export interface AdminFileView extends FileRow { link_label: string }

export function listFilesForCase(db: Db, caseId: string): AdminFileView[] {
  return db.prepare(
    `SELECT f.*, l.label AS link_label FROM files f JOIN links l ON l.id = f.link_id
     WHERE f.case_id = ? AND f.status NOT IN ('aborted', 'expired') ORDER BY f.created_at DESC`,
  ).all(caseId) as unknown as AdminFileView[];
}

export function listStaleUploads(db: Db, olderThanMs: number): FileRow[] {
  const cutoff = new Date(Date.now() - olderThanMs).toISOString();
  return db.prepare(`SELECT * FROM files WHERE status = 'uploading' AND created_at < ?`).all(cutoff) as unknown as FileRow[];
}

export function listUploadingForLink(db: Db, linkId: string): FileRow[] {
  return db.prepare(`SELECT * FROM files WHERE status = 'uploading' AND link_id = ?`).all(linkId) as unknown as FileRow[];
}

export function listCompleteFiles(db: Db): FileRow[] {
  return db.prepare(`SELECT * FROM files WHERE status = 'complete'`).all() as unknown as FileRow[];
}

export function liveStorageKeys(db: Db): Set<string> {
  const rows = db.prepare(`SELECT id FROM files WHERE status IN ('uploading', 'complete')`).all() as unknown as Array<{ id: string }>;
  return new Set(rows.map((r) => r.id));
}
