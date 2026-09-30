import type { Db } from '../db.js';
import { now } from '../db.js';
import { log } from '../log.js';

export interface AuditEvent {
  actorType: 'admin' | 'link' | 'system';
  actorId?: string | null;
  action: string;
  caseId?: string | null;
  linkId?: string | null;
  fileId?: string | null;
  ip?: string | null;
  details?: Record<string, unknown>;
}

export interface AuditRow {
  id: number; ts: string; actor_type: string; actor_id: string | null; action: string;
  case_id: string | null; link_id: string | null; file_id: string | null; ip: string | null; details: string | null;
  /** The account's current name, for panel actors that still exist. */
  actor_name: string | null;
}

export function audit(db: Db, ev: AuditEvent): void {
  db.prepare(
    `INSERT INTO audit_log (ts, actor_type, actor_id, action, case_id, link_id, file_id, ip, details)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(now(), ev.actorType, ev.actorId ?? null, ev.action, ev.caseId ?? null, ev.linkId ?? null, ev.fileId ?? null, ev.ip ?? null,
    ev.details ? JSON.stringify(ev.details) : null);
  log.info(`audit ${ev.action}`, { actor: `${ev.actorType}:${ev.actorId ?? '-'}`, caseId: ev.caseId, linkId: ev.linkId, fileId: ev.fileId, ip: ev.ip });
}

export function listAudit(db: Db, limit = 200): AuditRow[] {
  return db.prepare(
    `SELECT l.*, a.username AS actor_name FROM audit_log l
     LEFT JOIN admins a ON l.actor_type = 'admin' AND a.id = l.actor_id
     ORDER BY l.id DESC LIMIT ?`,
  ).all(limit) as unknown as AuditRow[];
}
