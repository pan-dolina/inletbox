import type { Db } from '../db.js';
import { now } from '../db.js';
import { newId } from '../crypto.js';

export interface Case {
  id: string; name: string; description: string; status: 'open' | 'closed'; created_at: string; updated_at: string;
}
export interface CaseSummary extends Case { link_count: number; file_count: number; total_bytes: number }

export function createCase(db: Db, input: { name: string; description?: string }): Case {
  const name = input.name.trim();
  if (!name || name.length > 200) throw new Error('Case name must be 1-200 characters');
  const c: Case = { id: newId('c'), name, description: (input.description ?? '').trim().slice(0, 5000), status: 'open', created_at: now(), updated_at: now() };
  db.prepare('INSERT INTO cases (id, name, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(c.id, c.name, c.description, c.status, c.created_at, c.updated_at);
  return c;
}

export function getCase(db: Db, id: string): Case | null {
  return (db.prepare('SELECT * FROM cases WHERE id = ?').get(id) as Case | undefined) ?? null;
}

export function listCases(db: Db): CaseSummary[] {
  return db.prepare(
    `SELECT c.*,
       (SELECT COUNT(*) FROM links l WHERE l.case_id = c.id AND l.revoked_at IS NULL) AS link_count,
       (SELECT COUNT(*) FROM files f WHERE f.case_id = c.id AND f.status = 'complete') AS file_count,
       (SELECT COALESCE(SUM(size), 0) FROM files f WHERE f.case_id = c.id AND f.status = 'complete') AS total_bytes
     FROM cases c ORDER BY c.status = 'open' DESC, c.created_at DESC`,
  ).all() as unknown as CaseSummary[];
}

export function updateCase(db: Db, id: string, input: { name?: string; description?: string; status?: 'open' | 'closed' }): Case | null {
  const existing = getCase(db, id);
  if (!existing) return null;
  const name = input.name !== undefined ? input.name.trim() : existing.name;
  if (!name || name.length > 200) throw new Error('Case name must be 1-200 characters');
  const description = input.description !== undefined ? input.description.trim().slice(0, 5000) : existing.description;
  const status = input.status ?? existing.status;
  if (!['open', 'closed'].includes(status)) throw new Error('Invalid status');
  db.prepare('UPDATE cases SET name = ?, description = ?, status = ?, updated_at = ? WHERE id = ?').run(name, description, status, now(), id);
  return getCase(db, id);
}
