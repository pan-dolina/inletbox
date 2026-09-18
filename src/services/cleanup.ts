import type { DataStore } from '@tus/utils';
import type { Config } from '../config.js';
import type { Db } from '../db.js';
import { log } from '../log.js';
import type { StorageBackend } from '../storage/index.js';
import { audit } from './audit.js';
import { purgeExpiredSessions } from './auth.js';
import { failUpload, listCompleteFiles, listStaleUploads, liveStorageKeys, markMissing, type FileRow } from './files.js';

export interface CleanupDeps { db: Db; cfg: Config; storage: StorageBackend; tusStore: DataStore }

export interface CleanupReport { staleUploads: number; missingFiles: number; orphans: number; sessions: number }

/** Removes an unfinished upload's data from storage, whichever mechanism created it. */
export async function discardUploadData(deps: CleanupDeps, file: FileRow): Promise<void> {
  if (file.upload_kind === 'tus') {
    try { await deps.tusStore.remove(file.id); } catch { /* may already be gone */ }
  }
  await deps.storage.delete(file.id).catch((err) => log.warn('cleanup: delete failed', { fileId: file.id, err }));
}

/**
 * Keeps metadata and storage consistent:
 *  1. unfinished uploads older than the TTL are removed and their quota released;
 *  2. completed files whose object vanished are flagged as 'missing';
 *  3. storage artefacts no live file references are deleted (tus sidecars,
 *     partial objects, abandoned multipart uploads);
 *  4. expired admin sessions are purged.
 */
export async function runCleanup(deps: CleanupDeps, opts: { ttlMs?: number; verifyFiles?: boolean } = {}): Promise<CleanupReport> {
  const ttlMs = opts.ttlMs ?? deps.cfg.incompleteUploadTtlMs;
  const report: CleanupReport = { staleUploads: 0, missingFiles: 0, orphans: 0, sessions: 0 };

  for (const file of listStaleUploads(deps.db, ttlMs)) {
    await discardUploadData(deps, file);
    if (failUpload(deps.db, file.id, 'expired')) {
      report.staleUploads++;
      audit(deps.db, { actorType: 'system', action: 'upload.expired', caseId: file.case_id, linkId: file.link_id, fileId: file.id });
    }
  }

  if (opts.verifyFiles ?? true) {
    for (const file of listCompleteFiles(deps.db)) {
      const st = await deps.storage.stat(file.id).catch(() => undefined);
      if (st === undefined) continue; // storage error: don't flag
      if (st === null) {
        markMissing(deps.db, file.id);
        report.missingFiles++;
        audit(deps.db, { actorType: 'system', action: 'file.missing', caseId: file.case_id, linkId: file.link_id, fileId: file.id });
      }
    }
  }

  const live = liveStorageKeys(deps.db);
  try {
    const { removed } = await deps.storage.cleanupOrphans({ olderThanMs: ttlMs, isLive: (key) => live.has(key) });
    report.orphans = removed;
  } catch (err) {
    log.warn('cleanup: orphan sweep failed', { err });
  }

  report.sessions = purgeExpiredSessions(deps.db);
  log.info('cleanup finished', { ...report });
  return report;
}
