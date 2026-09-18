import type { IncomingMessage } from 'node:http';
import type { Request, Response } from 'express';
import { Server as TusServer, EVENTS } from '@tus/server';
import type { Upload } from '@tus/utils';
import { newId } from '../crypto.js';
import { log } from '../log.js';
import { audit } from '../services/audit.js';
import { completeUpload, failUpload, getFile, LimitError, reserveUpload } from '../services/files.js';
import { effectiveLimits, type ResolvedLink } from '../services/links.js';
import type { AppContext } from './context.js';

export const TUS_PATH = '/api/tus';

interface TusHttpError { status_code: number; body: string }

function tusError(status: number, code: string, message: string, extra: Record<string, unknown> = {}): TusHttpError {
  return { status_code: status, body: JSON.stringify({ error: code, message, ...extra }) };
}

/** The tus handlers receive a web-standard Request; the Express request (with the authenticated link) hangs off its node runtime. */
function expressReq(req: unknown): Request {
  const r = req as { runtime?: { node?: { req?: IncomingMessage } }; node?: { req?: IncomingMessage } };
  const node = r.runtime?.node?.req ?? r.node?.req;
  if (!node) throw new Error('tus: node request unavailable');
  return node as Request;
}

function linkOf(req: unknown): ResolvedLink {
  const link = expressReq(req).uploadLink;
  if (!link) throw tusError(401, 'missing_token', 'Authorization required');
  return link;
}

/**
 * Resumable uploads (browser + scripted CLI) via the tus protocol.
 *
 * Authorization model:
 *  - every request must carry a valid, active link token (checked by Express before we get here);
 *  - POST reserves quota atomically and binds the new upload id to that link;
 *  - HEAD/PATCH/DELETE on an upload id are allowed only for the link that created it
 *    and only while the upload is still in progress;
 *  - completion is idempotent at the database level.
 */
export function createTusServer(ctx: AppContext): TusServer {
  const server = new TusServer({
    path: TUS_PATH,
    datastore: ctx.tusStore,
    relativeLocation: true,
    disableTerminationForFinishedUploads: true,
    namingFunction: () => newId('f'),
    maxSize: (req) => effectiveLimits(ctx.cfg, linkOf(req).link).maxFileBytes,

    onIncomingRequest: async (req, uploadId) => {
      const method = expressReq(req).method;
      const resolved = linkOf(req);
      if (method === 'POST' || method === 'OPTIONS') return;
      const file = getFile(ctx.db, uploadId);
      if (!file || file.link_id !== resolved.link.id) {
        // Same answer for "not yours" and "does not exist": no oracle for other links' uploads.
        throw tusError(404, 'upload_not_found', 'Upload not found');
      }
      if (file.status !== 'uploading') {
        throw tusError(410, 'upload_finished', `Upload is ${file.status} and can no longer be modified`);
      }
    },

    onUploadCreate: async (req, upload: Upload) => {
      const ereq = expressReq(req);
      const resolved = linkOf(req);
      if (upload.sizeIsDeferred || upload.size === undefined) {
        throw tusError(400, 'length_required', 'Upload-Length is required (deferred length is not supported)');
      }
      try {
        reserveUpload(ctx.db, ctx.cfg, {
          id: upload.id,
          link: resolved.link,
          originalName: upload.metadata?.filename ?? 'unnamed',
          uploadKind: 'tus',
          declaredSize: upload.size,
          clientIp: ereq.ip ?? null,
        });
      } catch (err) {
        if (err instanceof LimitError) throw tusError(413, err.code, err.message, { limit: err.limit });
        throw err;
      }
      audit(ctx.db, { actorType: 'link', actorId: resolved.link.id, action: 'upload.start', caseId: resolved.case.id, linkId: resolved.link.id, fileId: upload.id, ip: ereq.ip, details: { kind: 'tus', size: upload.size } });
      return {};
    },

    onUploadFinish: async (req, upload: Upload) => {
      const ereq = expressReq(req);
      const resolved = linkOf(req);
      if (upload.size === undefined || upload.offset !== upload.size) {
        throw tusError(500, 'incomplete', 'Upload finished with unexpected offset');
      }
      const changed = completeUpload(ctx.db, upload.id, upload.size);
      if (changed) {
        audit(ctx.db, { actorType: 'link', actorId: resolved.link.id, action: 'upload.complete', caseId: resolved.case.id, linkId: resolved.link.id, fileId: upload.id, ip: ereq.ip, details: { kind: 'tus', size: upload.size, name: upload.metadata?.filename } });
        // Without its sidecar the upload can no longer be addressed via tus at all.
        ctx.storage.removeTusSidecar(upload.id).catch((e) => log.warn('tus: sidecar cleanup failed', { fileId: upload.id, err: e }));
      }
      return { status_code: 204 };
    },

    onResponseError: async (_req, err) => {
      if ('status_code' in err && typeof err.body === 'string' && err.body.startsWith('{')) return { status_code: err.status_code, body: err.body };
      if ('status_code' in err) return { status_code: err.status_code, body: JSON.stringify({ error: 'tus_error', message: err.body.trim() }) };
      log.error('tus: unexpected error', { err });
      return { status_code: 500, body: JSON.stringify({ error: 'internal', message: 'Internal error' }) };
    },
  });

  // Client-initiated termination of an in-progress upload releases its quota.
  server.on(EVENTS.POST_TERMINATE, (req, _res, id: string) => {
    try {
      const resolved = linkOf(req);
      const file = getFile(ctx.db, id);
      if (file && failUpload(ctx.db, id, 'aborted')) {
        audit(ctx.db, { actorType: 'link', actorId: resolved.link.id, action: 'upload.cancel', caseId: file.case_id, linkId: file.link_id, fileId: id });
      }
    } catch (err) {
      log.warn('tus: terminate bookkeeping failed', { err });
    }
  });

  return server;
}

/** Express adapter. GET is refused so the tus server can never act as a download endpoint. */
export function tusHandler(server: TusServer) {
  return (req: Request, res: Response): void => {
    if (req.method === 'GET') {
      res.status(405).json({ error: 'method_not_allowed', message: 'Uploaded files cannot be read back' });
      return;
    }
    if (req.headers.expect?.toLowerCase() === '100-continue') res.writeContinue();
    server.handle(req, res).catch((err) => {
      log.error('tus: handler failed', { err });
      if (!res.headersSent) res.status(500).json({ error: 'internal' });
    });
  };
}
