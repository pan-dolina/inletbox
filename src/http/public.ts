import { Router, type Request, type Response } from 'express';
import { TOKEN_RE } from '../crypto.js';
import { log } from '../log.js';
import { audit } from '../services/audit.js';
import { completeUpload, failUpload, LimitError, listFilesForLink, reserveUpload, sanitizeFilename } from '../services/files.js';
import { effectiveLimits, linkUsage, resolveToken, touchLink } from '../services/links.js';
import { StorageLimitError } from '../storage/index.js';
import type { AppContext } from './context.js';
import { LINK_STATE_MESSAGES, publicLimiter, requireLinkBearer, tokenFailureLimiter } from './middleware.js';
import { createTusServer, tusHandler } from './tus.js';
import { linkUnavailablePage, uploadPage } from './views/upload.js';

/**
 * After rejecting an upload we must still deal with the request body the client
 * may be sending. Well-behaved clients (curl, browsers) stop on their own once
 * they see the error response, so we discard what arrives; a client that keeps
 * streaming past the cap gets its connection cut.
 */
function discardBody(req: Request, capBytes = 64 * 1024 * 1024): void {
  let seen = 0;
  req.on('data', (chunk: Buffer) => {
    seen += chunk.length;
    if (seen > capBytes) req.socket.destroy();
  });
  req.on('error', () => undefined);
  req.resume();
}

/** Content-Length as a number, or null when absent/chunked. */
function declaredLength(req: Request): number | null {
  if (req.headers['transfer-encoding']) return null;
  const raw = req.headers['content-length'];
  if (raw === undefined) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

export function publicRouter(ctx: AppContext): Router {
  const r = Router();
  const tus = createTusServer(ctx);
  const tokenFailures = tokenFailureLimiter(ctx); // shared store: page and API count against the same budget

  // ---- upload page ---------------------------------------------------------
  r.get('/u/:token', tokenFailures, (req, res) => {
    const token = String(req.params.token ?? '');
    const resolved = TOKEN_RE.test(token) ? resolveToken(ctx.db, token) : null;
    if (!resolved) {
      res.status(404).type('html').send(linkUnavailablePage('Nieprawidłowy link', 'Ten link do uploadu nie istnieje.'));
      return;
    }
    if (resolved.state !== 'active') {
      const m = LINK_STATE_MESSAGES[resolved.state];
      res.status(m.status).type('html').send(linkUnavailablePage('Link niedostępny', m.message));
      return;
    }
    touchLink(ctx.db, resolved.link.id);
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(uploadPage({
      cfg: ctx.cfg, case: resolved.case, link: resolved.link, token,
      limits: effectiveLimits(ctx.cfg, resolved.link), usage: linkUsage(ctx.db, resolved.link.id),
    }));
  });

  // ---- JSON API (Bearer token) ------------------------------------------------
  const api = Router();
  api.use(publicLimiter(ctx));
  api.use(tokenFailures);
  api.use(requireLinkBearer(ctx));

  api.get('/link', (req, res) => {
    const { link, case: c } = req.uploadLink!;
    const limits = effectiveLimits(ctx.cfg, link);
    res.json({ case: { name: c.name }, link: { label: link.label, expires_at: link.expires_at }, limits, usage: linkUsage(ctx.db, link.id) });
  });

  api.get('/files', (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ files: listFilesForLink(ctx.db, req.uploadLink!.link.id) });
  });

  // No download/read endpoints exist for link holders. The next handler makes this explicit.
  api.get('/files/:id', (_req, res) => { res.status(403).json({ error: 'forbidden', message: 'Uploaded files cannot be read back through an upload link' }); });
  api.get('/files/:id/download', (_req, res) => { res.status(403).json({ error: 'forbidden', message: 'Uploaded files cannot be read back through an upload link' }); });
  api.delete('/files/:id', (_req, res) => { res.status(403).json({ error: 'forbidden', message: 'Completed files cannot be deleted through an upload link' }); });

  // Simple streaming upload: curl -T file URL/  (PUT with the file name appended) or POST with X-File-Name.
  const direct = async (req: Request, res: Response): Promise<void> => {
    const { link, case: c } = req.uploadLink!;
    const nameParam = typeof req.params.name === 'string' ? req.params.name : '';
    const headerName = typeof req.headers['x-file-name'] === 'string' ? safeDecode(req.headers['x-file-name']) : '';
    const originalName = sanitizeFilename(nameParam || headerName);
    const declared = declaredLength(req);
    const ip = req.ip ?? null; // resolve now: the socket may be gone once streaming fails

    let reservation;
    try {
      reservation = reserveUpload(ctx.db, ctx.cfg, { link, originalName, uploadKind: 'direct', declaredSize: declared, clientIp: ip });
    } catch (err) {
      if (err instanceof LimitError) {
        res.status(413).json({ error: err.code, message: err.message, limit: err.limit });
        discardBody(req);
        return;
      }
      throw err;
    }
    const { file, maxBytes } = reservation;
    audit(ctx.db, { actorType: 'link', actorId: link.id, action: 'upload.start', caseId: c.id, linkId: link.id, fileId: file.id, ip, details: { kind: 'direct', size: declared } });

    if (req.headers.expect?.toLowerCase() === '100-continue') res.writeContinue();

    let result;
    try {
      result = await ctx.storage.put(file.id, req, { maxBytes });
      if (!req.complete) throw new Error('request ended before body was complete');
      if (declared != null && result.size !== declared) throw new Error(`received ${result.size} bytes, Content-Length was ${declared}`);
    } catch (err) {
      failUpload(ctx.db, file.id, 'aborted');
      await ctx.storage.delete(file.id).catch(() => undefined);
      // The request stream was torn down mid-body: this connection must not be reused for another request.
      if (!res.headersSent) res.setHeader('Connection', 'close');
      if (err instanceof StorageLimitError) {
        audit(ctx.db, { actorType: 'link', actorId: link.id, action: 'upload.rejected', caseId: c.id, linkId: link.id, fileId: file.id, ip, details: { reason: 'limit', maxBytes } });
        res.status(413).json({ error: 'file_too_large', message: `Upload exceeded the allowed ${maxBytes} bytes`, limit: maxBytes });
        discardBody(req);
        return;
      }
      audit(ctx.db, { actorType: 'link', actorId: link.id, action: 'upload.aborted', caseId: c.id, linkId: link.id, fileId: file.id, ip, details: { reason: (err as Error).message } });
      log.info('direct upload aborted', { fileId: file.id, reason: (err as Error).message });
      if (!res.headersSent && !req.socket.destroyed) res.status(400).json({ error: 'upload_incomplete', message: 'Connection closed before the upload completed' });
      return;
    }

    completeUpload(ctx.db, file.id, result.size, result.sha256);
    audit(ctx.db, { actorType: 'link', actorId: link.id, action: 'upload.complete', caseId: c.id, linkId: link.id, fileId: file.id, ip, details: { kind: 'direct', size: result.size, name: originalName } });
    res.status(201).json({ id: file.id, name: originalName, size: result.size, sha256: result.sha256, status: 'complete' });
  };
  api.put('/upload', direct);
  api.post('/upload', direct);
  api.put('/upload/:name', direct);
  api.post('/upload/:name', direct);

  // Resumable uploads (tus). Express only authenticates; the tus server does the rest.
  api.all('/tus', tusHandler(tus));
  api.all('/tus/:id', tusHandler(tus));

  r.use('/api', api);
  return r;
}

function safeDecode(v: string): string {
  try { return decodeURIComponent(v); } catch { return v; }
}
