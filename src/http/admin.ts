import { Router, urlencoded, type Request, type Response } from 'express';
import { create as contentDisposition } from 'content-disposition';
import QRCode from 'qrcode';
import { pipeline } from 'node:stream/promises';
import { parseSize } from '../config.js';
import { ID_RE } from '../crypto.js';
import { log } from '../log.js';
import { audit, listAudit } from '../services/audit.js';
import {
  authenticate, beginTotpEnrolment, changeAdminPassword, confirmTotpEnrolment, createSession, destroyOtherSessions, destroySession,
  disableTotp, MAX_TOTP_ATTEMPTS, pendingTotpSecret, regenerateRecoveryCodes, remainingRecoveryCodes, totpLockedUntil, verifySessionTotp,
} from '../services/auth.js';
import { createCase, getCase, listCases, updateCase } from '../services/cases.js';
import { discardUploadData } from '../services/cleanup.js';
import { failUpload, getFile, listFilesForCase, listUploadingForLink, markDeleted } from '../services/files.js';
import { createLink, getLink, listLinksForCase, revokeLink } from '../services/links.js';
import { StorageNotFoundError } from '../storage/index.js';
import { otpauthUri } from '../totp.js';
import { t, type MessageKey } from '../i18n.js';
import type { AppContext } from './context.js';
import { SESSION_COOKIE } from './context.js';
import { csrfProtect, loginLimiter, requireAdmin, sessionCookie } from './middleware.js';
import { adminNav, auditPage, casePage, casesPage, errorPage, loginPage, type AdminViewContext } from './views/admin.js';
import { securityPage, totpLoginPage, type SecurityPageData } from './views/security.js';

function viewCtx(req: Request): AdminViewContext {
  return { lang: req.lang, csrfToken: req.session!.csrfToken, username: req.session!.admin.username, path: req.originalUrl };
}

function sendError(req: Request, res: Response, titleKey: MessageKey, messageKey: MessageKey, status = 404): void {
  const e = errorPage(req.lang, t(req.lang, titleKey), t(req.lang, messageKey), status, req.originalUrl, '/admin');
  res.status(e.status).type('html').send(e.body);
}

function field(req: Request, name: string): string {
  const v = (req.body as Record<string, unknown> | undefined)?.[name];
  return typeof v === 'string' ? v : '';
}

function optionalSize(raw: string, name: string): number | null {
  const v = raw.trim();
  return v ? parseSize(v, name) : null;
}

function validId(id: string | undefined): string | null {
  return id && ID_RE.test(id) ? id : null;
}

function clearSessionCookie(res: Response): void {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

export function adminRouter(ctx: AppContext): Router {
  const r = Router();
  r.use(urlencoded({ extended: false, limit: '64kb' }));
  // One budget for password and second-factor failures.
  const loginFailures = loginLimiter(ctx);

  // ---- login / logout ----------------------------------------------------
  r.get('/login', (req, res) => {
    if (req.session) return res.redirect(req.session.totpVerified ? '/admin' : '/admin/totp');
    res.type('html').send(loginPage(req.lang, {}));
  });

  r.post('/login', loginFailures, (req, res) => {
    const username = field(req, 'username').trim();
    const password = field(req, 'password');
    const admin = username && password ? authenticate(ctx.db, username, password) : null;
    if (!admin) {
      // The attempted username is deliberately not recorded: that field routinely receives passwords typed into the wrong box.
      audit(ctx.db, { actorType: 'system', action: 'admin.login_failed', ip: req.ip });
      res.status(401).type('html').send(loginPage(req.lang, { error: t(req.lang, 'login.failed') }));
      return;
    }
    // A fresh session id on every login (no fixation); it is only "pending" until the second factor passes.
    const { sessionId } = createSession(ctx.db, admin, ctx.cfg.sessionTtlMs);
    res.setHeader('Set-Cookie', sessionCookie(ctx, sessionId, Math.floor(ctx.cfg.sessionTtlMs / 1000)));
    if (admin.totp_enabled) {
      audit(ctx.db, { actorType: 'admin', actorId: admin.id, action: 'admin.login_password', ip: req.ip });
      res.redirect(303, '/admin/totp');
      return;
    }
    audit(ctx.db, { actorType: 'admin', actorId: admin.id, action: 'admin.login', ip: req.ip });
    res.redirect(303, ctx.cfg.adminRequireTotp ? '/admin/security' : '/admin');
  });

  // Everything below needs at least a password-authenticated session and a CSRF token for state changes.
  r.use(requireAdmin({ verified: false }));
  r.use(csrfProtect(ctx));

  r.post('/logout', (req, res) => {
    if (req.sessionId) destroySession(ctx.db, req.sessionId);
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.logout', ip: req.ip });
    clearSessionCookie(res);
    res.redirect(303, '/admin/login');
  });

  // ---- second factor -------------------------------------------------------
  r.get('/totp', (req, res) => {
    if (req.session!.totpVerified) return res.redirect('/admin');
    const lockedUntil = totpLockedUntil(ctx.db, req.session!.admin.id);
    res.type('html').send(totpLoginPage(req.lang, { csrfToken: req.session!.csrfToken, lockedUntil: lockedUntil ?? undefined }));
  });

  r.post('/totp', loginFailures, (req, res) => {
    const session = req.session!;
    if (session.totpVerified) return res.redirect(303, '/admin');
    const result = verifySessionTotp(ctx.db, req.sessionId!, field(req, 'code'), ctx.cfg.sessionTtlMs);
    if (result.status === 'ok') {
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.login', ip: req.ip, details: { second_factor: true } });
      // Fresh session id for the privileged session.
      res.setHeader('Set-Cookie', sessionCookie(ctx, result.sessionId, Math.floor(ctx.cfg.sessionTtlMs / 1000)));
      res.redirect(303, '/admin');
      return;
    }
    if (result.status === 'locked') {
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_locked', ip: req.ip, details: { account_locked_until: result.accountLockedUntil } });
      clearSessionCookie(res);
      res.status(401).type('html').send(loginPage(req.lang, { error: t(req.lang, result.accountLockedUntil ? 'login.account_locked' : 'login.too_many_codes') }));
      return;
    }
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_failed', ip: req.ip });
    res.status(401).type('html').send(totpLoginPage(req.lang, { csrfToken: session.csrfToken, error: t(req.lang, 'totp.invalid'), attemptsLeft: MAX_TOTP_ATTEMPTS - session.totpAttempts - 1 }));
  });

  // From here on the second factor must have been passed.
  r.use(requireAdmin({ verified: true }));

  // ---- security settings ------------------------------------------------
  async function renderSecurity(req: Request, res: Response, extra: Partial<SecurityPageData> = {}, status = 200): Promise<void> {
    const session = req.session!;
    const pending = session.admin.totp_enabled ? null : pendingTotpSecret(ctx.db, session.admin.id);
    let enrol: SecurityPageData['enrol'];
    if (pending) {
      const uri = otpauthUri({ secret: pending, account: session.admin.username, issuer: ctx.cfg.brand.name });
      const qrSvg = await QRCode.toString(uri, { type: 'svg', margin: 1, width: 200 });
      enrol = { qrSvg, secret: pending, uri };
    }
    res.status(status).type('html').send(securityPage({
      lang: req.lang, csrfToken: session.csrfToken, username: session.admin.username, nav: adminNav(viewCtx(req)),
      totpEnabled: session.admin.totp_enabled, totpRequired: ctx.cfg.adminRequireTotp, issuer: ctx.cfg.brand.name,
      recoveryLeft: session.admin.totp_enabled ? remainingRecoveryCodes(ctx.db, session.admin.id) : 0,
      enrol, ...extra,
    }));
  }

  r.get('/security', (req, res, next) => { renderSecurity(req, res).catch(next); });

  r.post('/security/password', (req, res, next) => {
    const session = req.session!;
    const newPassword = field(req, 'new_password');
    if (newPassword !== field(req, 'new_password_confirm')) {
      renderSecurity(req, res, { error: t(req.lang, 'security.password.mismatch') }, 400).catch(next);
      return;
    }
    try {
      if (!changeAdminPassword(ctx.db, session.admin.id, field(req, 'current_password'), newPassword)) {
        renderSecurity(req, res, { error: t(req.lang, 'security.password.invalid_current') }, 400).catch(next);
        return;
      }
    } catch (err) {
      renderSecurity(req, res, { error: (err as Error).message }, 400).catch(next);
      return;
    }
    destroyOtherSessions(ctx.db, session.admin.id, req.sessionId!);
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.password_changed', ip: req.ip });
    renderSecurity(req, res, { ok: t(req.lang, 'security.password.changed') }).catch(next);
  });

  r.post('/security/totp/begin', (req, res, next) => {
    try {
      beginTotpEnrolment(ctx.db, req.session!.admin.id);
      renderSecurity(req, res).catch(next);
    } catch (err) {
      renderSecurity(req, res, { error: (err as Error).message }, 400).catch(next);
    }
  });

  r.post('/security/totp/confirm', (req, res, next) => {
    const session = req.session!;
    const codes = confirmTotpEnrolment(ctx.db, session.admin.id, field(req, 'code'));
    if (!codes) {
      renderSecurity(req, res, { error: t(req.lang, 'security.msg.code_mismatch') }, 400).catch(next);
      return;
    }
    // Other sessions of this admin did not prove the second factor: end them.
    destroyOtherSessions(ctx.db, session.admin.id, req.sessionId!);
    session.admin.totp_enabled = true;
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_enabled', ip: req.ip });
    renderSecurity(req, res, { ok: t(req.lang, 'security.msg.enabled'), recoveryCodes: codes }).catch(next);
  });

  r.post('/security/totp/recovery', (req, res, next) => {
    const session = req.session!;
    const codes = regenerateRecoveryCodes(ctx.db, session.admin.id, field(req, 'code'));
    if (!codes) {
      renderSecurity(req, res, { error: t(req.lang, 'security.msg.invalid_code') }, 400).catch(next);
      return;
    }
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.recovery_codes_regenerated', ip: req.ip });
    renderSecurity(req, res, { ok: t(req.lang, 'security.msg.regenerated'), recoveryCodes: codes }).catch(next);
  });

  r.post('/security/totp/disable', (req, res, next) => {
    const session = req.session!;
    if (ctx.cfg.adminRequireTotp) {
      renderSecurity(req, res, { error: t(req.lang, 'security.msg.required') }, 400).catch(next);
      return;
    }
    if (!disableTotp(ctx.db, session.admin.id, field(req, 'code'), req.sessionId!)) {
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_failed', ip: req.ip, details: { context: 'disable' } });
      renderSecurity(req, res, { error: t(req.lang, 'security.msg.invalid_code') }, 400).catch(next);
      return;
    }
    session.admin.totp_enabled = false;
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_disabled', ip: req.ip });
    renderSecurity(req, res, { ok: t(req.lang, 'security.msg.disabled') }).catch(next);
  });

  // With ADMIN_REQUIRE_TOTP, admins without a second factor may only reach the security page.
  r.use((req, res, next) => {
    if (ctx.cfg.adminRequireTotp && !req.session!.admin.totp_enabled) {
      if (req.method === 'GET') return res.redirect(302, '/admin/security');
      res.status(403).type('text/plain').send('TOTP enrolment required');
      return;
    }
    next();
  });

  // ---- cases -------------------------------------------------------------
  r.get('/', (req, res) => {
    res.type('html').send(casesPage(viewCtx(req), listCases(ctx.db)));
  });

  r.post('/cases', (req, res) => {
    try {
      const c = createCase(ctx.db, { name: field(req, 'name'), description: field(req, 'description') });
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'case.create', caseId: c.id, ip: req.ip, details: { name: c.name } });
      res.redirect(303, `/admin/cases/${c.id}`);
    } catch (err) {
      res.status(400).type('html').send(casesPage(viewCtx(req), listCases(ctx.db), { error: (err as Error).message }));
    }
  });

  function renderCase(req: Request, res: Response, caseId: string, extra: { error?: string; ok?: string; newLink?: { label: string; url: string } } = {}, status = 200): void {
    const c = getCase(ctx.db, caseId);
    if (!c) return sendError(req, res, 'error.not_found.title', 'error.case_missing');
    res.status(status).type('html').send(casePage(viewCtx(req), { case: c, links: listLinksForCase(ctx.db, c.id), files: listFilesForCase(ctx.db, c.id), cfg: ctx.cfg, ...extra }));
  }

  r.get('/cases/:id', (req, res) => {
    const id = validId(req.params.id);
    if (!id) return renderCase(req, res, '');
    renderCase(req, res, id);
  });

  r.post('/cases/:id', (req, res) => {
    const id = validId(req.params.id);
    if (!id) return renderCase(req, res, '');
    try {
      const c = updateCase(ctx.db, id, { name: field(req, 'name'), description: field(req, 'description') });
      if (!c) return renderCase(req, res, '');
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'case.update', caseId: id, ip: req.ip });
      renderCase(req, res, id, { ok: t(req.lang, 'case.saved') });
    } catch (err) {
      renderCase(req, res, id, { error: (err as Error).message }, 400);
    }
  });

  r.post('/cases/:id/status', (req, res) => {
    const id = validId(req.params.id);
    if (!id) return renderCase(req, res, '');
    const status = field(req, 'status') === 'closed' ? 'closed' : 'open';
    const c = updateCase(ctx.db, id, { status });
    if (!c) return renderCase(req, res, '');
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: status === 'closed' ? 'case.close' : 'case.reopen', caseId: id, ip: req.ip });
    res.redirect(303, `/admin/cases/${id}`);
  });

  // ---- links -------------------------------------------------------------
  r.post('/cases/:id/links', (req, res) => {
    const id = validId(req.params.id);
    if (!id) return renderCase(req, res, '');
    const c = getCase(ctx.db, id);
    if (!c) return renderCase(req, res, '');
    if (c.status !== 'open') return renderCase(req, res, id, { error: t(req.lang, 'case.closed_no_links') }, 400);
    try {
      const expiresRaw = field(req, 'expires_at').trim();
      const expiresAt = expiresRaw ? new Date(expiresRaw.endsWith('Z') ? expiresRaw : `${expiresRaw}Z`) : null;
      if (expiresAt && Number.isNaN(expiresAt.getTime())) throw new Error(t(req.lang, 'error.invalid_expiry'));
      const maxFilesRaw = field(req, 'max_files').trim();
      const { link, url } = createLink(ctx.db, ctx.cfg, {
        caseId: id,
        label: field(req, 'label'),
        expiresAt,
        maxFileBytes: optionalSize(field(req, 'max_file_size'), 'max file size'),
        maxFiles: maxFilesRaw ? Number(maxFilesRaw) : null,
        maxTotalBytes: optionalSize(field(req, 'max_total_size'), 'max total size'),
      });
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'link.create', caseId: id, linkId: link.id, ip: req.ip, details: { label: link.label, expires_at: link.expires_at, max_file_bytes: link.max_file_bytes, max_files: link.max_files, max_total_bytes: link.max_total_bytes } });
      // The full URL is shown exactly once, in this response. It is not stored anywhere.
      renderCase(req, res, id, { newLink: { label: link.label, url } });
    } catch (err) {
      renderCase(req, res, id, { error: (err as Error).message }, 400);
    }
  });

  r.post('/links/:id/revoke', async (req, res) => {
    const id = validId(req.params.id);
    const link = id ? getLink(ctx.db, id) : null;
    if (!link) return sendError(req, res, 'error.not_found.title', 'error.link_missing');
    if (revokeLink(ctx.db, link.id)) {
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'link.revoke', caseId: link.case_id, linkId: link.id, ip: req.ip });
      // In-flight uploads on a revoked link are discarded immediately.
      for (const f of listUploadingForLink(ctx.db, link.id)) {
        await discardUploadData(ctx, f);
        failUpload(ctx.db, f.id, 'aborted');
      }
    }
    res.redirect(303, `/admin/cases/${link.case_id}`);
  });

  // ---- files -------------------------------------------------------------
  r.get('/files/:id/download', async (req, res) => {
    const id = validId(req.params.id);
    const file = id ? getFile(ctx.db, id) : null;
    if (!file || file.status !== 'complete') return sendError(req, res, 'error.not_found.title', 'error.file_missing');
    let stream;
    try {
      stream = await ctx.storage.get(file.id);
    } catch (err) {
      if (err instanceof StorageNotFoundError) return sendError(req, res, 'error.storage_missing.title', 'error.storage_missing', 410);
      throw err;
    }
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'file.download', caseId: file.case_id, linkId: file.link_id, fileId: file.id, ip: req.ip });
    // Always an opaque attachment: never sniffed, never rendered, never scripted.
    res.status(200);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', contentDisposition(file.original_name, { type: 'attachment' }));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('Cache-Control', 'no-store');
    if (file.size != null) res.setHeader('Content-Length', String(file.size));
    try {
      await pipeline(stream, res);
    } catch (err) {
      // Client went away mid-download; nothing to do.
      log.debug('download interrupted', { fileId: file.id, err: err as Error });
    }
  });

  r.post('/files/:id/delete', async (req, res) => {
    const id = validId(req.params.id);
    const file = id ? getFile(ctx.db, id) : null;
    if (!file) return sendError(req, res, 'error.not_found.title', 'error.file_not_exist');
    if (markDeleted(ctx.db, file.id)) {
      await ctx.storage.delete(file.id);
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'file.delete', caseId: file.case_id, linkId: file.link_id, fileId: file.id, ip: req.ip, details: { name: file.original_name, size: file.size } });
    }
    res.redirect(303, `/admin/cases/${file.case_id}`);
  });

  // ---- audit -------------------------------------------------------------
  r.get('/audit', (req, res) => {
    res.type('html').send(auditPage(viewCtx(req), listAudit(ctx.db, 300)));
  });

  return r;
}
