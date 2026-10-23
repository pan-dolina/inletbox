import { Router, urlencoded, type NextFunction, type Request, type Response } from 'express';
import { create as contentDisposition } from 'content-disposition';
import QRCode from 'qrcode';
import { pipeline } from 'node:stream/promises';
import { parseSize } from '../config.js';
import { ID_RE } from '../crypto.js';
import { log } from '../log.js';
import { audit, listAudit } from '../services/audit.js';
import {
  authenticate, beginTotpEnrolment, changeAdminPassword, confirmTotpEnrolment, createSession, destroyOtherSessions, destroySession,
  disableTotp, hasSecondFactor, markConfirmed, MAX_TOTP_ATTEMPTS, pendingTotpSecret, recordLogin, regenerateRecoveryCodes,
  regenerateRecoveryCodesConfirmed, remainingRecoveryCodes, totpLockedUntil, verifyConfirmCode, verifySessionTotp, type Admin,
} from '../services/auth.js';
import {
  beginCeremony, credentialIds, listPasskeys, MAX_PASSKEYS, registerPasskey, removePasskey, verifyPasskeyConfirm, verifyPasskeyLogin, CEREMONY_TTL_MS,
} from '../services/passkeys.js';
import { listSessions, offerBinding, refreshBinding, registerBinding, revokeSession, type IssuedCookie } from '../services/sessions.js';
import { DbscError, proofFromHeader } from '../dbsc.js';
import { WebAuthnError, type Expected } from '../webauthn.js';
import {
  addCaseMember, assignableUsers, canAccessCase, caseMembers, createUser, deleteUser, getUser, isRole, listUsers, removeCaseMember,
  resetUserPassword, resetUserTotp, setUserDisabled, setUserRole, UserError, type UserSummary,
} from '../services/users.js';
import { createCase, getCase, listCases, updateCase, type Case } from '../services/cases.js';
import { discardUploadData } from '../services/cleanup.js';
import { failUpload, getFile, listFilesForCase, listUploadingForLink, markDeleted } from '../services/files.js';
import { createLink, getLink, listLinksForCase, revokeLink } from '../services/links.js';
import { StorageNotFoundError } from '../storage/index.js';
import { otpauthUri } from '../totp.js';
import { t, type MessageKey } from '../i18n.js';
import type { AppContext } from './context.js';
import { BOUND_COOKIE, SESSION_COOKIE } from './context.js';
import { csrfProtect, loginLimiter, requireAdmin, requireConfirmed, safeNext, sessionCookie } from './middleware.js';
import { adminNav, auditPage, casePage, casesPage, errorPage, usersPage, type UsersPageData, loginPage, type AdminViewContext } from './views/admin.js';
import { confirmPage, securityPage, totpLoginPage, type SecurityPageData } from './views/security.js';

function viewCtx(req: Request): AdminViewContext {
  const { admin } = req.session!;
  return { lang: req.lang, csrfToken: req.session!.csrfToken, username: admin.username, path: req.originalUrl, role: admin.role, userId: admin.id };
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

/** A route parameter as a string; Express types it loosely once middleware sits in front of the handler. */
function param(req: Request, name: string): string | undefined {
  const v = req.params[name];
  return typeof v === 'string' ? v : undefined;
}

function validId(id: string | undefined): string | null {
  return id && ID_RE.test(id) ? id : null;
}

function clearSessionCookie(res: Response): void {
  res.setHeader('Set-Cookie', [`${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`, `${BOUND_COOKIE}=; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=0`]);
}

/** Recorded with the session and shown in the account's session list. */
function sessionMeta(req: Request): { ip?: string; userAgent?: string } {
  return { ip: req.ip, userAgent: req.headers['user-agent'] };
}

/** A JSON answer for passkey.js: where to go next, or what went wrong. */
function sendJson(res: Response, status: number, body: { redirect?: string; error?: string } & Record<string, unknown>): void {
  res.status(status).type('application/json').setHeader('Cache-Control', 'no-store');
  res.send(JSON.stringify(body));
}

export function adminRouter(ctx: AppContext): Router {
  const r = Router();
  r.use(urlencoded({ extended: false, limit: '64kb' }));
  // One budget for password and second-factor failures.
  const loginFailures = loginLimiter(ctx);

  /** What every WebAuthn ceremony must be bound to: this site, as PUBLIC_URL names it. */
  const publicUrl = new URL(ctx.cfg.publicUrl);
  const rp: Omit<Expected, 'challenge'> = { origin: publicUrl.origin, rpId: publicUrl.hostname };

  const boundCookie = (c: IssuedCookie): string =>
    `${BOUND_COOKIE}=${c.cookie}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=${c.maxAgeSec}${ctx.cfg.cookieSecure ? '; Secure' : ''}`;
  /** The session config the browser keeps for a bound session (DBSC). */
  const dbscConfig = (bindingId: string) => ({
    session_identifier: bindingId,
    refresh_url: '/admin/dbsc/refresh',
    scope: { origin: publicUrl.origin, include_site: false },
    credentials: [{ type: 'cookie', name: BOUND_COOKIE, attributes: `Path=/admin; HttpOnly; SameSite=Lax${ctx.cfg.cookieSecure ? '; Secure' : ''}` }],
  });

  // ---- device-bound sessions (DBSC) ---------------------------------------
  // The browser calls these on its own. They carry no CSRF token (a signature over our
  // challenge stands in for it) and never redirect: a redirect here can stall the
  // navigation the browser is holding back.
  r.post('/dbsc/register', (req, res) => {
    const jwt = proofFromHeader(req.headers['secure-session-response']);
    if (!req.session?.totpVerified || !req.sessionId || !jwt) return sendJson(res, 400, { error: 'registration refused' });
    try {
      const issued = registerBinding(ctx.db, req.sessionId, jwt);
      audit(ctx.db, { actorType: 'admin', actorId: req.session.admin.id, action: 'admin.session_bound', ip: req.ip });
      res.setHeader('Set-Cookie', boundCookie(issued));
      sendJson(res, 200, dbscConfig(issued.bindingId));
    } catch (err) {
      if (!(err instanceof DbscError)) throw err;
      log.warn('dbsc registration refused', { reason: err.message });
      sendJson(res, 400, { error: 'registration refused' });
    }
  });

  r.post('/dbsc/refresh', (req, res) => {
    const bindingId = String(req.headers['sec-secure-session-id'] ?? '').replace(/^"|"$/g, '');
    if (!ID_RE.test(bindingId)) return sendJson(res, 400, { error: 'unknown session' });
    let result;
    try {
      result = refreshBinding(ctx.db, bindingId, proofFromHeader(req.headers['secure-session-response']));
    } catch (err) {
      if (!(err instanceof DbscError)) throw err;
      log.warn('dbsc refresh refused', { reason: err.message });
      return sendJson(res, 401, { error: 'refresh refused' });
    }
    if (result.status === 'ended') return sendJson(res, 401, { continue: false });
    if (result.status === 'challenge') {
      res.setHeader('Secure-Session-Challenge', `"${result.challenge}";id="${result.bindingId}"`);
      return sendJson(res, 403, { error: 'challenge required' });
    }
    res.setHeader('Set-Cookie', boundCookie(result.issued));
    res.setHeader('Secure-Session-Challenge', `"${result.issued.nextChallenge}";id="${result.issued.bindingId}"`);
    sendJson(res, 200, dbscConfig(result.issued.bindingId));
  });

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
    const { sessionId } = createSession(ctx.db, admin, ctx.cfg.sessionTtlMs, sessionMeta(req));
    res.setHeader('Set-Cookie', sessionCookie(ctx, sessionId, Math.floor(ctx.cfg.sessionTtlMs / 1000)));
    if (hasSecondFactor(admin)) {
      audit(ctx.db, { actorType: 'admin', actorId: admin.id, action: 'admin.login_password', ip: req.ip });
      res.redirect(303, '/admin/totp');
      return;
    }
    // Signing in is itself a confirmation, for as long as a confirmation lasts.
    markConfirmed(ctx.db, sessionId, ctx.cfg.reauthWindowMs);
    recordLogin(ctx.db, admin.id);
    audit(ctx.db, { actorType: 'admin', actorId: admin.id, action: 'admin.login', ip: req.ip });
    res.redirect(303, (ctx.cfg.adminRequireTotp || admin.must_change_password) ? '/admin/security' : '/admin');
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
  /** What the second step offers this account: a passkey button, the code form, or both. */
  function secondStep(admin: Admin) {
    return { passkey: admin.passkeys > 0, totp: admin.totp_enabled, codes: admin.totp_enabled || remainingRecoveryCodes(ctx.db, admin.id) > 0 };
  }

  /** A complete sign-in: the new privileged cookie, a fresh confirmation, the login on record. */
  function signedIn(req: Request, res: Response, sessionId: string, factor: string): string {
    const { admin } = req.session!;
    markConfirmed(ctx.db, sessionId, ctx.cfg.reauthWindowMs);
    recordLogin(ctx.db, admin.id);
    audit(ctx.db, { actorType: 'admin', actorId: admin.id, action: 'admin.login', ip: req.ip, details: { second_factor: factor } });
    res.setHeader('Set-Cookie', sessionCookie(ctx, sessionId, Math.floor(ctx.cfg.sessionTtlMs / 1000)));
    return admin.must_change_password ? '/admin/security' : '/admin';
  }

  r.get('/totp', (req, res) => {
    if (req.session!.totpVerified) return res.redirect('/admin');
    const lockedUntil = totpLockedUntil(ctx.db, req.session!.admin.id);
    res.type('html').send(totpLoginPage(req.lang, { csrfToken: req.session!.csrfToken, lockedUntil: lockedUntil ?? undefined, ...secondStep(req.session!.admin) }));
  });

  r.post('/webauthn/login/options', (req, res) => {
    const { admin, totpVerified } = req.session!;
    if (totpVerified) return sendJson(res, 200, { redirect: '/admin' });
    const allow = credentialIds(ctx.db, admin.id);
    if (allow.length === 0) return sendJson(res, 400, { error: t(req.lang, 'passkey.failed') });
    const challenge = beginCeremony(ctx.db, req.sessionId!, 'login');
    sendJson(res, 200, { challenge, rpId: rp.rpId, allow, timeout: CEREMONY_TTL_MS });
  });

  r.post('/webauthn/login', loginFailures, (req, res) => {
    const session = req.session!;
    if (session.totpVerified) return sendJson(res, 200, { redirect: '/admin' });
    try {
      const fresh = verifyPasskeyLogin(ctx.db, req.sessionId!, session.admin, ctx.cfg.sessionTtlMs, field(req, 'credential_id'), {
        clientDataJSON: field(req, 'client_data'), authenticatorData: field(req, 'authenticator_data'), signature: field(req, 'signature'),
      }, rp);
      sendJson(res, 200, { redirect: signedIn(req, res, fresh.sessionId, 'passkey') });
    } catch (err) {
      if (!(err instanceof WebAuthnError)) throw err;
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.passkey_failed', ip: req.ip, details: { reason: err.message } });
      sendJson(res, 401, { error: t(req.lang, 'passkey.failed') });
    }
  });

  r.post('/totp', loginFailures, (req, res) => {
    const session = req.session!;
    if (session.totpVerified) return res.redirect(303, '/admin');
    const result = verifySessionTotp(ctx.db, req.sessionId!, field(req, 'code'), ctx.cfg.sessionTtlMs);
    if (result.status === 'ok') {
      // Fresh session id for the privileged session.
      res.redirect(303, signedIn(req, res, result.sessionId, result.factor));
      return;
    }
    if (result.status === 'locked') {
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_locked', ip: req.ip, details: { account_locked_until: result.accountLockedUntil } });
      clearSessionCookie(res);
      res.status(401).type('html').send(loginPage(req.lang, { error: t(req.lang, result.accountLockedUntil ? 'login.account_locked' : 'login.too_many_codes') }));
      return;
    }
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.totp_failed', ip: req.ip });
    res.status(401).type('html').send(totpLoginPage(req.lang, { csrfToken: session.csrfToken, error: t(req.lang, 'totp.invalid'), attemptsLeft: MAX_TOTP_ATTEMPTS - session.totpAttempts - 1, ...secondStep(session.admin) }));
  });

  // From here on the second factor must have been passed.
  r.use(requireAdmin({ verified: true }));

  // A complete session is offered device binding once, on the first page it loads
  // (not on the login response itself: after a passkey sign-in that is a fetch, and
  // the browser only acts on the header reliably for documents).
  r.use((req, res, next) => {
    if (ctx.cfg.deviceBoundSessions && ctx.cfg.cookieSecure && req.method === 'GET' && req.headers['sec-fetch-dest'] === 'document') {
      const challenge = offerBinding(ctx.db, req.sessionId!);
      if (challenge) res.setHeader('Secure-Session-Registration', `(ES256 RS256);path="/admin/dbsc/register";challenge="${challenge}"`);
    }
    next();
  });

  // ---- confirmation of sensitive actions -----------------------------------
  function renderConfirm(req: Request, res: Response, error?: string, status = 200): void {
    const { admin } = req.session!;
    const step = secondStep(admin);
    res.status(status).type('html').send(confirmPage({
      lang: req.lang, nav: adminNav(viewCtx(req)), csrfToken: req.session!.csrfToken,
      next: safeNext(req.query.next ?? field(req, 'next')), minutes: Math.round(ctx.cfg.reauthWindowMs / 60_000),
      passkey: step.passkey, codes: step.codes, password: !hasSecondFactor(admin), error,
    }));
  }

  function confirmed(req: Request, method: string): void {
    markConfirmed(ctx.db, req.sessionId!, ctx.cfg.reauthWindowMs);
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.confirmed', ip: req.ip, details: { method } });
  }

  r.get('/confirm', (req, res) => renderConfirm(req, res));

  r.post('/confirm/code', loginFailures, (req, res) => {
    const result = verifyConfirmCode(ctx.db, req.session!.admin.id, field(req, 'code'));
    if (result !== 'ok') {
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.confirm_failed', ip: req.ip, details: { method: 'code' } });
      return renderConfirm(req, res, t(req.lang, result === 'locked' ? 'confirm.locked' : 'confirm.invalid'), 401);
    }
    confirmed(req, 'code');
    res.redirect(303, safeNext(field(req, 'next')));
  });

  // Only an account without a second factor confirms with its password: anyone else
  // has something a cookie thief does not, and must use it.
  r.post('/confirm/password', loginFailures, (req, res) => {
    const { admin } = req.session!;
    if (hasSecondFactor(admin) || !authenticate(ctx.db, admin.username, field(req, 'password'))) {
      audit(ctx.db, { actorType: 'admin', actorId: admin.id, action: 'admin.confirm_failed', ip: req.ip, details: { method: 'password' } });
      return renderConfirm(req, res, t(req.lang, 'confirm.invalid'), 401);
    }
    confirmed(req, 'password');
    res.redirect(303, safeNext(field(req, 'next')));
  });

  r.post('/webauthn/confirm/options', (req, res) => {
    const allow = credentialIds(ctx.db, req.session!.admin.id);
    if (allow.length === 0) return sendJson(res, 400, { error: t(req.lang, 'passkey.failed') });
    sendJson(res, 200, { challenge: beginCeremony(ctx.db, req.sessionId!, 'confirm'), rpId: rp.rpId, allow, timeout: CEREMONY_TTL_MS });
  });

  r.post('/confirm/passkey', loginFailures, (req, res) => {
    try {
      verifyPasskeyConfirm(ctx.db, req.sessionId!, req.session!.admin.id, field(req, 'credential_id'), {
        clientDataJSON: field(req, 'client_data'), authenticatorData: field(req, 'authenticator_data'), signature: field(req, 'signature'),
      }, rp);
    } catch (err) {
      if (!(err instanceof WebAuthnError)) throw err;
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.confirm_failed', ip: req.ip, details: { method: 'passkey', reason: err.message } });
      return sendJson(res, 401, { error: t(req.lang, 'passkey.failed') });
    }
    confirmed(req, 'passkey');
    sendJson(res, 200, { redirect: safeNext(req.query.next) });
  });

  const backToSecurity = () => '/admin/security';

  // ---- security settings ------------------------------------------------
  // A passkey is added by a fetch, after which the page navigates: the outcome (and the
  // recovery codes, for a first factor) waits here for that one page view. In memory on
  // purpose — codes must not be written anywhere — and gone after a minute.
  const flashes = new Map<string, { ok?: string; recoveryCodes?: string[]; at?: number }>();
  function takeFlash(sessionId: string): Partial<SecurityPageData> | null {
    const f = flashes.get(sessionId);
    flashes.delete(sessionId);
    return f && Date.now() - (f.at ?? 0) < 60_000 ? { ok: f.ok, recoveryCodes: f.recoveryCodes } : null;
  }

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
      recoveryLeft: hasSecondFactor(session.admin) ? remainingRecoveryCodes(ctx.db, session.admin.id) : 0,
      passkeys: listPasskeys(ctx.db, session.admin.id), sessions: listSessions(ctx.db, session.admin.id, req.sessionId!),
      mustChangePassword: session.admin.must_change_password,
      enrol, ...extra,
    }));
  }

  r.get('/security', (req, res, next) => {
    const flash = takeFlash(req.sessionId!);
    renderSecurity(req, res, flash ?? {}).catch(next);
  });

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
    session.admin.must_change_password = false;
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.password_changed', ip: req.ip });
    renderSecurity(req, res, { ok: t(req.lang, 'security.password.changed') }).catch(next);
  });

  r.post('/security/totp/begin', requireConfirmed(backToSecurity), (req, res, next) => {
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
    if (ctx.cfg.adminRequireTotp && session.admin.passkeys === 0) {
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

  // ---- passkeys ----------------------------------------------------------------
  // Adding one is gated like enabling TOTP: whoever holds only a cookie must not be
  // able to give themselves a factor of their own.
  r.post('/security/passkeys/options', (req, res) => {
    const { admin, confirmedUntil } = req.session!;
    if (!confirmedUntil || confirmedUntil <= new Date().toISOString()) return sendJson(res, 200, { redirect: '/admin/confirm?next=%2Fadmin%2Fsecurity' });
    const exclude = credentialIds(ctx.db, admin.id);
    if (exclude.length >= MAX_PASSKEYS) return sendJson(res, 400, { error: t(req.lang, 'passkeys.limit', { n: MAX_PASSKEYS }) });
    const challenge = beginCeremony(ctx.db, req.sessionId!, 'register');
    sendJson(res, 200, {
      challenge, rpId: rp.rpId, rpName: ctx.cfg.brand.name, userId: Buffer.from(admin.id, 'utf8').toString('base64url'),
      userName: admin.username, exclude, timeout: CEREMONY_TTL_MS,
    });
  });

  r.post('/security/passkeys', requireConfirmed(backToSecurity), (req, res) => {
    const session = req.session!;
    const wasFirst = !hasSecondFactor(session.admin);
    try {
      const pk = registerPasskey(ctx.db, req.sessionId!, session.admin.id, field(req, 'name'), {
        clientDataJSON: field(req, 'client_data'), authenticatorData: field(req, 'authenticator_data'), publicKey: field(req, 'public_key'),
        algorithm: Number(field(req, 'algorithm')), credentialId: field(req, 'credential_id'),
      }, rp);
      // Other sessions did not prove this factor: end them, as when TOTP is enabled.
      destroyOtherSessions(ctx.db, session.admin.id, req.sessionId!);
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.passkey_added', ip: req.ip, details: { passkey: pk.id, name: pk.name } });
      // The first factor of the account comes with recovery codes, shown once.
      const codes = wasFirst ? regenerateRecoveryCodesConfirmed(ctx.db, session.admin.id) : null;
      for (const [k, v] of flashes) if (Date.now() - (v.at ?? 0) >= 60_000) flashes.delete(k);
      flashes.set(req.sessionId!, { ok: t(req.lang, 'passkeys.added', { name: pk.name }), recoveryCodes: codes ?? undefined, at: Date.now() });
      sendJson(res, 200, { redirect: '/admin/security' });
    } catch (err) {
      if (!(err instanceof WebAuthnError)) throw err;
      audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.passkey_failed', ip: req.ip, details: { context: 'register', reason: err.message } });
      const key = err.message === 'too many passkeys' ? 'passkeys.limit' : err.message === 'passkey already registered' ? 'passkeys.duplicate' : 'passkey.failed';
      sendJson(res, 400, { error: t(req.lang, key, { n: MAX_PASSKEYS }) });
    }
  });

  r.post('/security/passkeys/:id/remove', requireConfirmed(backToSecurity), (req, res, next) => {
    const session = req.session!;
    const id = validId(param(req, 'id'));
    if (ctx.cfg.adminRequireTotp && !session.admin.totp_enabled && session.admin.passkeys <= 1) {
      renderSecurity(req, res, { error: t(req.lang, 'passkeys.last_required') }, 400).catch(next);
      return;
    }
    const pk = id ? removePasskey(ctx.db, session.admin.id, id, req.sessionId!) : null;
    if (!pk) return sendError(req, res, 'error.not_found.title', 'error.not_found.title');
    session.admin.passkeys -= 1;
    audit(ctx.db, { actorType: 'admin', actorId: session.admin.id, action: 'admin.passkey_removed', ip: req.ip, details: { passkey: pk.id, name: pk.name } });
    renderSecurity(req, res, { ok: t(req.lang, 'passkeys.removed', { name: pk.name }) }).catch(next);
  });

  r.post('/security/recovery/regenerate', requireConfirmed(backToSecurity), (req, res, next) => {
    const codes = regenerateRecoveryCodesConfirmed(ctx.db, req.session!.admin.id);
    if (!codes) return renderSecurity(req, res, { error: t(req.lang, 'security.msg.invalid_code') }, 400).catch(next);
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.recovery_codes_regenerated', ip: req.ip });
    renderSecurity(req, res, { ok: t(req.lang, 'security.msg.regenerated'), recoveryCodes: codes }).catch(next);
  });

  // ---- sessions -------------------------------------------------------------------
  r.post('/security/sessions/revoke-others', (req, res, next) => {
    destroyOtherSessions(ctx.db, req.session!.admin.id, req.sessionId!);
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.sessions_revoked', ip: req.ip, details: { scope: 'others' } });
    renderSecurity(req, res, { ok: t(req.lang, 'sessions.revoked_others') }).catch(next);
  });

  r.post('/security/sessions/:id/revoke', (req, res, next) => {
    const id = param(req, 'id') ?? '';
    if (!/^s_[0-9a-zA-Z_-]{16,32}$/.test(id) || id === req.session!.publicId || !revokeSession(ctx.db, req.session!.admin.id, id)) {
      return sendError(req, res, 'error.not_found.title', 'error.not_found.title');
    }
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'admin.sessions_revoked', ip: req.ip, details: { session: id } });
    renderSecurity(req, res, { ok: t(req.lang, 'sessions.revoked') }).catch(next);
  });

  // With ADMIN_REQUIRE_TOTP, accounts without a second factor may only reach the
  // security page; so may an account still holding a password an administrator issued.
  r.use((req, res, next) => {
    const { admin } = req.session!;
    const missing = admin.must_change_password ? 'Password change required' : ctx.cfg.adminRequireTotp && !hasSecondFactor(admin) ? 'Second factor required' : null;
    if (missing) {
      if (req.method === 'GET') return res.redirect(302, '/admin/security');
      res.status(403).type('text/plain').send(missing);
      return;
    }
    next();
  });

  /**
   * The case, if this account may work on it. A case someone is not assigned to
   * answers exactly like one that does not exist: its id reveals nothing.
   */
  function caseFor(req: Request, id: string | null | undefined): Case | null {
    const c = id ? getCase(ctx.db, id) : null;
    return c && canAccessCase(ctx.db, req.session!.admin, c.id) ? c : null;
  }

  /** Accounts and the audit log are the administrators' alone. */
  const adminsOnly = (req: Request, res: Response, next: NextFunction): void => {
    if (req.session!.admin.role === 'admin') return next();
    sendError(req, res, 'error.forbidden.title', 'error.forbidden', 403);
  };

  // ---- cases -------------------------------------------------------------
  r.get('/', (req, res) => {
    res.type('html').send(casesPage(viewCtx(req), listCases(ctx.db, req.session!.admin)));
  });

  r.post('/cases', (req, res) => {
    try {
      const c = createCase(ctx.db, { name: field(req, 'name'), description: field(req, 'description') });
      // A user who opens a case works on it; an administrator sees it anyway.
      if (req.session!.admin.role !== 'admin') addCaseMember(ctx.db, c.id, req.session!.admin.id);
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'case.create', caseId: c.id, ip: req.ip, details: { name: c.name } });
      res.redirect(303, `/admin/cases/${c.id}`);
    } catch (err) {
      res.status(400).type('html').send(casesPage(viewCtx(req), listCases(ctx.db, req.session!.admin), { error: (err as Error).message }));
    }
  });

  function renderCase(req: Request, res: Response, caseId: string, extra: { error?: string; ok?: string; newLink?: { label: string; url: string } } = {}, status = 200): void {
    const c = caseFor(req, caseId);
    if (!c) return sendError(req, res, 'error.not_found.title', 'error.case_missing');
    res.status(status).type('html').send(casePage(viewCtx(req), {
      case: c, links: listLinksForCase(ctx.db, c.id), files: listFilesForCase(ctx.db, c.id), cfg: ctx.cfg,
      members: caseMembers(ctx.db, c.id), assignable: assignableUsers(ctx.db, c.id), ...extra,
    }));
  }

  r.get('/cases/:id', (req, res) => {
    const id = validId(param(req, 'id'));
    if (!id) return renderCase(req, res, '');
    renderCase(req, res, id);
  });

  r.post('/cases/:id', (req, res) => {
    const id = validId(param(req, 'id'));
    if (!id) return renderCase(req, res, '');
    if (!caseFor(req, id)) return renderCase(req, res, '');
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
    const id = validId(param(req, 'id'));
    if (!id) return renderCase(req, res, '');
    if (!caseFor(req, id)) return renderCase(req, res, '');
    const status = field(req, 'status') === 'closed' ? 'closed' : 'open';
    const c = updateCase(ctx.db, id, { status });
    if (!c) return renderCase(req, res, '');
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: status === 'closed' ? 'case.close' : 'case.reopen', caseId: id, ip: req.ip });
    res.redirect(303, `/admin/cases/${id}`);
  });

  // ---- links -------------------------------------------------------------
  // Issuing a link hands out a credential, so it needs a recent confirmation.
  const backToCase = (req: Request) => `/admin/cases/${validId(param(req, 'id')) ?? ''}`;
  r.post('/cases/:id/links', requireConfirmed(backToCase), (req, res) => {
    const id = validId(param(req, 'id'));
    if (!id) return renderCase(req, res, '');
    const c = caseFor(req, id);
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
    const id = validId(param(req, 'id'));
    const link = id ? getLink(ctx.db, id) : null;
    if (!link || !caseFor(req, link.case_id)) return sendError(req, res, 'error.not_found.title', 'error.link_missing');
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
  r.get('/files/:id/download', requireConfirmed(() => '/admin'), async (req, res) => {
    const id = validId(param(req, 'id'));
    const file = id ? getFile(ctx.db, id) : null;
    if (!file || file.status !== 'complete' || !caseFor(req, file.case_id)) return sendError(req, res, 'error.not_found.title', 'error.file_missing');
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
    const id = validId(param(req, 'id'));
    const file = id ? getFile(ctx.db, id) : null;
    if (!file || !caseFor(req, file.case_id)) return sendError(req, res, 'error.not_found.title', 'error.file_not_exist');
    if (markDeleted(ctx.db, file.id)) {
      await ctx.storage.delete(file.id);
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'file.delete', caseId: file.case_id, linkId: file.link_id, fileId: file.id, ip: req.ip, details: { name: file.original_name, size: file.size } });
    }
    res.redirect(303, `/admin/cases/${file.case_id}`);
  });

  // ---- case assignments ---------------------------------------------------
  // Anyone working on a case may bring a colleague in or take one off it; administrators
  // see every case and are never members.
  r.post('/cases/:id/members', (req, res) => {
    const id = validId(param(req, 'id'));
    const c = caseFor(req, id);
    if (!c) return renderCase(req, res, '');
    const user = getUser(ctx.db, validId(field(req, 'user_id')) ?? '');
    if (!user || user.role !== 'user' || user.disabled_at) return renderCase(req, res, c.id, { error: t(req.lang, 'users.missing') }, 400);
    if (addCaseMember(ctx.db, c.id, user.id)) {
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'case.member_add', caseId: c.id, ip: req.ip, details: { user: user.id, username: user.username } });
    }
    renderCase(req, res, c.id, { ok: t(req.lang, 'members.added', { username: user.username }) });
  });

  r.post('/cases/:id/members/:uid/remove', (req, res) => {
    const id = validId(param(req, 'id'));
    const c = caseFor(req, id);
    if (!c) return renderCase(req, res, '');
    const user = getUser(ctx.db, validId(param(req, 'uid')) ?? '');
    // Taking yourself off would lock you out of the page you are on; someone else does that.
    if (user && user.id === req.session!.admin.id) return renderCase(req, res, c.id, { error: t(req.lang, 'members.not_self') }, 400);
    if (!user || !removeCaseMember(ctx.db, c.id, user.id)) return renderCase(req, res, c.id, { error: t(req.lang, 'users.missing') }, 404);
    audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'case.member_remove', caseId: c.id, ip: req.ip, details: { user: user.id, username: user.username } });
    renderCase(req, res, c.id, { ok: t(req.lang, 'members.removed', { username: user.username }) });
  });

  // ---- accounts ------------------------------------------------------------
  function renderUsers(req: Request, res: Response, extra: Omit<UsersPageData, 'users'> = {}, status = 200): void {
    res.status(status).type('html').send(usersPage(viewCtx(req), { users: listUsers(ctx.db), ...extra }));
  }

  function userErrorText(req: Request, err: unknown): string {
    if (err instanceof UserError) return t(req.lang, err.key, err.params);
    throw err;
  }

  r.get('/users', adminsOnly, (req, res) => renderUsers(req, res));

  const backToUsers = () => '/admin/users';
  r.post('/users', adminsOnly, requireConfirmed(backToUsers), (req, res) => {
    const role = field(req, 'role');
    try {
      const { user, password } = createUser(ctx.db, { username: field(req, 'username'), role: isRole(role) ? role : 'user' });
      audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action: 'user.create', ip: req.ip, details: { user: user.id, username: user.username, role: user.role } });
      // The password is shown once, in this response, and never stored in clear.
      renderUsers(req, res, { issued: { username: user.username, password, reset: false } });
    } catch (err) {
      renderUsers(req, res, { error: userErrorText(req, err) }, 400);
    }
  });

  /** One account action: runs `fn`, audits it, and redraws the list with the outcome. */
  function userAction(path: string, action: string, fn: (req: Request, actorId: string, id: string) => { user: UserSummary; ok: string; details?: Record<string, unknown>; issued?: UsersPageData['issued'] }) {
    r.post(`/users/:id/${path}`, adminsOnly, requireConfirmed(backToUsers), (req, res) => {
      const id = validId(param(req, 'id'));
      if (!id) return renderUsers(req, res, { error: t(req.lang, 'users.missing') }, 404);
      try {
        const done = fn(req, req.session!.admin.id, id);
        audit(ctx.db, { actorType: 'admin', actorId: req.session!.admin.id, action, ip: req.ip, details: { user: done.user.id, username: done.user.username, ...done.details } });
        renderUsers(req, res, { ok: done.ok, issued: done.issued });
      } catch (err) {
        renderUsers(req, res, { error: userErrorText(req, err) }, 400);
      }
    });
  }

  userAction('role', 'user.role', (req, actor, id) => {
    const role = field(req, 'role');
    if (!isRole(role)) throw new UserError('users.invalid_role');
    const user = setUserRole(ctx.db, actor, id, role);
    return { user, ok: t(req.lang, 'users.role_changed', { username: user.username, role: t(req.lang, role === 'admin' ? 'users.role.admin' : 'users.role.user') }), details: { role } };
  });
  userAction('password', 'user.password_reset', (req, actor, id) => {
    const { user, password } = resetUserPassword(ctx.db, actor, id);
    return { user, ok: t(req.lang, 'users.password_reset', { username: user.username }), issued: { username: user.username, password, reset: true } };
  });
  userAction('totp', 'user.totp_reset', (req, actor, id) => {
    const user = resetUserTotp(ctx.db, actor, id);
    return { user, ok: t(req.lang, 'users.totp_reset', { username: user.username }) };
  });
  userAction('disable', 'user.disable', (req, actor, id) => {
    const user = setUserDisabled(ctx.db, actor, id, true);
    return { user, ok: t(req.lang, 'users.disabled', { username: user.username }) };
  });
  userAction('enable', 'user.enable', (req, actor, id) => {
    const user = setUserDisabled(ctx.db, actor, id, false);
    return { user, ok: t(req.lang, 'users.enabled', { username: user.username }) };
  });
  userAction('delete', 'user.delete', (req, actor, id) => {
    const user = deleteUser(ctx.db, actor, id);
    return { user, ok: t(req.lang, 'users.deleted', { username: user.username }) };
  });

  // ---- audit -------------------------------------------------------------
  r.get('/audit', adminsOnly, (req, res) => {
    res.type('html').send(auditPage(viewCtx(req), listAudit(ctx.db, 300)));
  });

  return r;
}
