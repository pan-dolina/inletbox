import type { NextFunction, Request, RequestHandler, Response } from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { safeEqual } from '../crypto.js';
import { isLang, LANG_COOKIE, negotiateLang, t, type MessageKey } from '../i18n.js';
import { log, redact } from '../log.js';
import { getSession } from '../services/auth.js';
import { resolveToken, touchLink, type LinkState } from '../services/links.js';
import { SESSION_COOKIE, type AppContext } from './context.js';

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

export function securityHeaders(): RequestHandler {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'none'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'font-src': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'none'"],
        'object-src': ["'none'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
    xFrameOptions: { action: 'deny' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    strictTransportSecurity: false, // HSTS belongs to the TLS-terminating reverse proxy
  });
}

// ---------------------------------------------------------------------------
// Request logging (never logs headers, bodies, query strings or link tokens)
// ---------------------------------------------------------------------------

export function requestLogger(): RequestHandler {
  return (req, res, next) => {
    const started = process.hrtime.bigint();
    const ip = req.ip; // resolve now: the socket may be gone by the time the response finishes
    const method = req.method;
    const path = redact(req.path);
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      log.info('request', { method, path, status: res.statusCode, ms: Math.round(ms), ip });
    });
    next();
  };
}

// ---------------------------------------------------------------------------
// Language: explicit cookie (set by the footer switcher) beats Accept-Language; English is the default.
// ---------------------------------------------------------------------------

export function languageMiddleware(): RequestHandler {
  return (req, _res, next) => {
    const fromCookie = parseCookies(req.headers.cookie)[LANG_COOKIE];
    req.lang = isLang(fromCookie) ? fromCookie : negotiateLang(req.headers['accept-language']);
    next();
  };
}

export function langCookie(ctx: AppContext, lang: string): string {
  const parts = [`${LANG_COOKIE}=${lang}`, 'Path=/', 'SameSite=Lax', `Max-Age=${365 * 24 * 3600}`];
  if (ctx.cfg.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

// ---------------------------------------------------------------------------
// Cookies & admin sessions
// ---------------------------------------------------------------------------

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    try { out[k] = decodeURIComponent(v); } catch { /* malformed cookie value: ignore it */ }
  }
  return out;
}

export function sessionCookie(ctx: AppContext, value: string, maxAgeSec: number): string {
  const parts = [`${SESSION_COOKIE}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (ctx.cfg.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

export function sessionMiddleware(ctx: AppContext): RequestHandler {
  return (req, _res, next) => {
    const sid = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (sid) {
      const session = getSession(ctx.db, sid);
      if (session) {
        req.session = session;
        req.sessionId = sid;
      }
    }
    next();
  };
}

/** A session must exist. With `verified: true` the second factor must also have been passed. */
export function requireAdmin(opts: { verified: boolean } = { verified: true }): RequestHandler {
  return (req, res, next) => {
    if (req.session && (!opts.verified || req.session.totpVerified)) return next();
    const target = req.session ? '/admin/totp' : '/admin/login';
    if (req.method === 'GET' || req.method === 'HEAD') {
      res.redirect(302, target);
      return;
    }
    res.status(401).type('text/plain').send('Unauthorized');
  };
}

/**
 * CSRF protection for cookie-authenticated admin routes:
 *  - SameSite=Lax cookies already block cross-site POSTs in modern browsers;
 *  - additionally, Sec-Fetch-Site (when present) must be same-origin/none and a
 *    concrete Origin must match this site. Note that with Referrer-Policy:
 *    no-referrer browsers send "Origin: null" on same-origin form posts, so a
 *    null Origin is treated as unknown rather than foreign;
 *  - and every form carries a per-session synchroniser token, which is the
 *    check that actually decides.
 */
export function csrfProtect(ctx: AppContext): RequestHandler {
  const expectedOrigin = new URL(ctx.cfg.publicUrl).origin;
  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const fetchSite = req.headers['sec-fetch-site'];
    const origin = req.headers.origin;
    const reject = (reason: string) => {
      log.warn('csrf: request rejected', { reason, origin, fetchSite, host: req.headers.host, path: req.path });
      res.status(403).type('text/plain').send(t(req.lang, 'error.cross_site'));
    };
    if (fetchSite && !['same-origin', 'none'].includes(String(fetchSite))) return reject('sec-fetch-site');
    if (origin && origin !== 'null' && origin !== expectedOrigin && origin !== `${req.protocol}://${req.headers.host}`) return reject('origin');
    const token = (req.body as Record<string, unknown> | undefined)?._csrf;
    if (!req.session || typeof token !== 'string' || !safeEqual(token, req.session.csrfToken)) {
      res.status(403).type('text/plain').send(t(req.lang, 'error.csrf'));
      return;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

export function loginLimiter(ctx: AppContext): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60_000,
    limit: ctx.cfg.loginRateLimitPer15Min,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: 'Too many login attempts. Try again later.',
  });
}

/** Counts only failed (401/403/404) token lookups, so brute-forcing link tokens is throttled. */
export function tokenFailureLimiter(ctx: AppContext): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60_000,
    limit: ctx.cfg.tokenFailureRateLimitPer15Min,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    // Only unknown/unauthenticated tokens count; limit and state errors (403/413) are legitimate uploader mistakes.
    requestWasSuccessful: (_req, res) => res.statusCode !== 401 && res.statusCode !== 404,
    message: { error: 'rate_limited', message: 'Too many failed attempts. Try again later.' },
  });
}

export function publicLimiter(ctx: AppContext): RequestHandler {
  return rateLimit({
    windowMs: 60_000,
    limit: ctx.cfg.publicRateLimitPerMinute,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'rate_limited', message: 'Too many requests. Slow down.' },
  });
}

// ---------------------------------------------------------------------------
// Upload-link authentication
// ---------------------------------------------------------------------------

export function extractBearer(req: Request): string | null {
  const h = req.headers.authorization;
  if (!h) return null;
  const m = /^Bearer\s+([A-Za-z0-9_-]+)\s*$/i.exec(h);
  return m ? m[1]! : null;
}

export const LINK_STATE_MESSAGES: Record<Exclude<LinkState, 'active'>, { status: number; code: string; message: MessageKey }> = {
  expired: { status: 403, code: 'link_expired', message: 'link.expired' },
  revoked: { status: 403, code: 'link_revoked', message: 'link.revoked' },
  case_closed: { status: 403, code: 'case_closed', message: 'link.case_closed' },
};

/**
 * Authenticates API requests with `Authorization: Bearer <token>`.
 * Tokens are never accepted from query strings (they would end up in logs).
 */
export function requireLinkBearer(ctx: AppContext): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = extractBearer(req);
    if (!token) {
      res.status(401).json({ error: 'missing_token', message: 'Authorization: Bearer <token> header required' });
      return;
    }
    const resolved = resolveToken(ctx.db, token);
    if (!resolved) {
      res.status(404).json({ error: 'invalid_token', message: 'Unknown upload link' });
      return;
    }
    if (resolved.state !== 'active') {
      const m = LINK_STATE_MESSAGES[resolved.state];
      res.status(m.status).json({ error: m.code, message: t(req.lang, m.message) });
      return;
    }
    touchLink(ctx.db, resolved.link.id);
    req.uploadLink = resolved;
    req.uploadToken = token;
    next();
  };
}
