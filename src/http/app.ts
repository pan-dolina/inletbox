import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { log } from '../log.js';
import { adminRouter } from './admin.js';
import { brandRouter } from './brand.js';
import { setAppVersion, setAssetVersion, setBrand } from './html.js';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import type { AppContext } from './context.js';
import { publicRouter } from './public.js';
import { langCookie, languageMiddleware, requestLogger, securityHeaders, sessionMiddleware } from './middleware.js';
import { isLang, t } from '../i18n.js';
import { errorPage, homePage } from './views/admin.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

export function createApp(ctx: AppContext): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.cfg.trustProxy);
  app.set('etag', false);

  app.use(securityHeaders());
  app.use(requestLogger());
  app.use(languageMiddleware());

  setBrand(ctx.cfg.brand);
  // package.json ships in the runtime image, so this is the version that is actually running.
  try {
    setAppVersion((JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as { version?: string }).version ?? '0.0.0');
  } catch { /* keep the default: a missing package.json must not stop the server */ }
  const h = createHash('sha256');
  for (const f of ['public/style.css', 'public/upload.js', 'public/admin.js', 'public/inletbox-logo.png', 'node_modules/tus-js-client/dist/tus.min.js']) {
    try { h.update(fs.readFileSync(path.join(ROOT, f))); } catch { /* missing asset: version still changes when others do */ }
  }
  h.update(JSON.stringify(ctx.cfg.brand));
  setAssetVersion(h.digest('hex').slice(0, 12));
  app.use('/brand', brandRouter(ctx.cfg.brand));

  // Static assets: our own CSS/JS, the tus browser client from node_modules, and the CLI helper script.
  // Anything referenced through asset() carries a content hash in ?v=, so it can be frozen for a
  // year — a changed file gets a new URL. The same files are also reachable without the hash (the
  // upload script is linked verbatim so people can curl it), and those must keep revalidating or
  // an upgrade never reaches anyone. express.static would override this, hence cacheControl: false.
  app.use('/static', (req, res, next) => {
    const hashed = typeof req.query.v === 'string' && req.query.v.length > 0;
    res.setHeader('Cache-Control', hashed ? 'public, max-age=31536000, immutable' : 'public, max-age=3600');
    next();
  });
  const staticOpts = { index: false, dotfiles: 'ignore' as const, cacheControl: false, etag: true };
  app.use('/static/vendor/tus.min.js', express.static(path.join(ROOT, 'node_modules/tus-js-client/dist/tus.min.js'), staticOpts));
  app.use('/static/inletbox-upload.sh', express.static(path.join(ROOT, 'scripts/inletbox-upload.sh'), { ...staticOpts, setHeaders: (res) => res.type('text/plain') }));
  app.use('/static', express.static(path.join(ROOT, 'public'), staticOpts));

  app.get('/healthz', (_req, res) => { res.json({ ok: true }); });

  // Footer language switcher: remembers the choice in a cookie and returns to the page (same-site paths only).
  app.get('/lang/:lang', (req, res) => {
    const lang = String(req.params.lang);
    if (!isLang(lang)) { res.status(404).type('text/plain').send('Unknown language'); return; }
    const next = typeof req.query.next === 'string' ? req.query.next : '/';
    const safeNext = next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
    res.setHeader('Set-Cookie', langCookie(ctx, lang));
    res.redirect(303, safeNext);
  });
  app.get('/', (req, res) => { res.type('html').send(homePage(req.lang)); });

  app.use(sessionMiddleware(ctx));
  app.use('/admin', adminRouter(ctx));
  app.use(publicRouter(ctx));

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    const homeHref = req.path.startsWith('/admin') ? '/admin' : '/';
    const e = errorPage(req.lang, t(req.lang, 'error.not_found.title'), t(req.lang, 'error.page_missing'), 404, req.originalUrl, homeHref);
    res.status(e.status).type('html').send(e.body);
  });

  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    const e = err as { status?: number; statusCode?: number; message?: string; type?: string };
    const status = e.status ?? e.statusCode ?? 500;
    if (status >= 500) log.error('unhandled error', { method: req.method, path: req.path, err: err as Error });
    if (res.headersSent) return;
    if (req.path.startsWith('/api/')) {
      res.status(status).json({ error: status >= 500 ? 'internal' : 'bad_request', message: status >= 500 ? 'Internal error' : e.message });
      return;
    }
    const lang = req.lang ?? 'en';
    const homeHref = req.path.startsWith('/admin') ? '/admin' : '/';
    const page = errorPage(lang, t(lang, status >= 500 ? 'error.server.title' : 'error.bad_request.title'), status >= 500 ? t(lang, 'error.server') : (e.message ?? 'Bad request'), status, req.originalUrl, homeHref);
    res.status(page.status).type('html').send(page.body);
  });

  return app;
}
