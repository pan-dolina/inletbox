import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { log } from '../log.js';
import { adminRouter } from './admin.js';
import type { AppContext } from './context.js';
import { publicRouter } from './public.js';
import { requestLogger, securityHeaders, sessionMiddleware } from './middleware.js';
import { errorPage } from './views/admin.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

export function createApp(ctx: AppContext): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.cfg.trustProxy);
  app.set('etag', false);

  app.use(securityHeaders());
  app.use(requestLogger());

  // Static assets: our own CSS/JS, the tus browser client from node_modules, and the CLI helper script.
  const staticOpts = { index: false, dotfiles: 'ignore' as const, maxAge: '1h', etag: true };
  app.use('/static/vendor/tus.min.js', express.static(path.join(ROOT, 'node_modules/tus-js-client/dist/tus.min.js'), staticOpts));
  app.use('/static/inletbox-upload.sh', express.static(path.join(ROOT, 'scripts/inletbox-upload.sh'), { ...staticOpts, setHeaders: (res) => res.type('text/plain') }));
  app.use('/static', express.static(path.join(ROOT, 'public'), staticOpts));

  app.get('/healthz', (_req, res) => { res.json({ ok: true }); });
  app.get('/', (_req, res) => { res.redirect('/admin'); });

  app.use(sessionMiddleware(ctx));
  app.use('/admin', adminRouter(ctx));
  app.use(publicRouter(ctx));

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    const e = errorPage('Nie znaleziono', 'Strona nie istnieje.');
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
    const page = errorPage(status >= 500 ? 'Błąd serwera' : 'Nieprawidłowe żądanie', status >= 500 ? 'Wystąpił nieoczekiwany błąd.' : (e.message ?? 'Bad request'), status);
    res.status(page.status).type('html').send(page.body);
  });

  return app;
}
