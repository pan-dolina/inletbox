import http from 'node:http';
import { loadConfig } from './config.js';
import { migrate, openDatabase } from './db.js';
import { createApp } from './http/app.js';
import type { AppContext } from './http/context.js';
import { log, setLogLevel } from './log.js';
import { countAdmins } from './services/auth.js';
import { runCleanup } from './services/cleanup.js';
import { createStorage } from './storage/index.js';

export interface RunningServer { server: http.Server; ctx: AppContext; close: () => Promise<void> }

export async function startServer(env: NodeJS.ProcessEnv = process.env, listen: { host?: string; port?: number } = {}): Promise<RunningServer> {
  // Everything this process writes (database, uploads, tus sidecars) is private to its user.
  process.umask(0o077);
  const cfg = loadConfig(env);
  setLogLevel(cfg.logLevel);
  const db = openDatabase(cfg.databasePath);
  migrate(db);
  const storage = createStorage(cfg);
  await storage.healthCheck();
  const tusStore = storage.createTusStore({ expirationMs: cfg.incompleteUploadTtlMs });
  const ctx: AppContext = { cfg, db, storage, tusStore };

  const app = createApp(ctx);
  const server = http.createServer(app);
  // Requests carrying "Expect: 100-continue" (curl does this for PUT bodies) are routed through the app too;
  // handlers call res.writeContinue() once they accept the upload.
  server.on('checkContinue', (req, res) => app(req, res));
  // Large uploads may legitimately take hours: disable the per-request timeout
  // (Node defaults to 5 minutes). Header parsing and socket *inactivity* stay
  // bounded (slowloris): an active upload keeps the socket busy, a trickling
  // login form does not.
  server.requestTimeout = 0;
  server.headersTimeout = 60_000;
  server.keepAliveTimeout = 75_000;
  server.timeout = 300_000;

  let cleanupTimer: NodeJS.Timeout | undefined;
  let cleanupRunning = false;
  const cleanupTick = async () => {
    if (cleanupRunning) return;
    cleanupRunning = true;
    try { await runCleanup(ctx); } catch (err) { log.error('cleanup failed', { err: err as Error }); } finally { cleanupRunning = false; }
  };

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(listen.port ?? cfg.port, listen.host ?? cfg.host, () => { server.off('error', reject); resolve(); });
  });
  const addr = server.address();
  log.info('inletbox listening', { address: typeof addr === 'string' ? addr : `${addr?.address}:${addr?.port}`, storage: cfg.storage, publicUrl: cfg.publicUrl });
  if (countAdmins(db) === 0) log.warn('no admin account exists yet: run `node dist/cli.js create-admin <username>`');

  if (cfg.cleanupIntervalMs > 0) {
    cleanupTimer = setInterval(cleanupTick, cfg.cleanupIntervalMs);
    cleanupTimer.unref();
    setTimeout(cleanupTick, 5_000).unref();
  }

  const close = async () => {
    if (cleanupTimer) clearInterval(cleanupTimer);
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
    db.close();
  };
  return { server, ctx, close };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  startServer().then((running) => {
    const shutdown = (signal: string) => {
      log.info('shutting down', { signal });
      running.close().then(() => process.exit(0)).catch(() => process.exit(1));
      setTimeout(() => process.exit(1), 15_000).unref();
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }).catch((err) => {
    log.error('startup failed', { err });
    process.exit(1);
  });
}
