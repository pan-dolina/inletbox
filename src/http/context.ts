import type { DataStore } from '@tus/utils';
import type { Config } from '../config.js';
import type { Db } from '../db.js';
import type { StorageBackend } from '../storage/index.js';
import type { Session } from '../services/auth.js';
import type { ResolvedLink } from '../services/links.js';

export interface AppContext {
  cfg: Config;
  db: Db;
  storage: StorageBackend;
  tusStore: DataStore;
}

// Request-scoped data attached by middleware.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: Session;
      sessionId?: string;
      uploadLink?: ResolvedLink;
      /** Token as presented by the client; used only to build curl examples on the upload page. */
      uploadToken?: string;
    }
  }
}

export const SESSION_COOKIE = 'inletbox_sid';
