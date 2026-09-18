import type { Config } from '../config.js';
import { LocalStorage } from './local.js';
import { S3Storage } from './s3.js';
import type { StorageBackend } from './types.js';

export * from './types.js';

export function createStorage(cfg: Config): StorageBackend {
  if (cfg.storage === 's3') return new S3Storage(cfg.s3);
  return new LocalStorage(cfg.localStorageDir);
}
