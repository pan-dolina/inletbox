import path from 'node:path';

export type StorageBackendKind = 'local' | 's3';

export interface Config {
  publicUrl: string;
  host: string;
  port: number;
  trustProxy: boolean | number | string;
  dataDir: string;
  databasePath: string;
  storage: StorageBackendKind;
  localStorageDir: string;
  s3: {
    endpoint?: string;
    region: string;
    bucket: string;
    accessKeyId?: string;
    secretAccessKey?: string;
    forcePathStyle: boolean;
    partSize: number;
  };
  maxFileBytes: number;
  uploadChunkBytes: number;
  incompleteUploadTtlMs: number;
  cleanupIntervalMs: number;
  sessionTtlMs: number;
  /** When true, admins without TOTP must enrol before using the panel. */
  adminRequireTotp: boolean;
  cookieSecure: boolean;
  loginRateLimitPer15Min: number;
  tokenFailureRateLimitPer15Min: number;
  publicRateLimitPerMinute: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

const SIZE_UNITS: Record<string, number> = {
  b: 1,
  k: 1024, kb: 1024, kib: 1024,
  m: 1024 ** 2, mb: 1024 ** 2, mib: 1024 ** 2,
  g: 1024 ** 3, gb: 1024 ** 3, gib: 1024 ** 3,
  t: 1024 ** 4, tb: 1024 ** 4, tib: 1024 ** 4,
};

/** Parses "10GB", "512MiB", "1048576" into bytes. Binary units (1 MB = 1 MiB). */
export function parseSize(input: string, name = 'size'): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$/.exec(input);
  if (!m) throw new Error(`Invalid ${name}: "${input}"`);
  const unit = (m[2] ?? '').toLowerCase();
  const mult = unit === '' ? 1 : SIZE_UNITS[unit];
  if (mult === undefined) throw new Error(`Invalid unit in ${name}: "${input}"`);
  const value = Math.floor(Number(m[1]) * mult);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${name}: "${input}"`);
  return value;
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

function num(env: NodeJS.ProcessEnv, key: string, def: number): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) throw new Error(`Invalid ${key}: "${raw}"`);
  return n;
}

function bool(env: NodeJS.ProcessEnv, key: string, def: boolean): boolean {
  const raw = env[key];
  if (raw === undefined || raw === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const publicUrl = (env.PUBLIC_URL ?? 'http://localhost:3000').replace(/\/+$/, '');
  let parsed: URL;
  try { parsed = new URL(publicUrl); } catch { throw new Error(`PUBLIC_URL is not a valid URL: "${publicUrl}"`); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('PUBLIC_URL must start with http:// or https://');

  const dataDir = path.resolve(env.DATA_DIR ?? './data');
  const storage = (env.STORAGE_BACKEND ?? 'local') as StorageBackendKind;
  if (!['local', 's3'].includes(storage)) throw new Error(`STORAGE_BACKEND must be "local" or "s3", got "${storage}"`);

  const trustRaw = env.TRUST_PROXY ?? 'false';
  let trustProxy: boolean | number | string = false;
  if (['true', '1', 'yes'].includes(trustRaw.toLowerCase())) trustProxy = trustRaw === '1' ? 1 : true;
  else if (/^\d+$/.test(trustRaw)) trustProxy = Number(trustRaw);
  else if (trustRaw && !['false', '0', 'no', ''].includes(trustRaw.toLowerCase())) trustProxy = trustRaw;

  const s3PartSize = parseSize(env.S3_PART_SIZE ?? '8MB', 'S3_PART_SIZE');
  if (storage === 's3') {
    if (!env.S3_BUCKET) throw new Error('S3_BUCKET is required when STORAGE_BACKEND=s3');
    if (s3PartSize < 5 * 1024 * 1024) throw new Error('S3_PART_SIZE must be at least 5MB');
  }

  const maxFileBytes = parseSize(env.MAX_FILE_SIZE ?? '10GB', 'MAX_FILE_SIZE');
  if (maxFileBytes < 1) throw new Error('MAX_FILE_SIZE must be positive');
  const uploadChunkBytes = parseSize(env.UPLOAD_CHUNK_SIZE ?? '32MB', 'UPLOAD_CHUNK_SIZE');
  if (uploadChunkBytes < 1024 * 1024) throw new Error('UPLOAD_CHUNK_SIZE must be at least 1MB');

  const logLevel = (env.LOG_LEVEL ?? 'info') as Config['logLevel'];
  if (!['debug', 'info', 'warn', 'error'].includes(logLevel)) throw new Error(`Invalid LOG_LEVEL: ${logLevel}`);

  return {
    publicUrl,
    host: env.HOST ?? '0.0.0.0',
    port: num(env, 'PORT', 3000),
    trustProxy,
    dataDir,
    databasePath: env.DATABASE_PATH ? path.resolve(env.DATABASE_PATH) : path.join(dataDir, 'inletbox.sqlite'),
    storage,
    localStorageDir: env.LOCAL_STORAGE_DIR ? path.resolve(env.LOCAL_STORAGE_DIR) : path.join(dataDir, 'files'),
    s3: {
      endpoint: env.S3_ENDPOINT || undefined,
      region: env.S3_REGION || 'us-east-1',
      bucket: env.S3_BUCKET ?? '',
      accessKeyId: env.S3_ACCESS_KEY_ID || undefined,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY || undefined,
      forcePathStyle: bool(env, 'S3_FORCE_PATH_STYLE', true),
      partSize: s3PartSize,
    },
    maxFileBytes,
    uploadChunkBytes,
    incompleteUploadTtlMs: num(env, 'INCOMPLETE_UPLOAD_TTL_HOURS', 24) * 3600_000,
    cleanupIntervalMs: num(env, 'CLEANUP_INTERVAL_MINUTES', 30) * 60_000,
    sessionTtlMs: num(env, 'SESSION_TTL_HOURS', 12) * 3600_000,
    adminRequireTotp: bool(env, 'ADMIN_REQUIRE_TOTP', false),
    cookieSecure: bool(env, 'COOKIE_SECURE', parsed.protocol === 'https:'),
    loginRateLimitPer15Min: num(env, 'LOGIN_RATE_LIMIT_PER_15MIN', 10),
    tokenFailureRateLimitPer15Min: num(env, 'TOKEN_FAILURE_RATE_LIMIT_PER_15MIN', 30),
    publicRateLimitPerMinute: num(env, 'PUBLIC_RATE_LIMIT_PER_MINUTE', 600),
    logLevel,
  };
}
