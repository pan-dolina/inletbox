import type { Config } from './config.js';

type Level = Config['logLevel'];
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let current: Level = 'info';
export function setLogLevel(level: Level): void { current = level; }

/**
 * Removes secrets from anything that could end up in a log line:
 * upload-link tokens in paths (/u/<token>) and token-like query params.
 */
export function redact(value: string): string {
  return value
    .replace(/\/u\/[^/?#\s]+/g, '/u/[redacted]')
    .replace(/(\/api\/upload\/)[^?#\s]+/g, '$1[filename]')
    .replace(/([?&](?:token|access_token|sig)=)[^&#\s]*/gi, '$1[redacted]');
}

function emit(level: Level, msg: string, fields?: Record<string, unknown>): void {
  if (ORDER[level] < ORDER[current]) return;
  const line: Record<string, unknown> = { ts: new Date().toISOString(), level, msg };
  if (fields) {
    for (const [k, v] of Object.entries(fields)) {
      if (v === undefined) continue;
      if (k === 'authorization' || k === 'cookie' || k === 'token' || k === 'password') continue;
      line[k] = typeof v === 'string' ? redact(v) : v instanceof Error ? { name: v.name, message: redact(v.message) } : v;
    }
  }
  const out = JSON.stringify(line);
  if (level === 'error' || level === 'warn') process.stderr.write(out + '\n');
  else process.stdout.write(out + '\n');
}

export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => emit('debug', msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => emit('info', msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => emit('warn', msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => emit('error', msg, fields),
};
