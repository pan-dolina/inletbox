/**
 * inletbox CLI
 *   create-admin <username> [--password-stdin]   create the first/next admin (password prompted, hidden)
 *   reset-password <username> [--password-stdin]
 *   migrate                                       apply pending migrations
 *   cleanup [--ttl-hours N]                       run the housekeeping job once
 *   disable-totp <username>                       remove the second factor (lost authenticator)
 */
import readline from 'node:readline';
import { loadConfig } from './config.js';
import { migrate, openDatabase } from './db.js';
import { log, setLogLevel } from './log.js';
import { countAdmins, createAdmin, findAdminByUsername, forceDisableTotp, MIN_PASSWORD_LENGTH, setAdminPassword } from './services/auth.js';
import { runCleanup } from './services/cleanup.js';
import { createStorage } from './storage/index.js';

async function readPassword(prompt: string, fromStdin: boolean): Promise<string> {
  if (fromStdin) {
    let data = '';
    for await (const chunk of process.stdin) data += chunk;
    return data.replace(/\r?\n$/, '');
  }
  const ask = (label: string = prompt): Promise<string> => new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    let value = '';
    process.stderr.write(label);
    const onKey = (_c: string, key: readline.Key) => {
      if (key.name === 'return' || key.name === 'enter') {
        process.stdin.off('keypress', onKey);
        process.stderr.write('\n');
        rl.close();
        resolve(value);
      } else if (key.name === 'backspace') {
        value = value.slice(0, -1);
      } else if (key.ctrl && key.name === 'c') {
        process.exit(130);
      } else if (typeof key.sequence === 'string' && !key.ctrl && !key.meta) {
        value += key.sequence;
      }
    };
    readline.emitKeypressEvents(process.stdin, rl);
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.on('keypress', onKey);
  });
  const p1 = await ask();
  const p2 = await ask('Repeat password: ');
  if (process.stdin.isTTY) process.stdin.setRawMode(false);
  if (p1 !== p2) throw new Error('Passwords do not match');
  return p1;
}

async function main(argv: string[]): Promise<void> {
  const cfg = loadConfig();
  setLogLevel('warn');
  const [cmd, ...rest] = argv;
  const db = openDatabase(cfg.databasePath);
  migrate(db);

  switch (cmd) {
    case 'migrate': {
      console.log('Migrations are up to date.');
      break;
    }
    case 'create-admin':
    case 'reset-password': {
      const username = rest.find((a) => !a.startsWith('--'));
      if (!username) throw new Error(`usage: ${cmd} <username> [--password-stdin]`);
      const fromStdin = rest.includes('--password-stdin');
      const password = await readPassword(`Password for ${username} (min ${MIN_PASSWORD_LENGTH} chars): `, fromStdin);
      if (cmd === 'create-admin') {
        const admin = createAdmin(db, username, password);
        console.log(`Admin "${admin.username}" created (${countAdmins(db)} admin(s) total).`);
      } else {
        if (!setAdminPassword(db, username, password)) throw new Error(`No admin named "${username}"`);
        console.log(`Password for "${username}" updated; existing sessions were revoked.`);
      }
      break;
    }
    case 'disable-totp': {
      const username = rest.find((a) => !a.startsWith('--'));
      if (!username) throw new Error('usage: disable-totp <username>');
      const admin = findAdminByUsername(db, username);
      if (!admin) throw new Error(`No admin named "${username}"`);
      forceDisableTotp(db, admin.id);
      console.log(`TOTP disabled for "${username}"; all their sessions were ended. They should re-enrol from the panel (Bezpieczeństwo).`);
      break;
    }
    case 'cleanup': {
      setLogLevel(cfg.logLevel);
      const idx = rest.indexOf('--ttl-hours');
      const ttlMs = idx >= 0 ? Number(rest[idx + 1]) * 3600_000 : undefined;
      const storage = createStorage(cfg);
      const tusStore = storage.createTusStore({ expirationMs: cfg.incompleteUploadTtlMs });
      const report = await runCleanup({ db, cfg, storage, tusStore }, { ttlMs });
      console.log(JSON.stringify(report));
      break;
    }
    default:
      console.error('usage: cli <create-admin|reset-password|disable-totp|migrate|cleanup> ...');
      process.exitCode = 2;
  }
  db.close();
}

main(process.argv.slice(2)).catch((err) => {
  log.error('cli failed', { err });
  console.error(`Error: ${(err as Error).message}`);
  process.exit(1);
});
