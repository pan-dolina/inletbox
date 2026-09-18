import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { listAudit } from '../src/services/audit.js';
import { findAdminByUsername, pendingTotpSecret, totpLockedUntil } from '../src/services/auth.js';
import { base32Decode, base32Encode, hotp, otpauthUri, totp, totpStep, verifyTotp } from '../src/totp.js';
import { ADMIN_PASS, ADMIN_USER, adminPost, boot, type AdminSession, type TestApp } from './helpers.js';

const execFileP = promisify(execFile);

describe('TOTP primitives', () => {
  const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));

  it('round-trips base32', () => {
    expect(RFC_SECRET).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(base32Decode(RFC_SECRET).toString('ascii')).toBe('12345678901234567890');
    expect(base32Decode('gezd gnbv-gy3t').toString('ascii')).toBe('1234567');
    expect(() => base32Decode('!!')).toThrow();
  });

  it('matches the RFC 6238 SHA-1 test vectors', () => {
    expect(hotp(RFC_SECRET, 1, { digits: 8 })).toBe('94287082');            // T = 59
    expect(totp(RFC_SECRET, 1111111109 * 1000, { digits: 8 })).toBe('07081804');
    expect(totp(RFC_SECRET, 1234567890 * 1000, { digits: 8 })).toBe('89005924');
    expect(totp(RFC_SECRET, 59 * 1000)).toBe('287082');                     // 6 digits
  });

  it('verifies within ±1 step and refuses replays via minStep', () => {
    const now = 1234567890 * 1000;
    const step = totpStep(now);
    expect(verifyTotp(RFC_SECRET, '005924', { nowMs: now })).toBe(step);
    expect(verifyTotp(RFC_SECRET, '005 924', { nowMs: now })).toBe(step);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step - 1), { nowMs: now })).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step + 1), { nowMs: now })).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step - 2), { nowMs: now })).toBeNull();
    expect(verifyTotp(RFC_SECRET, '005924', { nowMs: now, minStep: step })).toBeNull();
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step + 1), { nowMs: now, minStep: step })).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, '00592', { nowMs: now })).toBeNull();
    expect(verifyTotp(RFC_SECRET, 'abcdef', { nowMs: now })).toBeNull();
  });

  it('builds a standard otpauth URI', () => {
    const uri = otpauthUri({ secret: 'ABC234', account: 'ad min', issuer: 'inletbox' });
    expect(uri).toBe('otpauth://totp/inletbox%3Aad%20min?secret=ABC234&issuer=inletbox&algorithm=SHA1&digits=6&period=30');
  });
});

describe('admin two-factor login flow', () => {
  let app: TestApp;
  let secret: string;
  let recoveryCodes: string[];
  beforeAll(async () => { app = await boot({ LOGIN_RATE_LIMIT_PER_15MIN: '100' }); });
  afterAll(async () => { await app.close(); });
  // Wrong codes accumulate per account across tests (by design); each test starts unlocked.
  beforeEach(() => { app.ctx.db.prepare('UPDATE admins SET totp_failed_count = 0, totp_locked_until = NULL').run(); });

  async function passwordLogin(): Promise<{ cookie: string; location: string | null }> {
    const res = await fetch(`${app.base}/admin/login`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: ADMIN_USER, password: ADMIN_PASS }),
    });
    expect(res.status).toBe(303);
    return { cookie: res.headers.get('set-cookie')!.split(';')[0]!, location: res.headers.get('location') };
  }
  async function csrfFor(cookie: string, path = '/admin'): Promise<string> {
    const page = await (await fetch(`${app.base}${path}`, { headers: { cookie } })).text();
    return /name="_csrf" value="([^"]+)"/.exec(page)![1]!;
  }
  async function postTotp(cookie: string, code: string): Promise<Response> {
    const csrf = await csrfFor(cookie, '/admin/totp');
    return fetch(`${app.base}/admin/totp`, {
      method: 'POST', redirect: 'manual', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: csrf, code }),
    });
  }
  /** The privileged session gets a fresh cookie; the pending one is gone. */
  function rotated(res: Response): string { return res.headers.get('set-cookie')!.split(';')[0]!; }
  async function loginWithTotp(): Promise<AdminSession> {
    const { cookie } = await passwordLogin();
    const res = await postTotp(cookie, freshCode());
    expect(res.status).toBe(303);
    const verified = rotated(res);
    return { cookie: verified, csrf: await csrfFor(verified, '/admin/security') };
  }
  /**
   * A valid code for "now". Replay protection remembers the last accepted step, so between
   * logins the tests pretend enough time has passed by clearing it (instead of sleeping 30 s).
   */
  function freshCode(): string {
    app.ctx.db.prepare('UPDATE admins SET totp_last_step = NULL WHERE username = ?').run(ADMIN_USER);
    return totp(secret);
  }

  it('enrols through the security page: QR + secret, confirmation code, recovery codes shown once', async () => {
    const s: AdminSession = await app.adminLogin();
    const begin = await adminPost(app, s, '/admin/security/totp/begin');
    expect(begin.status).toBe(200);
    const page = await begin.text();
    expect(page).toContain('<svg');
    expect(page).toContain('otpauth');
    secret = pendingTotpSecret(app.ctx.db, findAdminByUsername(app.ctx.db, ADMIN_USER)!.id)!;
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(page).toContain(secret.replace(/(.{4})/g, '$1 ').trim());
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(false);

    // Wrong confirmation code does not enable anything.
    const bad = await adminPost(app, s, '/admin/security/totp/confirm', { code: '000000' });
    expect(bad.status).toBe(400);
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(false);

    const ok = await adminPost(app, s, '/admin/security/totp/confirm', { code: totp(secret) });
    expect(ok.status).toBe(200);
    const okPage = await ok.text();
    recoveryCodes = [...okPage.matchAll(/\b([a-z2-7]{5}-[a-z2-7]{5})\b/g)].map((m) => m[1]!);
    expect(recoveryCodes).toHaveLength(8);
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(true);
    // The enrolling session stays usable; the codes are not shown again.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).status).toBe(200);
    const again = await (await fetch(`${app.base}/admin/security`, { headers: { cookie: s.cookie } })).text();
    for (const c of recoveryCodes) expect(again).not.toContain(c);
    expect(again).toContain('Niewykorzystane kody zapasowe: <strong>8</strong>');
  });

  it('after enrolment the password alone yields a pending session that cannot use the panel', async () => {
    const { cookie, location } = await passwordLogin();
    expect(location).toBe('/admin/totp');
    expect((await fetch(`${app.base}/admin`, { headers: { cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/totp');
    expect((await fetch(`${app.base}/admin/security`, { headers: { cookie }, redirect: 'manual' })).status).toBe(302);
    expect((await fetch(`${app.base}/admin/files/f_0000000000000000/download`, { headers: { cookie }, redirect: 'manual' })).status).toBe(302);
    const csrf = await csrfFor(cookie, '/admin/totp');
    const post = await fetch(`${app.base}/admin/cases`, {
      method: 'POST', redirect: 'manual', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: csrf, name: 'should not exist' }),
    });
    expect(post.status).toBe(401);

    expect((await postTotp(cookie, '123456')).status).toBe(401);
    const good = await postTotp(cookie, freshCode());
    expect(good.status).toBe(303);
    expect(good.headers.get('location')).toBe('/admin');
    // Session id rotated: the pending cookie is dead, the new one is privileged.
    const verified = rotated(good);
    expect(verified).not.toBe(cookie);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: verified }, redirect: 'manual' })).status).toBe(200);
    const actions = listAudit(app.ctx.db, 20).map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(['admin.login_password', 'admin.totp_failed', 'admin.login']));
  });

  it('rejects replay of an already used code and codes outside the window', async () => {
    const code = freshCode();
    const a = await passwordLogin();
    expect((await postTotp(a.cookie, code)).status).toBe(303);
    const b = await passwordLogin();
    expect((await postTotp(b.cookie, code)).status).toBe(401);                          // same code again: replay
    expect((await postTotp(b.cookie, hotp(secret, totpStep() - 1))).status).toBe(401);  // older step than the accepted one
    expect((await postTotp(b.cookie, hotp(secret, totpStep() + 2))).status).toBe(401);  // outside the ±1 window
    expect((await postTotp(b.cookie, hotp(secret, totpStep() + 1))).status).toBe(303);  // next step: fine
  });

  it('locks the pending session after too many wrong codes', async () => {
    const { cookie } = await passwordLogin();
    for (let i = 0; i < 4; i++) {
      const res = await postTotp(cookie, '000000');
      expect(res.status).toBe(401);
      expect(await res.text()).toContain(`Pozostałe próby: ${4 - i}`);
    }
    const fifth = await postTotp(cookie, '000000');
    expect(fifth.status).toBe(401);
    expect(fifth.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(await fifth.text()).toContain('Zbyt wiele');
    // The session is gone: even a correct code cannot be used with the old cookie.
    expect((await fetch(`${app.base}/admin/totp`, { headers: { cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    expect(listAudit(app.ctx.db, 5).map((r) => r.action)).toContain('admin.totp_locked');
  });

  it('accepts each recovery code exactly once', async () => {
    const code = recoveryCodes[0]!;
    const a = await passwordLogin();
    const ok = await postTotp(a.cookie, code.toUpperCase());
    expect(ok.status).toBe(303);
    const b = await passwordLogin();
    expect((await postTotp(b.cookie, code)).status).toBe(401);
    expect((await postTotp(b.cookie, 'zzzzz-zzzzz')).status).toBe(401);
    const security = await (await fetch(`${app.base}/admin/security`, { headers: { cookie: rotated(ok) } })).text();
    expect(security).toContain('Niewykorzystane kody zapasowe: <strong>7</strong>');
  });

  it('locks the account (not just the session) after repeated wrong codes from any session', async () => {
    // Two pending sessions burn 5 attempts each: the 10th failure locks the account.
    for (let round = 0; round < 2; round++) {
      const { cookie } = await passwordLogin();
      for (let i = 0; i < 5; i++) await postTotp(cookie, '000000');
    }
    const admin = findAdminByUsername(app.ctx.db, ADMIN_USER)!;
    expect(totpLockedUntil(app.ctx.db, admin.id)).not.toBeNull();
    // A correct code from a brand-new session is refused while the lock holds.
    const fresh = await passwordLogin();
    const page = await (await fetch(`${app.base}/admin/totp`, { headers: { cookie: fresh.cookie } })).text();
    expect(page).toContain('tymczasowo zablokowane');
    const refused = await postTotp(fresh.cookie, freshCode());
    expect(refused.status).toBe(401);
    expect(await refused.text()).toContain('zablokowane na 15 minut');
    // Lock expiry (simulated) restores normal operation and the failure counter is reset by success.
    app.ctx.db.prepare('UPDATE admins SET totp_locked_until = NULL WHERE id = ?').run(admin.id);
    const again = await passwordLogin();
    expect((await postTotp(again.cookie, freshCode())).status).toBe(303);
    expect((app.ctx.db.prepare('SELECT totp_failed_count FROM admins WHERE id = ?').get(admin.id) as { totp_failed_count: number }).totp_failed_count).toBe(0);
  });

  it('regenerating recovery codes requires a valid TOTP code and invalidates the old ones', async () => {
    const s = await loginWithTotp();
    expect((await adminPost(app, s, '/admin/security/totp/recovery', { code: '000000' })).status).toBe(400);
    const res = await adminPost(app, s, '/admin/security/totp/recovery', { code: freshCode() });
    expect(res.status).toBe(200);
    const fresh = [...(await res.text()).matchAll(/\b([a-z2-7]{5}-[a-z2-7]{5})\b/g)].map((m) => m[1]!);
    expect(fresh).toHaveLength(8);
    expect(fresh).not.toContain(recoveryCodes[1]);
    const c = await passwordLogin();
    expect((await postTotp(c.cookie, recoveryCodes[1]!)).status).toBe(401);
    recoveryCodes = fresh;
  });

  it('disabling requires a code, ends every other session, and afterwards the password alone logs in', async () => {
    const s = await loginWithTotp();
    const other = await loginWithTotp();          // a second verified session
    const pending = await passwordLogin();         // and a pending one
    expect((await adminPost(app, s, '/admin/security/totp/disable', { code: '000000' })).status).toBe(400);
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(true);
    expect((await adminPost(app, s, '/admin/security/totp/disable', { code: freshCode() })).status).toBe(200);
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(false);
    // The disabling session survives; the others (verified or pending) are gone rather than silently upgraded.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).status).toBe(200);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: other.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: pending.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    const plain = await passwordLogin();
    expect(plain.location).toBe('/admin');
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: plain.cookie }, redirect: 'manual' })).status).toBe(200);
    expect(listAudit(app.ctx.db, 10).map((r) => r.action)).toContain('admin.totp_disabled');
  });

  it('the CLI can remove a lost second factor', async () => {
    const s = await app.adminLogin();
    await adminPost(app, s, '/admin/security/totp/begin');
    const sec = pendingTotpSecret(app.ctx.db, findAdminByUsername(app.ctx.db, ADMIN_USER)!.id)!;
    await adminPost(app, s, '/admin/security/totp/confirm', { code: totp(sec) });
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(true);
    const { stdout } = await execFileP('npx', ['tsx', 'src/cli.ts', 'disable-totp', ADMIN_USER], {
      cwd: new URL('..', import.meta.url).pathname,
      env: { ...process.env, DATA_DIR: app.dataDir, PUBLIC_URL: app.base, STORAGE_BACKEND: 'local' },
    });
    expect(stdout).toContain('TOTP disabled');
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(false);
    // The CLI also ends all sessions of that admin.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
  });
});

describe('ADMIN_REQUIRE_TOTP', () => {
  let app: TestApp;
  beforeAll(async () => { app = await boot({ ADMIN_REQUIRE_TOTP: 'true' }); });
  afterAll(async () => { await app.close(); });

  it('confines admins without a second factor to the security page until they enrol', async () => {
    const login = await fetch(`${app.base}/admin/login`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: ADMIN_USER, password: ADMIN_PASS }),
    });
    expect(login.headers.get('location')).toBe('/admin/security');
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
    expect((await fetch(`${app.base}/admin`, { headers: { cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/security');
    const securityPage = await (await fetch(`${app.base}/admin/security`, { headers: { cookie } })).text();
    expect(securityPage).toContain('wymaga uwierzytelniania dwuskładnikowego');
    const csrf = /name="_csrf" value="([^"]+)"/.exec(securityPage)![1]!;
    const s = { cookie, csrf };
    expect((await adminPost(app, s, '/admin/cases', { name: 'blocked' })).status).toBe(403);

    await adminPost(app, s, '/admin/security/totp/begin');
    const secret = pendingTotpSecret(app.ctx.db, findAdminByUsername(app.ctx.db, ADMIN_USER)!.id)!;
    expect((await adminPost(app, s, '/admin/security/totp/confirm', { code: totp(secret) })).status).toBe(200);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie }, redirect: 'manual' })).status).toBe(200);
    expect((await adminPost(app, s, '/admin/cases', { name: 'allowed' })).status).toBe(303);
    // Cannot be switched off on this instance.
    expect((await adminPost(app, s, '/admin/security/totp/disable', { code: hotp(secret, totpStep() + 1) })).status).toBe(400);
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.totp_enabled).toBe(true);
  });
});
