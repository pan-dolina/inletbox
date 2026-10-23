/**
 * Passkeys as a second factor, re-confirmation before sensitive actions, and the
 * account's session list. Every signature here is real (test/authenticator.ts).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { listAudit } from '../src/services/audit.js';
import { findAdminByUsername } from '../src/services/auth.js';
import { verifyAssertion, verifyRegistration, WebAuthnError } from '../src/webauthn.js';
import { SoftAuthenticator } from './authenticator.js';
import { adminPost, boot, type AdminSession, type TestApp } from './helpers.js';

const RP = { origin: 'https://drop.example.com', rpId: 'drop.example.com' };
const CHALLENGE = Buffer.alloc(32, 7).toString('base64url');

describe('WebAuthn verification', () => {
  for (const alg of [-7, -8, -257] as const) {
    it(`registers and verifies a passkey (COSE ${alg})`, () => {
      const a = new SoftAuthenticator(alg);
      const r = a.register({ challenge: CHALLENGE, ...RP });
      const reg = verifyRegistration({ clientDataJSON: r.client_data!, authenticatorData: r.authenticator_data!, publicKey: r.public_key!, algorithm: alg, credentialId: r.credential_id! }, { challenge: CHALLENGE, ...RP });
      expect(reg.credentialId).toBe(r.credential_id);
      const s = a.assert({ challenge: CHALLENGE, ...RP });
      expect(verifyAssertion({ clientDataJSON: s.client_data!, authenticatorData: s.authenticator_data!, signature: s.signature! }, { publicKey: reg.publicKey, algorithm: alg, signCount: 0 }, { challenge: CHALLENGE, ...RP }).signCount).toBe(0);
    });
  }

  it('refuses a ceremony made for another site, another challenge, or without the user', () => {
    const a = new SoftAuthenticator(-7);
    const reg = a.register({ challenge: CHALLENGE, ...RP });
    const input = (r: Record<string, string>) => ({ clientDataJSON: r.client_data!, authenticatorData: r.authenticator_data!, publicKey: r.public_key!, algorithm: -7, credentialId: r.credential_id! });
    const exp = { challenge: CHALLENGE, ...RP };
    expect(() => verifyRegistration(input(reg), { ...exp, origin: 'https://evil.example' })).toThrow('origin mismatch');
    expect(() => verifyRegistration(input(reg), { ...exp, challenge: Buffer.alloc(32, 8).toString('base64url') })).toThrow('challenge mismatch');
    expect(() => verifyRegistration(input(a.register({ challenge: CHALLENGE, origin: RP.origin, rpId: 'evil.example' })), exp)).toThrow('RP id mismatch');
    expect(() => verifyRegistration(input(a.register({ challenge: CHALLENGE, ...RP, flags: 0x04 })), exp)).toThrow('user not present');
    expect(() => verifyRegistration({ ...input(reg), algorithm: -8 }, exp)).toThrow('unsupported key type');
    expect(() => verifyRegistration({ ...input(reg), algorithm: -35 }, exp)).toThrow('unsupported algorithm');
    expect(() => verifyRegistration({ ...input(reg), credentialId: Buffer.alloc(32).toString('base64url') }, exp)).toThrow('credential id mismatch');
    expect(() => verifyRegistration({ ...input(reg), clientDataJSON: 'not base64!' }, exp)).toThrow(WebAuthnError);
  });

  it('refuses a forged signature, a create() presented as get(), and a counter that goes backwards', () => {
    const a = new SoftAuthenticator(-7, { counter: true });
    const other = new SoftAuthenticator(-7);
    const pk = a.register({ challenge: CHALLENGE, ...RP }).public_key!;
    const exp = { challenge: CHALLENGE, ...RP };
    const asInput = (s: Record<string, string>) => ({ clientDataJSON: s.client_data!, authenticatorData: s.authenticator_data!, signature: s.signature! });
    expect(() => verifyAssertion(asInput(other.assert(exp)), { publicKey: pk, algorithm: -7, signCount: 0 }, exp)).toThrow('bad signature');
    expect(() => verifyAssertion(asInput(a.assert({ ...exp, type: 'webauthn.create' })), { publicKey: pk, algorithm: -7, signCount: 0 }, exp)).toThrow('wrong ceremony type');
    const ok = verifyAssertion(asInput(a.assert(exp)), { publicKey: pk, algorithm: -7, signCount: 0 }, exp);
    expect(ok.signCount).toBeGreaterThan(1);
    // A clone replaying an older counter value.
    expect(() => verifyAssertion(asInput(a.assert(exp)), { publicKey: pk, algorithm: -7, signCount: ok.signCount + 5 }, exp)).toThrow('counter went backwards');
  });
});

describe('passkeys in the panel', () => {
  let app: TestApp;
  let origin: string;
  let rpId: string;
  beforeAll(async () => {
    app = await boot();
    origin = new URL(app.base).origin;
    rpId = new URL(app.base).hostname;
  });
  afterAll(async () => { await app.close(); });

  /** The JSON passkey.js would get back. */
  async function postJson(s: AdminSession, path: string, fields: Record<string, string> = {}) {
    const res = await adminPost(app, s, path, fields);
    return { status: res.status, body: (await res.json()) as Record<string, unknown> & { challenge?: string; redirect?: string; error?: string } };
  }

  /** Pretends the confirmation (or the login's own) has run out, as for a stolen cookie found later. */
  function expireConfirmation(): void {
    app.ctx.db.prepare('UPDATE sessions SET confirmed_until = ?').run(new Date(Date.now() - 1000).toISOString());
  }

  async function login(username: string, password: string): Promise<{ cookie: string; status: number; location: string | null }> {
    const res = await fetch(`${app.base}/admin/login`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0 Safari/537.36' }, body: new URLSearchParams({ username, password }) });
    return { cookie: res.headers.get('set-cookie')!.split(';')[0]!, status: res.status, location: res.headers.get('location') };
  }

  async function csrfOf(cookie: string, path: string): Promise<string> {
    return /name="_csrf" value="([^"]+)"/.exec(await (await fetch(`${app.base}${path}`, { headers: { cookie } })).text())![1]!;
  }

  const key = new SoftAuthenticator(-7);
  const user = { username: 'passkey-user', password: '' };
  let codes: string[] = [];

  it('adds a passkey after a fresh sign-in, shows recovery codes once, and ends the other sessions', async () => {
    const u = app.mkUser(user.username);
    user.password = u.password;
    const other = await app.login(u.username, u.password);
    const s = await app.login(u.username, u.password);

    const opt = await postJson(s, '/admin/security/passkeys/options');
    expect(opt.status).toBe(200);
    expect(opt.body).toMatchObject({ rpId, exclude: [] });
    const add = await postJson(s, '/admin/security/passkeys', { name: 'Laptop', ...key.register({ challenge: opt.body.challenge!, origin, rpId }) });
    expect(add).toMatchObject({ status: 200, body: { redirect: '/admin/security' } });

    const page = await (await fetch(`${app.base}/admin/security`, { headers: { cookie: s.cookie } })).text();
    expect(page).toContain('Passkey “Laptop” added.');
    codes = /<pre class="mono" data-copy-source>([^<]*)<\/pre>/.exec(page)![1]!.trim().split('\n');
    expect(codes).toHaveLength(8);
    // Shown once.
    expect(await (await fetch(`${app.base}/admin/security`, { headers: { cookie: s.cookie } })).text()).not.toContain('data-copy-source>');
    expect(findAdminByUsername(app.ctx.db, u.username)!.passkeys).toBe(1);
    // The other session did not prove the new factor.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: other.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    // The same challenge cannot register a second time.
    expect((await postJson(s, '/admin/security/passkeys', { name: 'Again', ...key.register({ challenge: opt.body.challenge!, origin, rpId }) })).status).toBe(400);
  });

  it('signs in with password + passkey; the session records how', async () => {
    const pending = await login(user.username, user.password);
    expect(pending.location).toBe('/admin/totp');
    const second = await (await fetch(`${app.base}/admin/totp`, { headers: { cookie: pending.cookie } })).text();
    expect(second).toContain('data-passkey="login"');
    expect(second).toContain('Recovery code');
    const s = { cookie: pending.cookie, csrf: /name="_csrf" value="([^"]+)"/.exec(second)![1]! };
    // Nothing else is reachable yet.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/totp');

    const opt = await postJson(s, '/admin/webauthn/login/options');
    expect(opt.body.allow).toEqual([key.credentialId.toString('base64url')]);
    // A passkey of someone else, or for another site, is refused and burns the challenge.
    const stranger = new SoftAuthenticator(-7);
    expect((await postJson(s, '/admin/webauthn/login', stranger.assert({ challenge: opt.body.challenge!, origin, rpId }))).status).toBe(401);
    expect((await postJson(s, '/admin/webauthn/login', key.assert({ challenge: opt.body.challenge!, origin, rpId }))).status).toBe(401);

    const opt2 = await postJson(s, '/admin/webauthn/login/options');
    const res = await adminPost(app, s, '/admin/webauthn/login', key.assert({ challenge: opt2.body.challenge!, origin, rpId }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ redirect: '/admin' });
    const full = res.headers.get('set-cookie')!.split(';')[0]!;
    expect(full).not.toBe(pending.cookie);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: full }, redirect: 'manual' })).status).toBe(200);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: pending.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    const session = app.ctx.db.prepare("SELECT second_factor, user_agent FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE a.username = ? AND s.totp_verified = 1 ORDER BY s.created_at DESC LIMIT 1").get(user.username) as { second_factor: string; user_agent: string };
    expect(session.second_factor).toBe('passkey');
    expect(listAudit(app.ctx.db, 20).some((r) => r.action === 'admin.login' && JSON.stringify(r.details).includes('passkey'))).toBe(true);
    expect(listAudit(app.ctx.db, 20).some((r) => r.action === 'admin.passkey_failed')).toBe(true);
  });

  it('a stolen cookie can look around, but not download, issue links, manage accounts or add a factor', async () => {
    const s = await app.adminLogin();
    const c = app.mkCase('Stolen cookie');
    expireConfirmation();
    const link = await adminPost(app, s, `/admin/cases/${c.id}/links`, { label: 'x' });
    expect(link.status).toBe(303);
    expect(link.headers.get('location')).toBe(`/admin/confirm?next=${encodeURIComponent(`/admin/cases/${c.id}`)}`);
    const dl = await fetch(`${app.base}/admin/files/f_0000000000000000/download`, { headers: { cookie: s.cookie }, redirect: 'manual' });
    expect(dl.headers.get('location')).toBe(`/admin/confirm?next=${encodeURIComponent('/admin/files/f_0000000000000000/download')}`);
    expect((await adminPost(app, s, '/admin/users', { username: 'mallory' })).headers.get('location')).toMatch(/^\/admin\/confirm\?next=%2Fadmin%2Fusers$/);
    expect((await postJson(s, '/admin/security/passkeys/options')).body.redirect).toMatch(/^\/admin\/confirm/);
    expect((await adminPost(app, s, '/admin/security/totp/begin')).headers.get('location')).toMatch(/^\/admin\/confirm/);
    // Reading is fine.
    expect((await fetch(`${app.base}/admin/cases/${c.id}`, { headers: { cookie: s.cookie } })).status).toBe(200);

    // The admin has no second factor, so the password confirms.
    const confirmPage = await (await fetch(`${app.base}/admin/confirm?next=%2Fadmin%2Fcases%2F${c.id}`, { headers: { cookie: s.cookie } })).text();
    expect(confirmPage).toContain('name="password"');
    expect((await adminPost(app, s, '/admin/confirm/password', { password: 'wrong-password-000', next: `/admin/cases/${c.id}` })).status).toBe(401);
    const ok = await adminPost(app, s, '/admin/confirm/password', { password: 'correct-horse-battery-staple', next: `/admin/cases/${c.id}` });
    expect(ok.headers.get('location')).toBe(`/admin/cases/${c.id}`);
    expect((await adminPost(app, s, `/admin/cases/${c.id}/links`, { label: 'x' })).status).toBe(200);
    // Only places inside the panel are followed.
    const off = await adminPost(app, s, '/admin/confirm/password', { password: 'correct-horse-battery-staple', next: 'https://evil.example/' });
    expect(off.headers.get('location')).toBe('/admin');
  });

  it('an account with a second factor confirms with it, never with the password alone', async () => {
    const pending = await login(user.username, user.password);
    const csrf = await csrfOf(pending.cookie, '/admin/totp');
    const opt = await postJson({ cookie: pending.cookie, csrf }, '/admin/webauthn/login/options');
    const res = await adminPost(app, { cookie: pending.cookie, csrf }, '/admin/webauthn/login', key.assert({ challenge: opt.body.challenge!, origin, rpId }));
    const s = { cookie: res.headers.get('set-cookie')!.split(';')[0]!, csrf: '' };
    s.csrf = await csrfOf(s.cookie, '/admin/security');
    expireConfirmation();

    const page = await (await fetch(`${app.base}/admin/confirm`, { headers: { cookie: s.cookie } })).text();
    expect(page).toContain('data-passkey="confirm"');
    expect(page).not.toContain('name="password"');
    expect((await adminPost(app, s, '/admin/confirm/password', { password: user.password })).status).toBe(401);

    const copt = await postJson(s, '/admin/webauthn/confirm/options');
    const done = await adminPost(app, s, `/admin/confirm/passkey?next=${encodeURIComponent('/admin/security')}`, key.assert({ challenge: copt.body.challenge!, origin, rpId }));
    expect(await done.json()).toEqual({ redirect: '/admin/security' });
    expect((await postJson(s, '/admin/security/passkeys/options')).body.challenge).toBeTruthy();
  });

  it('confirms with a recovery code once, and renews the codes after a passkey confirmation', async () => {
    const pending = await login(user.username, user.password);
    const sp = { cookie: pending.cookie, csrf: await csrfOf(pending.cookie, '/admin/totp') };
    // A recovery code also stands in for a lost passkey at login.
    const viaCode = await adminPost(app, sp, '/admin/totp', { code: codes[0]! });
    expect(viaCode.status).toBe(303);
    const s = { cookie: viaCode.headers.get('set-cookie')!.split(';')[0]!, csrf: '' };
    s.csrf = await csrfOf(s.cookie, '/admin/security');
    expireConfirmation();
    expect((await adminPost(app, s, '/admin/confirm/code', { code: codes[0]!, next: '/admin/security' })).status).toBe(401);
    const ok = await adminPost(app, s, '/admin/confirm/code', { code: codes[1]!, next: '/admin/security' });
    expect(ok.headers.get('location')).toBe('/admin/security');
    const renewed = await adminPost(app, s, '/admin/security/recovery/regenerate');
    expect(renewed.status).toBe(200);
    const fresh = /<pre class="mono" data-copy-source>([^<]*)<\/pre>/.exec(await renewed.text())![1]!.trim().split('\n');
    expect(fresh).toHaveLength(8);
    expect(fresh).not.toContain(codes[2]);
    codes = fresh;
    expect(listAudit(app.ctx.db, 10).some((r) => r.action === 'admin.confirmed')).toBe(true);
  });

  it('lists the sessions of the account and ends the ones it chooses', async () => {
    const a = await login(user.username, user.password);
    const sa = { cookie: a.cookie, csrf: await csrfOf(a.cookie, '/admin/totp') };
    const opt = await postJson(sa, '/admin/webauthn/login/options');
    const full = (await adminPost(app, sa, '/admin/webauthn/login', key.assert({ challenge: opt.body.challenge!, origin, rpId }))).headers.get('set-cookie')!.split(';')[0]!;
    const s = { cookie: full, csrf: await csrfOf(full, '/admin/security') };
    const stranger = await login(user.username, user.password); // got the password, not the passkey

    const page = await (await fetch(`${app.base}/admin/security`, { headers: { cookie: s.cookie } })).text();
    expect(page).toContain('Chrome · Windows');
    expect(page).toContain('this session');
    expect(page).toContain('password only, second step not done');
    const ids = [...page.matchAll(/\/admin\/security\/sessions\/(s_[0-9a-zA-Z_-]+)\/revoke/g)].map((m) => m[1]!);
    expect(ids.length).toBeGreaterThanOrEqual(2);
    const pendingId = (app.ctx.db.prepare('SELECT public_id FROM sessions WHERE id_hash = (SELECT id_hash FROM sessions WHERE totp_verified = 0 ORDER BY created_at DESC LIMIT 1)').get() as { public_id: string }).public_id;
    expect((await adminPost(app, s, `/admin/security/sessions/${pendingId}/revoke`)).status).toBe(200);
    expect((await fetch(`${app.base}/admin/totp`, { headers: { cookie: stranger.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    // Not your own current session, and not someone else's.
    const mine = (app.ctx.db.prepare('SELECT public_id FROM sessions WHERE totp_verified = 1 ORDER BY created_at DESC LIMIT 1').get() as { public_id: string }).public_id;
    expect((await adminPost(app, s, `/admin/security/sessions/${mine}/revoke`)).status).toBe(404);
    const admin = await app.adminLogin();
    const adminSession = (app.ctx.db.prepare('SELECT public_id FROM sessions ORDER BY created_at DESC LIMIT 1').get() as { public_id: string }).public_id;
    expect((await adminPost(app, s, `/admin/security/sessions/${adminSession}/revoke`)).status).toBe(404);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: admin.cookie }, redirect: 'manual' })).status).toBe(200);

    expect((await adminPost(app, s, '/admin/security/sessions/revoke-others')).status).toBe(200);
    expect(app.ctx.db.prepare('SELECT COUNT(*) AS n FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE a.username = ?').get(user.username)).toEqual({ n: 1 });
  });

  it('removing a passkey needs a confirmation and ends the other sessions; an admin reset removes them all', async () => {
    const s = await app.adminLogin();
    const k = new SoftAuthenticator(-8);
    const opt = await postJson(s, '/admin/security/passkeys/options');
    await postJson(s, '/admin/security/passkeys', { name: 'Key', ...k.register({ challenge: opt.body.challenge!, origin, rpId }) });
    const id = (app.ctx.db.prepare("SELECT id FROM admin_passkeys WHERE name = 'Key'").get() as { id: string }).id;
    expireConfirmation();
    expect((await adminPost(app, s, `/admin/security/passkeys/${id}/remove`)).headers.get('location')).toMatch(/^\/admin\/confirm/);
    app.ctx.db.prepare('UPDATE sessions SET confirmed_until = ?').run(new Date(Date.now() + 60_000).toISOString());
    const removed = await adminPost(app, s, `/admin/security/passkeys/${id}/remove`);
    expect(removed.status).toBe(200);
    expect(await removed.text()).toContain('Passkey “Key” removed.');

    const victim = findAdminByUsername(app.ctx.db, user.username)!;
    expect(victim.passkeys).toBe(1);
    // A passkey alone counts as two-factor in the account list, with the reset button.
    const list = await (await fetch(`${app.base}/admin/users`, { headers: { cookie: s.cookie } })).text();
    expect(list).toContain(`/admin/users/${victim.id}/totp`);
    expect((await adminPost(app, s, `/admin/users/${victim.id}/totp`)).status).toBe(200);
    expect(findAdminByUsername(app.ctx.db, user.username)!.passkeys).toBe(0);
    expect(app.ctx.db.prepare('SELECT COUNT(*) AS n FROM admin_recovery_codes WHERE admin_id = ?').get(victim.id)).toEqual({ n: 0 });
  });
});

describe('ADMIN_REQUIRE_TOTP with passkeys', () => {
  let app: TestApp;
  beforeAll(async () => { app = await boot({ ADMIN_REQUIRE_TOTP: 'true' }); });
  afterAll(async () => { await app.close(); });

  it('accepts a passkey as the required second factor, and keeps the last one', async () => {
    const origin = new URL(app.base).origin;
    const rpId = new URL(app.base).hostname;
    const s = await app.adminLogin();
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/security');
    const k = new SoftAuthenticator(-257);
    const opt = (await (await adminPost(app, s, '/admin/security/passkeys/options')).json()) as { challenge: string };
    expect((await adminPost(app, s, '/admin/security/passkeys', { name: 'Only', ...k.register({ challenge: opt.challenge, origin, rpId }) })).status).toBe(200);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).status).toBe(200);
    const id = (app.ctx.db.prepare('SELECT id FROM admin_passkeys').get() as { id: string }).id;
    const refused = await adminPost(app, s, `/admin/security/passkeys/${id}/remove`);
    expect(refused.status).toBe(400);
    expect(await refused.text()).toContain('requires a second factor');
  });
});
