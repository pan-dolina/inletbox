import { translator, type Lang, type Translator } from '../../i18n.js';
import type { Passkey } from '../../services/passkeys.js';
import type { SessionSummary } from '../../services/sessions.js';
import { fmtDate, html, layout, raw, type SafeHtml } from '../html.js';

/** A passkey button; passkey.js does the ceremony and reports into `status`. */
function passkeyButton(t: Translator, opts: { kind: 'login' | 'confirm' | 'register'; csrfToken: string; options: string; submit: string; label: string; primary?: boolean; nameInput?: string }): SafeHtml {
  return html`<button class="btn${opts.primary ? ' btn-primary' : ''}" type="button" hidden data-passkey="${opts.kind}" data-csrf="${opts.csrfToken}"
      data-options="${opts.options}" data-submit="${opts.submit}" data-status="passkey-status-${opts.kind}" ${opts.nameInput ? raw(`data-name-input="${opts.nameInput}"`) : ''}
      data-failed="${t('passkey.failed')}" data-cancelled="${t('passkey.cancelled')}" data-unsupported="${t('passkey.unsupported')}">${opts.label}</button>
    <p class="flash flash-error" id="passkey-status-${opts.kind}" role="status" hidden></p>`;
}

/**
 * Second step of the login: the session exists but the second factor is still missing.
 * A passkey button when the account has one; the code form when it has an app or recovery codes.
 */
export function totpLoginPage(lang: Lang, opts: { csrfToken: string; error?: string; attemptsLeft?: number; lockedUntil?: string; passkey?: boolean; totp?: boolean; codes?: boolean }): string {
  const t = translator(lang);
  const passkey = opts.passkey ?? false;
  const codes = opts.codes ?? true;
  return layout({
    lang, title: t(passkey ? 'second.title' : 'totp.title'), path: '/admin/totp',
    scripts: passkey ? ['/static/passkey.js'] : [],
    body: html`<section class="card narrow">
      <h1>${t(passkey ? 'second.title' : 'totp.title')}</h1>
      ${opts.error ? html`<div class="flash flash-error">${opts.error}${opts.attemptsLeft != null ? html` ${t('totp.attempts_left', { n: opts.attemptsLeft })}` : ''}</div>` : ''}
      ${opts.lockedUntil ? html`<div class="flash flash-error">${t('totp.locked_until', { until: opts.lockedUntil.replace('T', ' ').slice(0, 16) })}</div>` : ''}
      ${passkey ? html`<p>${passkeyButton(t, { kind: 'login', csrfToken: opts.csrfToken, options: '/admin/webauthn/login/options', submit: '/admin/webauthn/login', label: t('passkey.use'), primary: true })}</p>` : ''}
      ${passkey && codes ? html`<p class="muted small">${t('common.or')}</p>` : ''}
      ${codes ? html`<form method="post" action="/admin/totp">
        <input type="hidden" name="_csrf" value="${opts.csrfToken}">
        <label>${t(opts.totp === false ? 'second.recovery_label' : 'totp.code_label')}
          <input name="code" required autocomplete="one-time-code" ${opts.totp === false ? '' : raw('inputmode="numeric"')} ${passkey ? '' : raw('autofocus')} pattern="[0-9a-zA-Z\\- ]{6,12}">
        </label>
        <button class="btn${passkey ? '' : ' btn-primary'}" type="submit">${t('totp.confirm')}</button>
      </form>` : ''}
      <form method="post" action="/admin/logout" class="inline"><input type="hidden" name="_csrf" value="${opts.csrfToken}"><button class="btn btn-link btn-link-muted" type="submit">${t('totp.cancel_logout')}</button></form>
    </section>`,
  });
}

/** Re-confirmation before a sensitive action, with whatever the account has: passkey, code, or password. */
export function confirmPage(d: { lang: Lang; nav: SafeHtml; csrfToken: string; next: string; minutes: number; passkey: boolean; codes: boolean; password: boolean; error?: string }): string {
  const t = translator(d.lang);
  const csrf = html`<input type="hidden" name="_csrf" value="${d.csrfToken}"><input type="hidden" name="next" value="${d.next}">`;
  const parts: SafeHtml[] = [];
  if (d.passkey) parts.push(html`<p>${passkeyButton(t, { kind: 'confirm', csrfToken: d.csrfToken, options: '/admin/webauthn/confirm/options', submit: `/admin/confirm/passkey?next=${encodeURIComponent(d.next)}`, label: t('passkey.use'), primary: true })}</p>`);
  if (d.codes) parts.push(html`<form method="post" action="/admin/confirm/code">${csrf}
      <label>${t('confirm.code_label')} <input name="code" required autocomplete="one-time-code" ${d.passkey ? '' : raw('autofocus')}></label>
      <button class="btn${d.passkey ? '' : ' btn-primary'}" type="submit">${t('confirm.submit')}</button></form>`);
  if (d.password) parts.push(html`<form method="post" action="/admin/confirm/password">${csrf}
      <label>${t('confirm.password_label')} <input name="password" type="password" required autocomplete="current-password" autofocus></label>
      <button class="btn btn-primary" type="submit">${t('confirm.submit')}</button></form>`);
  return layout({
    lang: d.lang, title: t('confirm.title'), nav: d.nav, path: '/admin/confirm',
    scripts: d.passkey ? ['/static/passkey.js'] : [],
    body: html`<section class="card narrow">
      <h1>${t('confirm.title')}</h1>
      ${d.error ? html`<div class="flash flash-error">${d.error}</div>` : ''}
      <p>${t('confirm.intro', { minutes: d.minutes })}</p>
      <p class="muted small">${t('confirm.repeat')}</p>
      ${parts.map((p, i) => (i > 0 ? html`<p class="muted small">${t('common.or')}</p>${p}` : p))}
    </section>`,
  });
}

/** "Firefox · Windows" from a User-Agent string; good enough to recognise your own devices. */
export function describeUserAgent(ua: string | null): string | null {
  if (!ua) return null;
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl\//.test(ua) ? 'curl' : null;
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : null;
  return [browser, os].filter(Boolean).join(' · ') || null;
}

export interface SecurityPageData {
  lang: Lang;
  csrfToken: string;
  username: string;
  nav: SafeHtml;
  totpEnabled: boolean;
  totpRequired: boolean;
  issuer: string;
  recoveryLeft: number;
  passkeys: Passkey[];
  sessions: SessionSummary[];
  /** The password was issued by an administrator and has to be replaced before anything else. */
  mustChangePassword?: boolean;
  /** Enrolment in progress: QR (SVG markup produced by the qrcode library) + secret for manual entry. */
  enrol?: { qrSvg: string; secret: string; uri: string };
  /** Freshly generated recovery codes, shown once. */
  recoveryCodes?: string[];
  error?: string;
  ok?: string;
}

export function securityPage(d: SecurityPageData): string {
  const t = translator(d.lang);
  const csrf = html`<input type="hidden" name="_csrf" value="${d.csrfToken}">`;
  return layout({
    lang: d.lang, title: t('nav.security'), nav: d.nav, path: '/admin/security',
    scripts: ['/static/admin.js', '/static/passkey.js'],
    body: html`
      <section class="card">
        <h1>${t('security.title', { user: d.username })}</h1>
        ${d.error ? html`<div class="flash flash-error">${d.error}</div>` : ''}
        ${d.ok ? html`<div class="flash flash-ok">${d.ok}</div>` : ''}
        ${d.mustChangePassword ? html`<div class="warning">${t('security.must_change_notice')}</div>` : ''}
        ${d.totpRequired && !d.totpEnabled && d.passkeys.length === 0 ? html`<div class="warning">${t('security.required_notice')}</div>` : ''}
        <p>${raw(t('security.status', { state: `<strong>${d.totpEnabled ? t('security.enabled') : t('security.disabled')}</strong>` }))}
        ${d.totpEnabled || d.passkeys.length > 0 ? raw(t('security.recovery_left', { n: `<strong>${d.recoveryLeft}</strong>` })) : ''}</p>
      </section>

      <section class="card">
        <h2>${t('passkeys.title')}</h2>
        <p class="small">${t('passkeys.intro')}</p>
        ${d.passkeys.length === 0 ? html`<p class="muted">${t('passkeys.none')}</p>` : html`<table>
          <thead><tr><th>${t('passkeys.name')}</th><th>${t('passkeys.added_at')}</th><th>${t('passkeys.last_used')}</th><th></th></tr></thead>
          <tbody>${d.passkeys.map((p) => html`<tr>
            <td>${p.name}</td><td>${fmtDate(p.created_at, d.lang)}</td><td>${fmtDate(p.last_used_at, d.lang)}</td>
            <td><form method="post" action="/admin/security/passkeys/${p.id}/remove" class="inline" data-confirm="${t('passkeys.remove_confirm')}">${csrf}<button class="btn btn-danger btn-small" type="submit">${t('passkeys.remove')}</button></form></td>
          </tr>`)}</tbody></table>`}
        <div class="row">
          <label>${t('passkeys.name')} <input id="passkey-name" maxlength="64" placeholder="${t('passkeys.name_placeholder')}"></label>
          ${passkeyButton(t, { kind: 'register', csrfToken: d.csrfToken, options: '/admin/security/passkeys/options', submit: '/admin/security/passkeys', label: t('passkeys.add'), primary: true, nameInput: 'passkey-name' })}
        </div>
      </section>

      <section class="card">
        <h2>${t('security.password.title')}</h2>
        <form method="post" action="/admin/security/password" class="row">${csrf}
          <label>${t('security.password.current')} <input name="current_password" type="password" required autocomplete="current-password"></label>
          <label>${t('security.password.new')} <input name="new_password" type="password" required autocomplete="new-password" minlength="12"></label>
          <label>${t('security.password.confirm')} <input name="new_password_confirm" type="password" required autocomplete="new-password" minlength="12"></label>
          <button class="btn" type="submit">${t('security.password.submit')}</button>
        </form>
      </section>

      ${d.recoveryCodes ? html`<section class="card highlight">
        <h2>${t('security.recovery.title')}</h2>
        <p><strong>${t('security.recovery.intro').split('. ')[0]}.</strong> ${t('security.recovery.intro').split('. ').slice(1).join('. ')}</p>
        <pre class="mono" data-copy-source>${d.recoveryCodes.join('\n')}</pre>
        <p><button class="btn" type="button" data-copy>${t('common.copy')}</button></p>
      </section>` : ''}

      ${!d.totpEnabled && !d.enrol ? html`<section class="card">
        <h2>${t('security.enable.title')}</h2>
        <p class="small">${t('security.enable.intro')}</p>
        <form method="post" action="/admin/security/totp/begin">${csrf}<button class="btn btn-primary" type="submit">${t('security.enable.start')}</button></form>
      </section>` : ''}

      ${d.enrol ? html`<section class="card">
        <h2>${t('security.step1')}</h2>
        <div class="row">
          <div class="qr">${raw(d.enrol.qrSvg)}</div>
          <div class="grow small">
            <p>${t('security.manual_key')}</p>
            <p class="mono breakable">${d.enrol.secret.replace(/(.{4})/g, '$1 ').trim()}</p>
            <p class="muted">${t('security.key_params', { issuer: d.issuer, user: d.username })}</p>
            <p><a href="${d.enrol.uri}">${t('security.open_in_app')}</a> ${t('security.on_phone')}</p>
          </div>
        </div>
        <h2>${t('security.step2')}</h2>
        <form method="post" action="/admin/security/totp/confirm" class="row">${csrf}
          <label>${t('security.code_from_app')} <input name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 ]{6,7}" autofocus></label>
          <button class="btn btn-primary" type="submit">${t('security.enable.submit')}</button>
        </form>
        <p class="muted small">${t('security.pending_note')}</p>
      </section>` : ''}

      ${!d.totpEnabled && d.passkeys.length > 0 ? html`<section class="card">
        <h2>${t('security.recovery.title')}</h2>
        <form method="post" action="/admin/security/recovery/regenerate">${csrf}<button class="btn" type="submit">${t('security.recovery.regenerate_confirmed')}</button></form>
      </section>` : ''}

      ${d.totpEnabled ? html`<section class="card">
        <h2>${t('security.recovery.title')}</h2>
        <form method="post" action="/admin/security/totp/recovery" class="row">${csrf}
          <label>${t('security.current_code')} <input name="code" required autocomplete="one-time-code" inputmode="numeric"></label>
          <button class="btn" type="submit">${t('security.regenerate')}</button>
        </form>
      </section>
      <section class="card">
        <h2>${t('security.disable.title')}</h2>
        <p class="small">${raw(t('security.disable.intro', { cmd: '<code>node dist/cli.js disable-totp &lt;user&gt;</code>' }))}</p>
        <form method="post" action="/admin/security/totp/disable" class="row" data-confirm="${t('security.disable.confirm')}">${csrf}
          <label>${t('security.disable.code')} <input name="code" required autocomplete="one-time-code"></label>
          <button class="btn btn-danger" type="submit">${t('security.disable.submit')}</button>
        </form>
      </section>` : ''}

      <section class="card">
        <h2>${t('sessions.title')}</h2>
        <p class="small">${t('sessions.intro')}</p>
        <table>
          <thead><tr><th>${t('sessions.device')}</th><th>${t('sessions.ip')}</th><th>${t('sessions.started')}</th><th>${t('sessions.last_seen')}</th><th></th></tr></thead>
          <tbody>${d.sessions.map((s) => html`<tr>
            <td>${describeUserAgent(s.user_agent) ?? t('sessions.unknown_device')}
              ${s.current ? html`<br><span class="badge">${t('sessions.current')}</span>` : ''}
              ${s.pending ? html`<br><span class="badge badge-pending">${t('sessions.pending')}</span>` : ''}
              ${s.bound ? html`<br><span class="badge badge-active">${t('sessions.bound')}</span>` : ''}
              ${s.second_factor ? html`<br><span class="muted small">${t('sessions.factor', { factor: t(`sessions.via.${s.second_factor}`) })}</span>` : ''}</td>
            <td class="mono">${s.ip ?? '—'}</td><td>${fmtDate(s.created_at, d.lang)}</td><td>${fmtDate(s.last_seen_at, d.lang)}</td>
            <td>${s.current ? '' : html`<form method="post" action="/admin/security/sessions/${s.public_id}/revoke" class="inline">${csrf}<button class="btn btn-small" type="submit">${t('sessions.revoke')}</button></form>`}</td>
          </tr>`)}</tbody>
        </table>
        ${d.sessions.some((s) => !s.current) ? html`<form method="post" action="/admin/security/sessions/revoke-others">${csrf}<button class="btn" type="submit">${t('sessions.revoke_others')}</button></form>` : ''}
      </section>`,
  });
}
