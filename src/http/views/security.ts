import { translator, type Lang } from '../../i18n.js';
import { html, layout, raw, type SafeHtml } from '../html.js';

/** Second step of the login: the session exists but the TOTP code is still missing. */
export function totpLoginPage(lang: Lang, opts: { csrfToken: string; error?: string; attemptsLeft?: number; lockedUntil?: string }): string {
  const t = translator(lang);
  return layout({
    lang, title: t('totp.title'), path: '/admin/totp',
    body: html`<section class="card narrow">
      <h1>${t('totp.title')}</h1>
      ${opts.error ? html`<div class="flash flash-error">${opts.error}${opts.attemptsLeft != null ? html` ${t('totp.attempts_left', { n: opts.attemptsLeft })}` : ''}</div>` : ''}
      ${opts.lockedUntil ? html`<div class="flash flash-error">${t('totp.locked_until', { until: opts.lockedUntil.replace('T', ' ').slice(0, 16) })}</div>` : ''}
      <form method="post" action="/admin/totp">
        <input type="hidden" name="_csrf" value="${opts.csrfToken}">
        <label>${t('totp.code_label')}
          <input name="code" required autocomplete="one-time-code" inputmode="numeric" autofocus pattern="[0-9a-zA-Z\\- ]{6,12}">
        </label>
        <button class="btn btn-primary" type="submit">${t('totp.confirm')}</button>
      </form>
      <form method="post" action="/admin/logout" class="inline"><input type="hidden" name="_csrf" value="${opts.csrfToken}"><button class="btn btn-link btn-link-muted" type="submit">${t('totp.cancel_logout')}</button></form>
    </section>`,
  });
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
    scripts: ['/static/admin.js'],
    body: html`
      <section class="card">
        <h1>${t('security.title', { user: d.username })}</h1>
        ${d.error ? html`<div class="flash flash-error">${d.error}</div>` : ''}
        ${d.ok ? html`<div class="flash flash-ok">${d.ok}</div>` : ''}
        ${d.totpRequired && !d.totpEnabled ? html`<div class="warning">${t('security.required_notice')}</div>` : ''}
        <p>${raw(t('security.status', { state: `<strong>${d.totpEnabled ? t('security.enabled') : t('security.disabled')}</strong>` }))}
        ${d.totpEnabled ? raw(t('security.recovery_left', { n: `<strong>${d.recoveryLeft}</strong>` })) : ''}</p>
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
      </section>` : ''}`,
  });
}
