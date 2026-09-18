import { html, layout, raw, type SafeHtml } from '../html.js';

/** Second step of the login: the session exists but the TOTP code is still missing. */
export function totpLoginPage(opts: { csrfToken: string; error?: string; attemptsLeft?: number }): string {
  return layout({
    title: 'Drugi składnik',
    body: html`<section class="card narrow">
      <h1>Kod z aplikacji uwierzytelniającej</h1>
      ${opts.error ? html`<div class="flash flash-error">${opts.error}${opts.attemptsLeft != null ? html` Pozostałe próby: ${opts.attemptsLeft}.` : ''}</div>` : ''}
      <form method="post" action="/admin/totp">
        <input type="hidden" name="_csrf" value="${opts.csrfToken}">
        <label>Kod (6 cyfr) lub kod zapasowy
          <input name="code" required autocomplete="one-time-code" inputmode="numeric" autofocus pattern="[0-9a-zA-Z\\- ]{6,12}">
        </label>
        <button class="btn btn-primary" type="submit">Potwierdź</button>
      </form>
      <form method="post" action="/admin/logout" class="inline"><input type="hidden" name="_csrf" value="${opts.csrfToken}"><button class="btn btn-link" type="submit" style="color:#6b7280">Anuluj i wyloguj</button></form>
    </section>`,
  });
}

export interface SecurityPageData {
  csrfToken: string;
  username: string;
  nav: SafeHtml;
  totpEnabled: boolean;
  totpRequired: boolean;
  recoveryLeft: number;
  /** Enrolment in progress: QR (SVG markup produced by the qrcode library) + secret for manual entry. */
  enrol?: { qrSvg: string; secret: string; uri: string };
  /** Freshly generated recovery codes, shown once. */
  recoveryCodes?: string[];
  error?: string;
  ok?: string;
}

export function securityPage(d: SecurityPageData): string {
  const csrf = html`<input type="hidden" name="_csrf" value="${d.csrfToken}">`;
  return layout({
    title: 'Bezpieczeństwo',
    nav: d.nav,
    scripts: ['/static/admin.js'],
    body: html`
      <section class="card">
        <h1>Bezpieczeństwo konta „${d.username}”</h1>
        ${d.error ? html`<div class="flash flash-error">${d.error}</div>` : ''}
        ${d.ok ? html`<div class="flash flash-ok">${d.ok}</div>` : ''}
        ${d.totpRequired && !d.totpEnabled ? html`<div class="warning">Ta instancja wymaga uwierzytelniania dwuskładnikowego. Do czasu włączenia TOTP panel jest niedostępny.</div>` : ''}
        <p>Uwierzytelnianie dwuskładnikowe (TOTP, RFC 6238): <strong>${d.totpEnabled ? 'włączone' : 'wyłączone'}</strong>.
        ${d.totpEnabled ? html`Niewykorzystane kody zapasowe: <strong>${d.recoveryLeft}</strong>.` : ''}</p>
      </section>

      ${d.recoveryCodes ? html`<section class="card highlight">
        <h2>Kody zapasowe</h2>
        <p><strong>Zapisz je teraz w bezpiecznym miejscu.</strong> Każdy działa jeden raz i zastępuje kod z aplikacji, gdy stracisz do niej dostęp. Nie będą pokazane ponownie.</p>
        <pre class="mono" data-copy-source>${d.recoveryCodes.join('\n')}</pre>
        <p><button class="btn" type="button" data-copy>Kopiuj</button></p>
      </section>` : ''}

      ${!d.totpEnabled && !d.enrol ? html`<section class="card">
        <h2>Włącz TOTP</h2>
        <p class="small">Potrzebna jest aplikacja uwierzytelniająca (np. Aegis, Google Authenticator, 1Password, Bitwarden). Po włączeniu logowanie wymaga hasła i bieżącego kodu.</p>
        <form method="post" action="/admin/security/totp/begin">${csrf}<button class="btn btn-primary" type="submit">Rozpocznij konfigurację</button></form>
      </section>` : ''}

      ${d.enrol ? html`<section class="card">
        <h2>Krok 1: zeskanuj kod w aplikacji</h2>
        <div class="row">
          <div class="qr">${raw(d.enrol.qrSvg)}</div>
          <div class="grow small">
            <p>Albo wpisz klucz ręcznie:</p>
            <p class="mono" style="word-break:break-all">${d.enrol.secret.replace(/(.{4})/g, '$1 ').trim()}</p>
            <p class="muted">Typ: TOTP, SHA-1, 6 cyfr, 30 s. Wystawca: inletbox, konto: ${d.username}.</p>
            <p><a href="${d.enrol.uri}">Otwórz w aplikacji uwierzytelniającej</a> (na telefonie)</p>
          </div>
        </div>
        <h2>Krok 2: potwierdź kodem</h2>
        <form method="post" action="/admin/security/totp/confirm" class="row">${csrf}
          <label>Kod z aplikacji <input name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 ]{6,7}" autofocus></label>
          <button class="btn btn-primary" type="submit">Włącz TOTP</button>
        </form>
        <p class="muted small">Klucz jest tymczasowy do czasu potwierdzenia; ponowne rozpoczęcie konfiguracji generuje nowy.</p>
      </section>` : ''}

      ${d.totpEnabled ? html`<section class="card">
        <h2>Kody zapasowe</h2>
        <form method="post" action="/admin/security/totp/recovery" class="row">${csrf}
          <label>Bieżący kod z aplikacji <input name="code" required autocomplete="one-time-code" inputmode="numeric"></label>
          <button class="btn" type="submit">Wygeneruj nowe kody (stare przestaną działać)</button>
        </form>
      </section>
      <section class="card">
        <h2>Wyłącz TOTP</h2>
        <p class="small">Wymaga bieżącego kodu z aplikacji albo kodu zapasowego: sama sesja (np. skradzione ciasteczko) nie wystarczy. Gdy dostęp do aplikacji i kodów zapasowych jest utracony, operator może użyć <code>node dist/cli.js disable-totp &lt;użytkownik&gt;</code> na serwerze.</p>
        <form method="post" action="/admin/security/totp/disable" class="row" data-confirm="Wyłączyć uwierzytelnianie dwuskładnikowe?">${csrf}
          <label>Kod <input name="code" required autocomplete="one-time-code"></label>
          <button class="btn btn-danger" type="submit">Wyłącz</button>
        </form>
      </section>` : ''}`,
  });
}
