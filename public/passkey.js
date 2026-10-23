/* Passkeys: registration, sign-in (second step) and confirmation. No libraries:
 * WebAuthn wants ArrayBuffers, the server speaks base64url. Buttons carry their
 * endpoints in data-* attributes; messages come from the server in data-* too. */
(function () {
  'use strict';
  function toB64url(buf) {
    var s = '', bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromB64url(s) {
    var b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    var out = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
    return out.buffer;
  }
  function post(url, fields) {
    var body = new URLSearchParams(fields);
    return fetch(url, { method: 'POST', body: body, credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { return r.json().catch(function () { return { error: r.statusText }; }); });
  }
  function show(btn, msg) {
    var out = document.getElementById(btn.getAttribute('data-status') || '');
    if (out) { out.textContent = msg; out.hidden = !msg; }
  }
  function follow(res) {
    if (res.redirect) { window.location.assign(res.redirect); return true; }
    return false;
  }

  document.querySelectorAll('[data-passkey]').forEach(function (btn) {
    if (!window.PublicKeyCredential) { btn.disabled = true; show(btn, btn.getAttribute('data-unsupported') || ''); return; }
    btn.hidden = false;
    btn.addEventListener('click', function () {
      var kind = btn.getAttribute('data-passkey');
      var csrf = btn.getAttribute('data-csrf');
      var failed = btn.getAttribute('data-failed') || 'Failed';
      btn.disabled = true; show(btn, '');
      post(btn.getAttribute('data-options'), { _csrf: csrf }).then(function (opt) {
        if (follow(opt)) return null;
        if (opt.error) throw new Error(opt.error);
        if (kind === 'register') {
          return navigator.credentials.create({ publicKey: {
            challenge: fromB64url(opt.challenge),
            rp: { id: opt.rpId, name: opt.rpName },
            user: { id: fromB64url(opt.userId), name: opt.userName, displayName: opt.userName },
            pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
            excludeCredentials: opt.exclude.map(function (id) { return { type: 'public-key', id: fromB64url(id) }; }),
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
            attestation: 'none', timeout: opt.timeout,
          } }).then(function (cred) {
            var r = cred.response;
            if (!r.getPublicKey || !r.getAuthenticatorData) throw new Error(btn.getAttribute('data-unsupported') || failed);
            var nameInput = document.getElementById(btn.getAttribute('data-name-input') || '');
            return post(btn.getAttribute('data-submit'), {
              _csrf: csrf, name: nameInput ? nameInput.value : '',
              credential_id: toB64url(cred.rawId), client_data: toB64url(r.clientDataJSON),
              authenticator_data: toB64url(r.getAuthenticatorData()), public_key: toB64url(r.getPublicKey()),
              algorithm: String(r.getPublicKeyAlgorithm()),
            });
          });
        }
        return navigator.credentials.get({ publicKey: {
          challenge: fromB64url(opt.challenge), rpId: opt.rpId, timeout: opt.timeout, userVerification: 'preferred',
          allowCredentials: opt.allow.map(function (id) { return { type: 'public-key', id: fromB64url(id) }; }),
        } }).then(function (cred) {
          var r = cred.response;
          return post(btn.getAttribute('data-submit'), {
            _csrf: csrf, credential_id: toB64url(cred.rawId), client_data: toB64url(r.clientDataJSON),
            authenticator_data: toB64url(r.authenticatorData), signature: toB64url(r.signature),
          });
        });
      }).then(function (res) {
        if (!res) return;
        if (follow(res)) return;
        throw new Error(res.error || failed);
      }).catch(function (err) {
        btn.disabled = false;
        // The user closing the browser dialog is not worth an alarming message.
        show(btn, err && err.name === 'NotAllowedError' ? (btn.getAttribute('data-cancelled') || failed) : (err && err.message) || failed);
      });
    });
  });
})();
