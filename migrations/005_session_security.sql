-- Theft-resistant sessions (0.7.0): passkeys as a second factor, a list of sessions
-- the account can end, re-confirmation before sensitive actions, and sessions bound
-- to the device (DBSC) where the browser supports it.

-- WebAuthn credentials. The public key is SPKI (base64url); nothing secret is stored.
CREATE TABLE admin_passkeys (
  id            TEXT PRIMARY KEY,
  admin_id      TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key    TEXT NOT NULL,
  algorithm     INTEGER NOT NULL,
  sign_count    INTEGER NOT NULL DEFAULT 0,
  name          TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);
CREATE INDEX admin_passkeys_admin_idx ON admin_passkeys(admin_id);

-- public_id names a session in the panel (the cookie value is never shown, and its
-- hash is not handed out either). Sessions from before this migration get one here.
ALTER TABLE sessions ADD COLUMN public_id TEXT;
UPDATE sessions SET public_id = 's_' || lower(hex(randomblob(12))) WHERE public_id IS NULL;
CREATE UNIQUE INDEX sessions_public_id_idx ON sessions(public_id);
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN ip TEXT;
-- How the second factor was passed: 'totp', 'recovery', 'passkey' or NULL (none needed).
ALTER TABLE sessions ADD COLUMN second_factor TEXT;
-- Sensitive actions are allowed until this moment; afterwards the account confirms again.
ALTER TABLE sessions ADD COLUMN confirmed_until TEXT;
-- One pending WebAuthn ceremony per session: its challenge, purpose and deadline.
ALTER TABLE sessions ADD COLUMN webauthn_challenge TEXT;
ALTER TABLE sessions ADD COLUMN webauthn_purpose TEXT;
ALTER TABLE sessions ADD COLUMN webauthn_expires_at TEXT;
-- DBSC: the challenge offered with the registration header, and when it was offered.
ALTER TABLE sessions ADD COLUMN dbsc_challenge TEXT;
ALTER TABLE sessions ADD COLUMN dbsc_offered_at TEXT;

-- A session bound to a device key. Kept in its own rows so that concurrent requests
-- writing to the session can never overwrite the binding.
CREATE TABLE session_bindings (
  id                     TEXT PRIMARY KEY,
  session_hash           TEXT NOT NULL UNIQUE REFERENCES sessions(id_hash) ON DELETE CASCADE,
  alg                    TEXT NOT NULL,
  jwk                    TEXT NOT NULL,
  cookie_hash            TEXT NOT NULL,
  cookie_expires_at      TEXT NOT NULL,
  prev_cookie_hash       TEXT,
  prev_cookie_expires_at TEXT,
  challenge              TEXT,
  challenge_expires_at   TEXT,
  created_at             TEXT NOT NULL,
  refreshed_at           TEXT NOT NULL
);
