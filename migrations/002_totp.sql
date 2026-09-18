-- Two-factor authentication (TOTP, RFC 6238) for administrators.
ALTER TABLE admins ADD COLUMN totp_secret TEXT;          -- base32 secret; set while pending, kept once enabled
ALTER TABLE admins ADD COLUMN totp_enabled_at TEXT;      -- NULL = 2FA not enabled
ALTER TABLE admins ADD COLUMN totp_last_step INTEGER;    -- last accepted time step (replay protection)

-- A session is created after the password check; it becomes usable for the panel
-- only once totp_verified = 1 (or the admin has no TOTP enabled).
ALTER TABLE sessions ADD COLUMN totp_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN totp_attempts INTEGER NOT NULL DEFAULT 0;

CREATE TABLE admin_recovery_codes (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id  TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at   TEXT
);
CREATE INDEX admin_recovery_codes_admin_idx ON admin_recovery_codes(admin_id);
