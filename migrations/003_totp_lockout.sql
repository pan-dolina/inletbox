-- Per-account second-factor brute-force protection (independent of client IP and session).
ALTER TABLE admins ADD COLUMN totp_failed_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN totp_locked_until TEXT;
