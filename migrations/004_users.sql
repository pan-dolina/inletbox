-- Accounts get a role. 'admin' manages accounts, reads the audit log and sees
-- every case; 'user' sees only the cases they are assigned to. Every account that
-- existed before this migration was a full administrator, and stays one.
ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'user'));
-- A disabled account cannot sign in and loses its sessions, but keeps its history.
ALTER TABLE admins ADD COLUMN disabled_at TEXT;
-- Set when an administrator issued the password: the owner must replace it first.
ALTER TABLE admins ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN last_login_at TEXT;

-- Who may work on which case. Administrators need no rows here.
CREATE TABLE case_members (
  case_id    TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  admin_id   TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (case_id, admin_id)
);
CREATE INDEX case_members_admin_idx ON case_members(admin_id);
