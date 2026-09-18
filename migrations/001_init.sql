CREATE TABLE admins (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE sessions (
  id_hash      TEXT PRIMARY KEY,
  admin_id     TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  csrf_token   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at   TEXT NOT NULL
);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE cases (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL CHECK (status IN ('open', 'closed')) DEFAULT 'open',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE links (
  id              TEXT PRIMARY KEY,
  case_id         TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  label           TEXT NOT NULL,
  token_hash      TEXT NOT NULL UNIQUE,
  token_hint      TEXT NOT NULL,            -- first characters of the token, for display only
  expires_at      TEXT,                     -- NULL = never
  revoked_at      TEXT,
  max_file_bytes  INTEGER,                  -- NULL = global limit
  max_files       INTEGER,                  -- NULL = unlimited
  max_total_bytes INTEGER,                  -- NULL = unlimited
  created_at      TEXT NOT NULL,
  last_used_at    TEXT
);
CREATE INDEX links_case_idx ON links(case_id);

CREATE TABLE files (
  id             TEXT PRIMARY KEY,          -- also the storage key and the tus upload id
  case_id        TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  link_id        TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
  original_name  TEXT NOT NULL,
  upload_kind    TEXT NOT NULL CHECK (upload_kind IN ('tus', 'direct')),
  status         TEXT NOT NULL CHECK (status IN ('uploading', 'complete', 'aborted', 'expired', 'missing', 'deleted')),
  declared_size  INTEGER,                   -- size announced by the client (NULL if unknown)
  reserved_bytes INTEGER NOT NULL DEFAULT 0,-- quota reserved while uploading
  size           INTEGER,                   -- final size once complete
  sha256         TEXT,
  client_ip      TEXT,
  created_at     TEXT NOT NULL,
  completed_at   TEXT,
  deleted_at     TEXT
);
CREATE INDEX files_link_idx ON files(link_id, status);
CREATE INDEX files_case_idx ON files(case_id, status);
CREATE INDEX files_status_created_idx ON files(status, created_at);

CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('admin', 'link', 'system')),
  actor_id   TEXT,
  action     TEXT NOT NULL,
  case_id    TEXT,
  link_id    TEXT,
  file_id    TEXT,
  ip         TEXT,
  details    TEXT                          -- JSON
);
CREATE INDEX audit_ts_idx ON audit_log(ts);
