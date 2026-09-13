CREATE TABLE sites (
    slug          TEXT PRIMARY KEY,
    title         TEXT NOT NULL DEFAULT '',
    visibility    TEXT NOT NULL CHECK (visibility IN ('open', 'password')),
    password_hash TEXT,
    entry         TEXT NOT NULL DEFAULT 'index.html',
    file_count    INTEGER NOT NULL DEFAULT 0,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    CHECK (visibility != 'password' OR password_hash IS NOT NULL)
);

CREATE INDEX sites_expires_at ON sites (expires_at) WHERE expires_at IS NOT NULL;
