-- Applied in the transaction of a bucket's first write, so every statement
-- must be safe to run inside one, and to run again.

-- A SQLite Archive (https://sqlite.org/sqlar.html), so `sqlite3 bucket.sqlite3
-- -Atv` lists the objects and `-Ax` extracts them. featherd stores data
-- uncompressed (sz = length(data)) and reads zlib-compressed rows written by
-- other tools. Only regular files are objects; directory and symlink entries
-- are ignored.
CREATE TABLE IF NOT EXISTS sqlar(
    name  TEXT PRIMARY KEY,
    mode  INT,
    mtime INT,
    sz    INT,
    data  BLOB
);

-- S3 metadata the archive has no column for. sha256 is the raw 32-byte digest
-- of the uncompressed data; the served ETag is derived from it. An archive
-- entry without a row here, e.g. one added by `sqlite3 -A`, is served with an
-- ETag computed from its data, the default content type and its mtime.
CREATE TABLE IF NOT EXISTS content_meta (
    name         TEXT PRIMARY KEY,
    sha256       BLOB NOT NULL CHECK (typeof(sha256) = 'blob' AND length(sha256) = 32),
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream'
);

-- Any write to an archive entry, including one by another tool, drops its
-- metadata so a stale ETag is never served. featherd writes the metadata after
-- the entry. `REPLACE INTO sqlar`, as `sqlite3 -A` uses, fires the insert
-- trigger.
CREATE TRIGGER IF NOT EXISTS sqlar_insert_drops_meta AFTER INSERT ON sqlar
BEGIN DELETE FROM content_meta WHERE name = new.name; END;
CREATE TRIGGER IF NOT EXISTS sqlar_update_drops_meta AFTER UPDATE ON sqlar
BEGIN DELETE FROM content_meta WHERE name = old.name; END;
CREATE TRIGGER IF NOT EXISTS sqlar_delete_drops_meta AFTER DELETE ON sqlar
BEGIN DELETE FROM content_meta WHERE name = old.name; END;
