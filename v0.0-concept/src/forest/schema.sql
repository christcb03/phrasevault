-- Truth Forest SQLite schema.
-- Applied by db.ts at startup via migrate(). Add new statements at the bottom
-- of the array in db.ts — never modify existing ones.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS truth_nodes (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  label      TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'public',  -- 'public' | 'private' | 'community:<id>'
  payload    TEXT NOT NULL,                   -- plaintext JSON or base64 AES-GCM ciphertext
  created_at INTEGER NOT NULL,
  author     TEXT NOT NULL,
  sig        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS truth_links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,
  child_id      TEXT NOT NULL REFERENCES truth_nodes(id),
  link_type     TEXT NOT NULL,
  truth_score   REAL NOT NULL DEFAULT 1.0,
  sort_key      TEXT,
  score_method  TEXT,
  created_at    INTEGER NOT NULL,
  author        TEXT NOT NULL,
  sig           TEXT NOT NULL,
  removed_at    INTEGER,
  removed_by    TEXT,
  removal_sig   TEXT,
  superseded_by TEXT REFERENCES truth_links(id),
  suspended_at  INTEGER
);

-- Mutable sibling-order index. Maintained by db.insertLink / db.removeLink.
CREATE TABLE IF NOT EXISTS link_sibling_order (
  parent_id    TEXT NOT NULL,
  link_id      TEXT NOT NULL REFERENCES truth_links(id),
  next_link_id TEXT REFERENCES truth_links(id),
  PRIMARY KEY (parent_id, link_id)
);

-- Fast tree traversal
CREATE INDEX IF NOT EXISTS idx_links_parent
  ON truth_links(parent_id)
  WHERE removed_at IS NULL AND suspended_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_links_child
  ON truth_links(child_id)
  WHERE removed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_links_type
  ON truth_links(link_type)
  WHERE removed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_nodes_type
  ON truth_nodes(type);

CREATE INDEX IF NOT EXISTS idx_nodes_visibility
  ON truth_nodes(visibility);

CREATE INDEX IF NOT EXISTS idx_sibling_next
  ON link_sibling_order(next_link_id);
