/**
 * Mailboxer SQLite Database Schema & DDL
 *
 * Defines the relational schema, performance indexes, and inverted token search index
 * using Node.js 22 built-in node:sqlite (DatabaseSync) with zero external dependencies.
 *
 * @module storage/schema
 */

export const SCHEMA_VERSION = 1;

/**
 * SQLite Pragmas for concurrency, integrity, and performance.
 */
export const PRAGMAS_SQL = `
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
`;

/**
 * Core relational tables: accounts, folders, messages, message_search_index.
 */
export const CREATE_TABLES_SQL = `
-- 1. Accounts Table (User profiles and connection identities)
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  name TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- 2. Folders Table (IMAP mailboxes and synchronization checkpoints)
CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  delimiter TEXT DEFAULT '/',
  flags TEXT DEFAULT '[]',
  uidvalidity INTEGER,
  uidnext INTEGER,
  total_messages INTEGER DEFAULT 0,
  unseen_messages INTEGER DEFAULT 0,
  last_synced_at TEXT,
  sync_status TEXT DEFAULT 'IDLE',
  sync_error TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(account_id, path)
);

-- 3. Messages Table (Email headers, snippets, flags, thread IDs)
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  uid INTEGER NOT NULL,
  message_id TEXT,
  thread_id TEXT,
  sender TEXT NOT NULL,
  sender_email TEXT NOT NULL,
  recipients TEXT DEFAULT '[]',
  subject TEXT NOT NULL,
  date TEXT NOT NULL,
  body_snippet TEXT,
  flags TEXT DEFAULT '[]',
  is_seen INTEGER DEFAULT 0,
  is_flagged INTEGER DEFAULT 0,
  size INTEGER DEFAULT 0,
  category TEXT DEFAULT 'uncategorized',
  triage_score REAL DEFAULT 0.0,
  is_noise INTEGER DEFAULT 0,
  triage_reason TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(folder_id, uid)
);

-- 4. Full-Text Search Inverted Token Index Table (Zero-dependency FTS alternative)
CREATE TABLE IF NOT EXISTS message_search_index (
  token TEXT NOT NULL,
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  field TEXT NOT NULL,
  PRIMARY KEY (token, message_id, field)
) WITHOUT ROWID;

-- 5. Triage Rules Table (Anti-noise and classification rules)
CREATE TABLE IF NOT EXISTS triage_rules (
  id TEXT PRIMARY KEY,
  account_id TEXT,
  name TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  conditions TEXT,
  pattern TEXT,
  header TEXT,
  target_category TEXT,
  category TEXT NOT NULL CHECK(category IN ('VIP', 'UPDATE', 'NOISE', 'NORMAL')),
  action TEXT NOT NULL DEFAULT 'none' CHECK(action IN ('notify', 'badge', 'mute', 'none')),
  is_enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- 6. Full Message Bodies (fetched on demand when a message is opened)
CREATE TABLE IF NOT EXISTS message_bodies (
  message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  text_body TEXT,
  html_body TEXT,
  attachments TEXT DEFAULT '[]',
  headers TEXT DEFAULT '{}',
  fetched_at TEXT DEFAULT (datetime('now'))
);

-- 7. Web Push Subscriptions Table
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  user_agent TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT DEFAULT (datetime('now'))
);
`;

/**
 * High-performance B-tree indexes for ordering, filtering, and triage.
 */
export const CREATE_INDEXES_SQL = `
CREATE INDEX IF NOT EXISTS idx_messages_folder_uid ON messages(folder_id, uid);
CREATE INDEX IF NOT EXISTS idx_messages_account_date ON messages(account_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_messages_folder_date ON messages(folder_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_email ON messages(sender_email);
CREATE INDEX IF NOT EXISTS idx_messages_flags ON messages(folder_id, is_seen, is_flagged);
CREATE INDEX IF NOT EXISTS idx_messages_category ON messages(account_id, category);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date DESC);
CREATE INDEX IF NOT EXISTS idx_search_token ON message_search_index(token, message_id);
CREATE INDEX IF NOT EXISTS idx_search_msg_id ON message_search_index(message_id);
CREATE INDEX IF NOT EXISTS idx_triage_rules_priority ON triage_rules(is_enabled, priority ASC);
CREATE INDEX IF NOT EXISTS idx_push_subs_endpoint ON push_subscriptions(endpoint);
`;

/**
 * Initializes the database schema and enables required PRAGMAs.
 *
 * @param {import('node:sqlite').DatabaseSync} db - Active DatabaseSync instance
 */
export function initSchema(db) {
  if (!db) {
    throw new TypeError('DatabaseSync instance is required to initialize schema');
  }

  // Set PRAGMAs
  db.exec('PRAGMA foreign_keys = ON;');
  try {
    db.exec('PRAGMA journal_mode = WAL;');
  } catch {
    // In-memory or read-only databases may not support WAL mode
  }
  db.exec('PRAGMA synchronous = NORMAL;');
  db.exec('PRAGMA busy_timeout = 5000;');

  // Create tables and indexes
  db.exec(CREATE_TABLES_SQL);
  db.exec(CREATE_INDEXES_SQL);

  // Safe non-destructive column migrations for existing databases
  try {
    db.exec('ALTER TABLE messages ADD COLUMN triage_reason TEXT;');
  } catch {
    // Column already exists or table freshly created
  }
}

/**
 * Tokenizes text into search index tokens.
 * Extracts alphanumeric words and email components, lowercases them,
 * and discards tokens shorter than 2 characters.
 *
 * @param {string} text - Input text (e.g. subject, body snippet, sender)
 * @returns {string[]} Unique array of lowercase tokens
 */
export function tokenize(text) {
  if (!text || typeof text !== 'string') return [];

  const lower = text.toLowerCase();
  // Split on any character that is not a letter, digit, underscore, hyphen, or at-sign
  const rawTokens = lower.split(/[^a-z0-9@_.-]+/);
  const result = new Set();

  for (const raw of rawTokens) {
    const trimmed = raw.replace(/^[._-]+|[._-]+$/g, '');
    if (trimmed.length >= 2) {
      result.add(trimmed);

      // If token is an email address, also index username and domain parts
      if (trimmed.includes('@')) {
        const parts = trimmed.split('@');
        for (const p of parts) {
          const sub = p.replace(/^[._-]+|[._-]+$/g, '');
          if (sub.length >= 2) result.add(sub);
        }
      }
    }
  }

  return Array.from(result);
}
