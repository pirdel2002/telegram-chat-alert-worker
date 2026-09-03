CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_key TEXT NOT NULL UNIQUE,
  source_key TEXT NOT NULL,
  bot_id TEXT NOT NULL,
  direction TEXT NOT NULL,
  sent_at INTEGER NOT NULL,
  payload_cipher TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_time
  ON messages(sent_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_messages_bot_time
  ON messages(bot_id, sent_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_messages_source
  ON messages(source_key);

CREATE TABLE IF NOT EXISTS chat_sources (
  source_key TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL,
  business_connection_id TEXT NOT NULL,
  chat_id TEXT NOT NULL,
  conversation_key TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  log_enabled INTEGER NOT NULL DEFAULT 1,
  label_cipher TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_sources_updated
  ON chat_sources(updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_chat_sources_conversation
  ON chat_sources(conversation_key);
