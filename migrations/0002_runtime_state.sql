CREATE TABLE IF NOT EXISTS runtime_status (
  bot_id TEXT PRIMARY KEY,
  payload_cipher TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_cooldowns (
  bot_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (bot_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_rule_cooldowns_expiry
  ON rule_cooldowns(expires_at);

CREATE TABLE IF NOT EXISTS app_migrations (
  name TEXT PRIMARY KEY,
  completed_at INTEGER NOT NULL
);
