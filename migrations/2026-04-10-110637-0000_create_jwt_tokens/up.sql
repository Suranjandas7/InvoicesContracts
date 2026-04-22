-- Create jwt_tokens table for tracking issued tokens
CREATE TABLE jwt_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_jwt_tokens_hash ON jwt_tokens(token_hash);
CREATE INDEX idx_jwt_tokens_user ON jwt_tokens(user_id);
CREATE INDEX idx_jwt_tokens_expiry ON jwt_tokens(expires_at);
