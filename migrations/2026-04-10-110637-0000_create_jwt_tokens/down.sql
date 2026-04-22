-- Drop jwt_tokens table and indexes
DROP INDEX IF EXISTS idx_jwt_tokens_expiry;
DROP INDEX IF EXISTS idx_jwt_tokens_user;
DROP INDEX IF EXISTS idx_jwt_tokens_hash;
DROP TABLE IF EXISTS jwt_tokens;
