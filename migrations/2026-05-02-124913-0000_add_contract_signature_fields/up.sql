-- Add fields to contracts table for tracking multiple signatures
ALTER TABLE contracts ADD COLUMN required_signatures INTEGER NOT NULL DEFAULT 1;
ALTER TABLE contracts ADD COLUMN completed_signatures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE contracts ADD COLUMN final_hash TEXT;
