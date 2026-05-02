-- Add slot_id column to contract_signatures
ALTER TABLE contract_signatures ADD COLUMN slot_id INTEGER;

-- Add foreign key reference (SQLite doesn't enforce FKs but good to document)
-- Note: We'll need to update existing rows to have valid slot_id before adding NOT NULL

-- Drop the old unique constraint that prevented multiple signatures per contract
DROP INDEX IF EXISTS idx_unique_contract_signature;

-- Create new unique constraint on slot_id (prevents duplicate signatures per slot)
-- This handles race conditions where two requests try to sign the same slot
CREATE UNIQUE INDEX idx_slot_signature ON contract_signatures(slot_id);

-- Create index for faster lookups
CREATE INDEX idx_signature_slot_id ON contract_signatures(slot_id);
