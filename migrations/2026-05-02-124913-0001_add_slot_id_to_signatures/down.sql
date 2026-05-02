-- Remove slot_id column and restore old constraint
-- Note: This is a simplified rollback - in production, handle data carefully

DROP INDEX IF EXISTS idx_signature_slot_id;
DROP INDEX IF EXISTS idx_slot_signature;

-- Recreate the old unique constraint
CREATE UNIQUE INDEX idx_unique_contract_signature ON contract_signatures(contract_id);

-- SQLite doesn't support DROP COLUMN directly - this is a no-op for down migration
-- In a real scenario, you might recreate the table without the column
