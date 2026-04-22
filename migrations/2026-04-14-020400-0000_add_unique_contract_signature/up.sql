-- Add UNIQUE constraint to prevent duplicate contract signatures
-- This prevents race conditions where two concurrent requests could sign the same contract
CREATE UNIQUE INDEX idx_unique_contract_signature ON contract_signatures(contract_id);
