-- Drop the contract_signature_slots table
DROP INDEX IF EXISTS idx_signature_slot_order;
DROP INDEX IF EXISTS idx_signature_slot_contract;
DROP TABLE IF EXISTS contract_signature_slots;
