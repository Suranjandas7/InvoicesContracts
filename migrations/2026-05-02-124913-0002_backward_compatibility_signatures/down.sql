-- Reverse backward compatibility migration
-- Note: This is a simplified rollback - data may not be perfectly restored

-- Remove signature slots (this will cascade delete relationships)
DELETE FROM contract_signature_slots;

-- Reset contract signature counts
UPDATE contracts SET 
    required_signatures = 1,
    completed_signatures = 0,
    final_hash = NULL;

-- Remove slot_id references
UPDATE contract_signatures SET slot_id = NULL;
