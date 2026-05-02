-- Backward compatibility migration: Convert existing contracts to use new signature slots

-- Step 1: Create signature slots for existing contracts
-- For each existing contract, create slots based on current status:
-- - If status='signed', create 1 slot marked as filled
-- - If status='pending', create 1 slot not filled (awaiting signature)
INSERT INTO contract_signature_slots (contract_id, slot_name, slot_order, is_filled)
SELECT 
    id,
    NULL as slot_name,           -- Legacy signatures have no name
    0 as slot_order,             -- Single slot at position 0
    CASE WHEN status = 'signed' THEN 1 ELSE 0 END as is_filled
FROM contracts;

-- Step 2: Link existing signatures to their slots
-- Update each signature to reference its corresponding slot
UPDATE contract_signatures
SET slot_id = (
    SELECT id 
    FROM contract_signature_slots 
    WHERE contract_signature_slots.contract_id = contract_signatures.contract_id
    LIMIT 1
)
WHERE slot_id IS NULL;

-- Step 3: Update contracts table with signature counts
-- Set required_signatures=1 and completed_signatures based on status
UPDATE contracts
SET 
    required_signatures = 1,
    completed_signatures = CASE WHEN status = 'signed' THEN 1 ELSE 0 END;

-- Step 4: Generate final_hash for already-signed contracts
-- For contracts that are already signed, create a final hash combining all signatures
-- Note: This is done in application code during startup or migration script
-- The final_hash field will remain NULL until the multi-signature feature is fully active
