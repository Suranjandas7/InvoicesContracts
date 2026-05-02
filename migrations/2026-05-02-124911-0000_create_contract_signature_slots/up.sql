-- Create contract signature slots table
-- This defines the signature slots for each contract, supporting multiple signatures
CREATE TABLE contract_signature_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL,
    slot_name TEXT,              -- Optional name like "Manager", "Legal", or NULL
    slot_order INTEGER NOT NULL DEFAULT 0, -- Position (0, 1, 2...) for display/organization
    is_filled BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (contract_id) REFERENCES contracts(id) ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX idx_signature_slot_contract ON contract_signature_slots(contract_id);
CREATE INDEX idx_signature_slot_order ON contract_signature_slots(slot_order);
