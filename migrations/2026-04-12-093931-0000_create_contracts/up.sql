-- Create contracts table
CREATE TABLE contracts (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    contract_type TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);

-- Create contract signatures table
CREATE TABLE contract_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    contract_id TEXT NOT NULL,
    verification_code TEXT NOT NULL UNIQUE,
    signature_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    signed_at TEXT NOT NULL,
    signer_name TEXT,
    client_ip TEXT,
    user_agent TEXT,
    FOREIGN KEY (contract_id) REFERENCES contracts(id)
);

-- Create indexes for better query performance
CREATE INDEX idx_contract_customer ON contracts(customer_id);
CREATE INDEX idx_signature_contract ON contract_signatures(contract_id);
CREATE INDEX idx_signature_verification ON contract_signatures(verification_code);
