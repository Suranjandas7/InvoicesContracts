-- Remove fields from contracts table
-- Note: SQLite doesn't support DROP COLUMN directly, we need to recreate the table
-- This is a simplified down migration - in production, handle data preservation
CREATE TABLE contracts_backup (
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

INSERT INTO contracts_backup SELECT id, customer_id, contract_type, title, content, created_at, expires_at, status FROM contracts;
DROP TABLE contracts;
ALTER TABLE contracts_backup RENAME TO contracts;

-- Recreate indexes
CREATE INDEX idx_contract_customer ON contracts(customer_id);
