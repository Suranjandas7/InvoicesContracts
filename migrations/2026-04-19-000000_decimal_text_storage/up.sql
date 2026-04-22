-- Migration: Change invoice amount columns from REAL to TEXT for Decimal precision
-- SQLite doesn't have a native DECIMAL type, so we store Decimal values as TEXT
-- to avoid floating-point precision issues with financial calculations.
-- This makes the database compatible with rust_decimal::Decimal for perfect precision.

-- Create new table with TEXT columns for amounts
CREATE TABLE invoices_new (
    id TEXT PRIMARY KEY,
    serial_no INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    amount TEXT NOT NULL,  -- Changed from REAL to TEXT for Decimal precision
    due_date TEXT,
    status TEXT,
    payment_made TEXT,  -- Changed from REAL to TEXT for Decimal precision
    line_charges TEXT,
    after_line_items TEXT,
    memo TEXT,
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);

-- Copy data from old table, converting REAL to TEXT
INSERT INTO invoices_new (id, serial_no, customer_id, amount, due_date, status, payment_made, line_charges, after_line_items, memo)
SELECT id, serial_no, customer_id, 
       CAST(amount AS TEXT),  -- Convert REAL to TEXT for Decimal storage
       due_date, status, 
       CASE WHEN payment_made IS NOT NULL THEN CAST(payment_made AS TEXT) ELSE NULL END,
       line_charges, after_line_items, memo
FROM invoices;

-- Drop old table and rename new one
DROP TABLE invoices;
ALTER TABLE invoices_new RENAME TO invoices;
