-- Migration: Remove stored amount column - totals are now computed from line items
-- This eliminates rounding errors from stored totals getting out of sync with line items

-- Create new table without amount column (computed dynamically from line_charges)
CREATE TABLE invoices_new (
    id TEXT PRIMARY KEY,
    serial_no INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    due_date TEXT,
    status TEXT,
    payment_made TEXT,  -- Kept as TEXT for precise payment tracking (nullable)
    line_charges TEXT,  -- JSON: {"Description": 100.00} - source of truth for amounts
    after_line_items TEXT,  -- JSON: {"Tax": 0.215} - percentages applied to subtotal
    memo TEXT,
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);

-- Copy data from old table
INSERT INTO invoices_new (id, serial_no, customer_id, due_date, status, payment_made, line_charges, after_line_items, memo)
SELECT id, serial_no, customer_id, due_date, status, 
       CASE WHEN payment_made IS NOT NULL THEN CAST(payment_made AS TEXT) ELSE NULL END,
       line_charges, after_line_items, memo
FROM invoices;

-- Drop old table and rename new one
DROP TABLE invoices;
ALTER TABLE invoices_new RENAME TO invoices;
