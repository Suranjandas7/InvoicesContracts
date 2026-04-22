-- Revert: Change invoice amount columns back from TEXT to REAL
-- Note: This may introduce precision loss as TEXT Decimal values are converted back to REAL

-- Create old table structure with REAL columns
CREATE TABLE invoices_old (
    id TEXT PRIMARY KEY,
    serial_no INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    amount REAL NOT NULL,
    due_date TEXT,
    status TEXT,
    payment_made REAL DEFAULT 0.0,
    line_charges TEXT,
    after_line_items TEXT,
    memo TEXT,
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);

-- Copy data back, converting TEXT to REAL (may lose precision)
INSERT INTO invoices_old (id, serial_no, customer_id, amount, due_date, status, payment_made, line_charges, after_line_items, memo)
SELECT id, serial_no, customer_id, 
       CAST(amount AS REAL),
       due_date, status, 
       CASE WHEN payment_made IS NOT NULL THEN CAST(payment_made AS REAL) ELSE NULL END,
       line_charges, after_line_items, memo
FROM invoices;

-- Drop new table and rename old one back
DROP TABLE invoices;
ALTER TABLE invoices_old RENAME TO invoices;
