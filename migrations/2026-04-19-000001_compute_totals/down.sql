-- Revert: Add back amount column (will lose computed total precision)

CREATE TABLE invoices_old (
    id TEXT PRIMARY KEY,
    serial_no INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    amount TEXT NOT NULL,  -- Restored as TEXT
    due_date TEXT,
    status TEXT,
    payment_made TEXT,
    line_charges TEXT,
    after_line_items TEXT,
    memo TEXT,
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);

-- Copy data back - note: amount will be empty/default since we don't have stored values anymore
INSERT INTO invoices_old (id, serial_no, customer_id, amount, due_date, status, payment_made, line_charges, after_line_items, memo)
SELECT id, serial_no, customer_id, 
       '0.00',  -- Default since we no longer store amount
       due_date, status, payment_made, line_charges, after_line_items, memo
FROM invoices;

DROP TABLE invoices;
ALTER TABLE invoices_old RENAME TO invoices;
