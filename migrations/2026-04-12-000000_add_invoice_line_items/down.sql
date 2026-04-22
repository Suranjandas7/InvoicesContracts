-- SQLite does not support DROP COLUMN in versions prior to 3.35.
-- To roll back, recreate the table without the two new columns:
CREATE TABLE invoices_backup (
    id TEXT PRIMARY KEY,
    serial_no INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    amount REAL NOT NULL,
    due_date TEXT,
    status TEXT,
    payment_made REAL DEFAULT 0.0,
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);
INSERT INTO invoices_backup SELECT id, serial_no, customer_id, amount, due_date, status, payment_made FROM invoices;
DROP TABLE invoices;
ALTER TABLE invoices_backup RENAME TO invoices;
