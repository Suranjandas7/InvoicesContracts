-- Initial schema with all tables

CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL DEFAULT '',
    tax_id TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT ''
);

CREATE TABLE customer (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT,
    currency TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE invoices (
    id TEXT PRIMARY KEY,
    serial_no INTEGER NOT NULL,
    customer_id TEXT NOT NULL,
    amount REAL NOT NULL,
    due_date TEXT,
    status TEXT,
    payment_made REAL DEFAULT 0.0,
    FOREIGN KEY (customer_id) REFERENCES customer(id)
);
