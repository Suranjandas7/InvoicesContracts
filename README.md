Invoices&Contracts App
v0.1.0

A hobby project made in order to discover and learn 
how to write a somehwat non-trivial web app using Rust and Axum.

Features include:

* User authentication with JWT access tokens and refresh tokens.
* Rate limiting for login and sensitive operations to prevent brute force attacks.
* First-time admin user setup with secure bcrypt password hashing.
* User profile management with editable name, email, address, tax ID, and password changes.
* Customer management with full CRUD operations.
* Invoice generation and management with line items, after-line items for taxes and discounts, payment tracking with precise decimal arithmetic, and dynamic total calculation.
* Invoice viewing with formatted display of company and customer details.
* Contract management with CRUD operations, status tracking, and expiration dates.
* Digital contract signing with cryptographic signatures using ECDSA.
* Contract verification with tamper detection using stored content hashes.
* Signature proof generation and download for signed contracts.
* Public contract signing interface secured by customer UUID verification.
* SQLite database with Diesel ORM for data persistence.
* Secure session management with HTTP-only and secure cookies.
* Timing attack prevention on authentication to prevent email enumeration.

Updates that can be applied to this: integrate payments and share invoices automatically, better UI.

@2026
