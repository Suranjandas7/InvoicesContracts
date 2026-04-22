# Rules of Rust - Axom App Codebase - FOR AI EYES

*Quick reference for maintaining code quality and security patterns*

---

## 1. Database Queries

### ✅ DO: Use RETURNING Clause (Eliminate N+1)
```rust
// Good: Single query
let id = diesel::insert_into(table)
    .values(&data)
    .returning(user::id)
    .get_result(&mut conn)
    .await?;
```

### ❌ DON'T: Execute Then Select
```rust
// Bad: Two queries
.execute(&mut conn).await?;  // Insert
.select(id).order(id.desc()).first(&mut conn).await?;  // Then select
```

---

## 2. Input Validation

### ✅ DO: Validate All User Input
```rust
const MAX_NAME_LEN: usize = 200;
const MAX_EMAIL_LEN: usize = 255;

if payload.name.len() > MAX_NAME_LEN {
    return (StatusCode::PAYLOAD_TOO_LARGE, "...").into_response();
}

// Also validate format
if !payload.email.contains('@') {
    return (StatusCode::BAD_REQUEST, "Invalid email").into_response();
}
```

### ❌ DON'T: Accept Unbounded Strings
- Never accept arbitrary-length strings without limits
- DoS vector via memory exhaustion

**Standard Limits:**
- Names: 200 chars
- Emails: 255 chars  
- Addresses: 1000 chars
- Content: 1MB max
- Passwords: 8-128 chars

---

## 3. Error Handling

### ✅ DO: Use Proper Error Types + Log
```rust
.map_err(|e| {
    tracing::error!("Database error: {}", e);
    StatusCode::INTERNAL_SERVER_ERROR
})?
```

### ❌ DON'T: Swallow Errors
```rust
// Bad - loses context
.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
```

### ❌ NEVER: Use unwrap() in Production Code
```rust
// Forbidden in production paths
let user = result.unwrap();  // PANIC RISK!
```

### ✅ DO: Use expect() Only at Startup
```rust
// OK for startup configuration (fail-fast)
let pool = create_pool().expect("Failed to create database pool");
```

---

## 4. Async Patterns

### ✅ DO: Use tokio::sync::RwLock
```rust
use tokio::sync::RwLock;

let read = lock.read().await;  // Non-blocking
let write = lock.write().await;
```

### ❌ DON'T: Use std::sync::RwLock in Async
```rust
// Blocks executor thread - bad for async
use std::sync::RwLock;  // WRONG in async code
```

---

## 5. Security

### Timing Attack Prevention
```rust
// Always verify password even for non-existent users
let (hash, user_exists) = match user {
    Some(u) => (u.password.as_str(), true),
    None => (get_dummy_hash(), false),  // Dummy hash
};
let valid = verify_password(input, hash)? && user_exists;
```

### JWT Revocation Check
```rust
// Always check database revoked flag after decode
let token_data = decode_jwt(token, config)?;
if is_jwt_revoked(pool, token_data.claims.jti).await? {
    return Err(AuthError::TokenRevoked);
}
```

### Rate Limiting
```rust
// Apply to all auth endpoints BEFORE expensive ops
if rate_limiter.check_rate_limit(ip).await.is_err() {
    return (StatusCode::TOO_MANY_REQUESTS, ...);
}
// ... then do password verification, etc.
```

---

## 6. Database Patterns

### Connection Pool Limits
```rust
// Always set max size
Pool::builder()
    .max_size(10)  // Prevent resource exhaustion
    .build(manager)?;
```

### Race Condition Prevention
```rust
// Use UNIQUE constraints at database level
diesel::insert_into(signatures)
    .values(&signature)
    .execute(&mut conn)  // Will fail with UNIQUE violation
// Handle 409 Conflict for duplicates
```

---

## 7. Logging

### ✅ DO: Use tracing (Structured Logging)
```rust
tracing::error!("Database connection failed: {}", e);
tracing::info!("User {} logged in", user_id);
tracing::debug!("Processing request: {:?}", request);
```

### ❌ DON'T: Use eprintln! in Production
```rust
// Bad - unstructured, can't filter via RUST_LOG
eprintln!("Error: {}", e);  // AVOID
```

---

## 8. Cryptography

### Password Hashing
```rust
// Use bcrypt with default cost (12)
let hash = hash(password, bcrypt::DEFAULT_COST)?;  // ~50-300ms
```

### Token Generation
```rust
// High entropy for verification codes (min 60 bits)
let code = generate_random_string(12);  // ~60 bits entropy
```

---

## 9. Cookie Security

```rust
let mut cookie = Cookie::new(name, value);
cookie.set_http_only(true);     // Prevent XSS
cookie.set_secure(true);        // HTTPS only
cookie.set_same_site(SameSite::Strict);  // CSRF protection
cookie.set_path("/");
```

---

## 10. Quick Checklist

Before committing code, verify:

- [ ] No `unwrap()` in production paths (only `expect()` at startup)
- [ ] All user inputs have length validation
- [ ] Database queries use `RETURNING` not separate SELECT
- [ ] Errors are logged with `tracing` before mapping to HTTP codes
- [ ] Rate limiting applied to auth endpoints
- [ ] Using `tokio::sync::RwLock` not `std::sync::RwLock`
- [ ] Cookies have `http_only`, `secure`, `same_site(Strict)`
- [ ] Password verification uses timing-safe pattern
- [ ] Connection pool has `max_size()` configured

---
