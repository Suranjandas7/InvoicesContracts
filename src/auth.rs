// NOTE: refactor to be more general

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use bcrypt::verify;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8;
use jsonwebtoken::{decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{JwtConfig, COOKIE_NAME, REFRESH_COOKIE_NAME};
use crate::db::DbPool;
use crate::models::{Claims, CreateJwtToken, CreateRefreshToken, RefreshToken, User};
use crate::schema::{jwt_tokens, refresh_tokens, user};

// ── Unified Error Type ───────────────────────────────────────────────────────

/// Unified authentication error type for consistent error handling across the auth module.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[error("Database pool error: {0}")]
    Pool(String),

    #[error("JWT encoding/decoding error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Password verification error: {0}")]
    PasswordVerification(#[from] bcrypt::BcryptError),

    #[error("User not found: {0}")]
    UserNotFound(String),
}

impl From<bb8::RunError> for AuthError {
    fn from(e: bb8::RunError) -> Self {
        AuthError::Pool(e.to_string())
    }
}

// Verify password against hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    Ok(verify(password, hash)?)
}

/// NOTE: This returns a dummy bcrypt hash for timing attack prevention.
/// The hash is a pre-computed bcrypt hash of a dummy value. It doesn't matter what
/// the hash is or what it verifies against - it only needs to be a valid bcrypt hash
/// that takes the same time to verify as a real user's password hash.
pub fn get_dummy_hash() -> &'static str {
    // Pre-computed bcrypt hash: bcrypt::hash("dummy_password_for_timing_attack_prevention", 12)
    "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5KeJKj8v7W5uK"
}

// Generate JWT token
pub fn generate_jwt(user_id: i32, email: &str, config: &JwtConfig) -> Result<String, AuthError> {
    let now = Utc::now();
    let expiry = now + Duration::seconds(config.expiry_seconds());

    let claims = Claims {
        user_id,
        email: email.to_string(),
        exp: expiry.timestamp(),
        iat: now.timestamp(),
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )?)
}

// Decode and validate JWT token
pub fn decode_jwt(token: &str, config: &JwtConfig) -> Result<Claims, AuthError> {
    let validation = Validation::default();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}

// Hash token for storage (SHA-256)
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// Store JWT in database
pub async fn store_jwt(pool: &DbPool, user_id: i32, token: &str) -> Result<(), AuthError> {
    let mut conn = pool.get().await?;
    let token_hash = hash_token(token);
    let config = JwtConfig::new();

    let now = Utc::now();
    let expiry = now + Duration::seconds(config.expiry_seconds());

    let new_token = CreateJwtToken {
        user_id,
        token_hash,
        expires_at: expiry.to_rfc3339(),
        created_at: now.to_rfc3339(),
    };

    diesel::insert_into(jwt_tokens::table)
        .values(&new_token)
        .execute(&mut conn)
        .await?;

    Ok(())
}

// Revoke JWT
pub async fn revoke_token(pool: &DbPool, token: &str) -> Result<(), AuthError> {
    let mut conn = pool.get().await?;
    let token_hash = hash_token(token);

    diesel::update(jwt_tokens::table.filter(jwt_tokens::token_hash.eq(token_hash)))
        .set(jwt_tokens::revoked.eq(true))
        .execute(&mut conn)
        .await?;

    Ok(())
}

// Check if JWT is revoked in database
pub async fn is_jwt_revoked(pool: &DbPool, token: &str) -> Result<bool, AuthError> {
    let mut conn = pool.get().await?;
    let token_hash = hash_token(token);

    let revoked = jwt_tokens::table
        .filter(jwt_tokens::token_hash.eq(token_hash))
        .select(jwt_tokens::revoked)
        .first::<bool>(&mut conn)
        .await
        .optional()?;

    // If token not found in DB, treat as revoked (defensive approach)
    Ok(revoked.unwrap_or(true))
}

// --- Refresh token functions ---

// Generate a cryptographically random 256-bit refresh token (hex string)
pub fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// Store refresh token in database
pub async fn store_refresh_token(pool: &DbPool, user_id: i32, token: &str) -> Result<(), AuthError> {
    let mut conn = pool.get().await?;
    let token_hash = hash_token(token);
    let config = JwtConfig::new();

    let now = Utc::now();
    let expiry = now + Duration::seconds(config.refresh_expiry_seconds());

    let new_token = CreateRefreshToken {
        user_id,
        token_hash,
        expires_at: expiry.to_rfc3339(),
        created_at: now.to_rfc3339(),
    };

    diesel::insert_into(refresh_tokens::table)
        .values(&new_token)
        .execute(&mut conn)
        .await?;

    Ok(())
}

// Look up a valid refresh token row; returns (id, user_id) if valid
pub async fn get_valid_refresh_token(
    pool: &DbPool,
    token: &str,
) -> Result<Option<(i32, i32)>, AuthError> {
    let mut conn = pool.get().await?;
    let token_hash = hash_token(token);
    let now = Utc::now().to_rfc3339();

    let result: Result<RefreshToken, diesel::result::Error> = refresh_tokens::table
        .filter(refresh_tokens::token_hash.eq(token_hash))
        .filter(refresh_tokens::revoked.eq(false))
        .filter(refresh_tokens::expires_at.gt(now))
        .first(&mut conn)
        .await;

    match result {
        Ok(rt) => Ok(Some((rt.id, rt.user_id))),
        Err(diesel::result::Error::NotFound) => Ok(None),
        Err(e) => Err(AuthError::Database(e)),
    }
}

// Revoke refresh token by its raw value
pub async fn revoke_refresh_token(pool: &DbPool, token: &str) -> Result<(), AuthError> {
    let mut conn = pool.get().await?;
    let token_hash = hash_token(token);

    diesel::update(refresh_tokens::table.filter(refresh_tokens::token_hash.eq(token_hash)))
        .set(refresh_tokens::revoked.eq(true))
        .execute(&mut conn)
        .await?;

    Ok(())
}

// Get user by email
pub async fn get_user_by_email(pool: &DbPool, email_param: &str) -> Result<User, AuthError> {
    let mut conn = pool.get().await?;

    user::table
        .filter(user::email.eq(email_param))
        .first::<User>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AuthError::UserNotFound(email_param.to_string()),
            _ => AuthError::Database(e),
        })
}

// Get user by id
pub async fn get_user_by_id(pool: &DbPool, id: i32) -> Result<User, AuthError> {
    let mut conn = pool.get().await?;

    user::table
        .filter(user::id.eq(id))
        .first::<User>(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AuthError::UserNotFound(format!("User ID: {}", id)),
            _ => AuthError::Database(e),
        })
}

// Check if any users exist in the database
pub async fn user_exists(pool: &DbPool) -> Result<bool, AuthError> {
    let mut conn = pool.get().await?;

    let count: i64 = user::table
        .count()
        .first(&mut conn)
        .await?;

    Ok(count > 0)
}

// New tokens produced during a transparent refresh, carried on AuthUser so
// the handler can forward them as Set-Cookie headers via `apply_refreshed_cookies`.
#[derive(Clone)]
pub struct RefreshedTokens {
    pub new_jwt: String,
    pub new_refresh_token: String,
}

#[derive(Clone)]
pub struct AuthUser {
    pub email: String,
    pub refreshed_tokens: Option<RefreshedTokens>,
}

// Auth extractor - validates JWT from cookie or Authorization: Bearer header.
//
// Happy path  : JWT valid  -> populate AuthUser, no DB hit.
// Refresh path: JWT expired AND valid refresh_token cookie exists
//               -> issue new JWT + rotate refresh token (DB), populate AuthUser
//                  with `refreshed_tokens` set so the handler can update cookies.
// Failure     : redirect to /login.

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    DbPool: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = JwtConfig::new();

        // Extract access token from cookie or Authorization header
        let jwt_token = extract_cookie(parts, COOKIE_NAME)
            .or_else(|| extract_bearer(parts));

        // Extract refresh token from its own cookie
        let refresh_token_raw = extract_cookie(parts, REFRESH_COOKIE_NAME);

        // --- Happy path: valid JWT (check crypto + DB revocation) ---
        if let Some(ref token) = jwt_token {
            match decode_jwt(token, &config) {
                Ok(claims) => {
                    // JWT signature and expiration are valid
                    // Now check if token has been revoked in database
                    let pool = DbPool::from_ref(state);
                    
                    match is_jwt_revoked(&pool, token).await {
                        Ok(true) => {
                            // Token is revoked (e.g., user logged out)
                            return Err(Redirect::to("/login").into_response());
                        }
                        Ok(false) => {
                            // Token is valid and not revoked
                            return Ok(AuthUser {
                                email: claims.email,
                                refreshed_tokens: None,
                            });
                        }
                        Err(e) => {
                            // Database error checking revocation - log and reject
                            tracing::error!("Error checking JWT revocation: {}", e);
                            return Err(Redirect::to("/login").into_response());
                        }
                    }
                }
                Err(AuthError::Jwt(e)) if *e.kind() == ErrorKind::ExpiredSignature => {
                    // Fall through to refresh path
                }
                Err(_) => {
                    // Tampered / wrong secret
                    return Err(Redirect::to("/login").into_response());
                }
            }
        }

        // --- Refresh path: JWT missing or expired ---
        let refresh_raw = match refresh_token_raw {
            Some(r) => r,
            None => return Err(Redirect::to("/login").into_response()),
        };

        // Pull pool from Axum state (cheap clone of the pool handle)
        let pool = DbPool::from_ref(state);

        let valid_rt = get_valid_refresh_token(&pool, &refresh_raw)
            .await
            .ok()
            .flatten();

        let (_rt_id, user_id) = match valid_rt {
            Some(v) => v,
            None => return Err(Redirect::to("/login").into_response()),
        };

        let user = match get_user_by_id(&pool, user_id).await {
            Ok(u) => u,
            Err(_) => return Err(Redirect::to("/login").into_response()),
        };

        // Issue new access JWT
        let new_jwt = match generate_jwt(user.id, &user.email, &config) {
            Ok(t) => t,
            Err(_) => return Err(Redirect::to("/login").into_response()),
        };

        if store_jwt(&pool, user.id, &new_jwt).await.is_err() {
            return Err(Redirect::to("/login").into_response());
        }

        // Rotate refresh token
        let new_refresh = generate_refresh_token();
        let _ = revoke_refresh_token(&pool, &refresh_raw).await;
        if store_refresh_token(&pool, user.id, &new_refresh).await.is_err() {
            return Err(Redirect::to("/login").into_response());
        }

        Ok(AuthUser {
            email: user.email,
            refreshed_tokens: Some(RefreshedTokens {
                new_jwt,
                new_refresh_token: new_refresh,
            }),
        })
    }
}

// Apply refreshed cookies to an existing response, if a transparent refresh happened.
// Call this at the end of every protected handler that receives AuthUser.
pub fn apply_refreshed_cookies(user: &AuthUser, mut response: Response) -> Response {
    if let Some(ref tokens) = user.refreshed_tokens {
        let jwt_cookie = format!(
            "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict",
            COOKIE_NAME, tokens.new_jwt
        );
        let refresh_cookie = format!(
            "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict",
            REFRESH_COOKIE_NAME, tokens.new_refresh_token
        );
        let headers = response.headers_mut();
        
        // Parse and append JWT cookie header
        // If parsing fails, log the error and continue without setting the cookie
        // This prevents request panics from malformed cookie values (DoS protection)
        match jwt_cookie.parse() {
            Ok(header_value) => {
                headers.append(axum::http::header::SET_COOKIE, header_value);
            }
            Err(e) => {
                tracing::error!("Failed to parse JWT cookie header: {}. Cookie value: {}", e, jwt_cookie);
            }
        }
        
        // Parse and append refresh token cookie header
        match refresh_cookie.parse() {
            Ok(header_value) => {
                headers.append(axum::http::header::SET_COOKIE, header_value);
            }
            Err(e) => {
                tracing::error!("Failed to parse refresh cookie header: {}. Cookie value: {}", e, refresh_cookie);
            }
        }
    }
    response
}

// --- helpers ---

fn extract_cookie(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(';').find_map(|c| {
                let c = c.trim();
                let prefix = format!("{}=", name);
                c.strip_prefix(&prefix).map(|v| v.to_string())
            })
        })
}

fn extract_bearer(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

