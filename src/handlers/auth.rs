use axum::{
    extract::{State, ConnectInfo},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};

use bcrypt::hash;

use crate::auth::{
    decode_jwt, generate_jwt, generate_refresh_token, get_dummy_hash, get_user_by_email,
    revoke_token, store_jwt, store_refresh_token, verify_password,
    revoke_refresh_token, user_exists, AuthUser,
};
use crate::config::{JwtConfig, COOKIE_NAME, REFRESH_COOKIE_NAME};
use crate::db::DbPool;
use crate::models::{LoginRequest, LoginResponse, UserInfo, SetupRequest, SetupResponse, CheckSetupResponse, CreateFullUser, UpdateUserRequest, UserProfileResponse, UpdateUserResponse};
use crate::rate_limit::RateLimiter;
use crate::schema::user;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Serialize;

#[derive(Serialize)]
pub struct VerifyResponse {
    pub authenticated: bool,
}

// Login handler - issues both access JWT and refresh token
pub async fn login(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    cookies: Cookies,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // Check rate limit before processing login
    let client_ip = addr.ip();
    if rate_limiter.check_rate_limit(client_ip).await.is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(LoginResponse {
                success: false,
                message: "Too many login attempts. Please try again later.".to_string(),
                user: None,
            }),
        )
            .into_response();
    }

    // Get user by email (returns None if not found)
    // Important: We store the result as Option to enable constant-time verification below
    let user_option = get_user_by_email(&pool, &payload.email).await.ok();

    // TIMING ATTACK PREVENTION:
    // Always verify a password hash, even if the user doesn't exist.
    // This ensures all login attempts take approximately the same time (~50-300ms for bcrypt),
    // preventing attackers from using timing differences to enumerate valid email addresses.
    let (password_hash, user_exists) = match &user_option {
        Some(user) => (user.password.as_str(), true),
        None => (get_dummy_hash(), false), // Use dummy hash for non-existent users
    };

    // Verify password - this always takes the same time regardless of user existence
    let password_valid = match verify_password(&payload.password, password_hash) {
        Ok(valid) => valid && user_exists, // Even if dummy hash matches, authentication fails
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    success: false,
                    message: "Server error".to_string(),
                    user: None,
                }),
            )
                .into_response();
        }
    };

    // If authentication failed (invalid email or password), record and return error
    if !password_valid {
        // Record failed attempt for rate limiting
        rate_limiter.record_failed_attempt(client_ip).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                success: false,
                message: "Invalid email or password".to_string(),
                user: None,
            }),
        )
            .into_response();
    }

    // At this point, authentication succeeded, so user_option must be Some
    // However, we handle this defensively to prevent panics
    let user = match user_option {
        Some(u) => u,
        None => {
            // This should never happen due to password_valid logic, but handle gracefully
            tracing::error!(
                "INVARIANT VIOLATION: password_valid=true but user_option=None. \
                 This indicates a critical bug in the authentication logic."
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    success: false,
                    message: "Authentication error".to_string(),
                    user: None,
                }),
            )
                .into_response();
        }
    };

    // Generate access JWT (15 min)
    let config = JwtConfig::new();
    let token = match generate_jwt(user.id, &user.email, &config) {
        Ok(token) => token,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    success: false,
                    message: "Failed to generate token".to_string(),
                    user: None,
                }),
            )
                .into_response();
        }
    };

    // Store access JWT in DB
    if store_jwt(&pool, user.id, &token).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(LoginResponse {
                success: false,
                message: "Failed to store token".to_string(),
                user: None,
            }),
        )
            .into_response();
    }

    // Generate and store refresh token (7 days)
    let refresh_token = generate_refresh_token();
    if store_refresh_token(&pool, user.id, &refresh_token).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(LoginResponse {
                success: false,
                message: "Failed to store refresh token".to_string(),
                user: None,
            }),
        )
            .into_response();
    }

    // Set access JWT cookie (15 min)
    let mut jwt_cookie = Cookie::new(COOKIE_NAME, token);
    jwt_cookie.set_http_only(true);
    jwt_cookie.set_secure(true);
    jwt_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    jwt_cookie.set_path("/");
    cookies.add(jwt_cookie);

    // Set refresh token cookie (7 days)
    let mut refresh_cookie = Cookie::new(REFRESH_COOKIE_NAME, refresh_token);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(true);
    refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    refresh_cookie.set_path("/");
    cookies.add(refresh_cookie);

    // Reset rate limit on successful login
    rate_limiter.reset_attempts(client_ip).await;

    (
        StatusCode::OK,
        Json(LoginResponse {
            success: true,
            message: "Login successful".to_string(),
            user: Some(UserInfo {
                id: user.id,
                name: user.name,
                email: user.email,
            }),
        }),
    )
        .into_response()
}

// Logout handler - revokes both tokens and clears cookies
pub async fn logout(State(pool): State<DbPool>, cookies: Cookies) -> Response {
    // Revoke access JWT
    if let Some(cookie) = cookies.get(COOKIE_NAME) {
        let _ = revoke_token(&pool, cookie.value()).await;
    }

    // Revoke all refresh tokens for this user (identified via refresh cookie)
    if let Some(cookie) = cookies.get(REFRESH_COOKIE_NAME) {
        // We stored the user_id in the refresh token record; revoke by token hash
        // revoke_all is a belt-and-suspenders: revokes even tokens not in this cookie
        // For simplicity, revoke just the current one here via revoke_token equivalent
        let _ = revoke_refresh_token(&pool, cookie.value()).await;
        cookies.remove(Cookie::new(REFRESH_COOKIE_NAME, ""));
    }

    cookies.remove(Cookie::new(COOKIE_NAME, ""));

    Redirect::to("/").into_response()
}

// Verify authentication - checks if user has valid JWT token
pub async fn verify_auth(cookies: Cookies) -> Response {
    if let Some(token) = cookies.get(COOKIE_NAME) {
        let config = JwtConfig::new();
        if decode_jwt(token.value(), &config).is_ok() {
            return (
                StatusCode::OK,
                Json(VerifyResponse {
                    authenticated: true,
                }),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        Json(VerifyResponse {
            authenticated: false,
        }),
    )
        .into_response()
}

// Check if setup is needed (no users exist yet)
pub async fn check_setup(State(pool): State<DbPool>) -> Response {
    match user_exists(&pool).await {
        Ok(exists) => {
            let response = CheckSetupResponse { needs_setup: !exists };
            Json(response).into_response()
        }
        Err(e) => {
            // If the table doesn't exist, we definitely need setup
            // This handles the case when migrations haven't been run yet
            let error_str = format!("{:?}", e);
            tracing::debug!("User existence check error: {}", error_str);
            if error_str.to_lowercase().contains("no such table") || 
               error_str.to_lowercase().contains("table") && error_str.to_lowercase().contains("not exist") {
                tracing::info!("User table does not exist - setup required");
                let response = CheckSetupResponse { needs_setup: true };
                return Json(response).into_response();
            }
            tracing::error!("Error checking user existence: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// Setup first admin user - only works when no users exist
pub async fn setup_first_user(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    cookies: Cookies,
    Json(payload): Json<SetupRequest>,
) -> Response {
    // Check rate limit
    let client_ip = addr.ip();
    if rate_limiter.check_rate_limit(client_ip).await.is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(SetupResponse {
                success: false,
                message: "Too many setup attempts. Please try again later.".to_string(),
                redirect: None,
            }),
        ).into_response();
    }

    // Check if users already exist
    match user_exists(&pool).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                Json(SetupResponse {
                    success: false,
                    message: "Setup already completed. Please login instead.".to_string(),
                    redirect: Some("/login".to_string()),
                }),
            ).into_response();
        }
        Err(e) => {
            // If the table doesn't exist, we can still proceed with setup
            // (the migration should create it, or we'll get a clearer error on insert)
            let error_str = format!("{:?}", e).to_lowercase();
            tracing::debug!("Setup - user existence check error: {}", error_str);
            if error_str.contains("no such table") || 
               (error_str.contains("table") && error_str.contains("not exist")) {
                tracing::info!("User table does not exist - proceeding with setup");
                // Continue with setup
            } else {
                tracing::error!("Database error checking user existence: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SetupResponse {
                        success: false,
                        message: "Server error".to_string(),
                        redirect: None,
                    }),
                ).into_response();
            }
        }
        Ok(false) => {} // Continue with setup
    }

    // Hash password with bcrypt
    let password_hash = match hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Password hashing error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SetupResponse {
                    success: false,
                    message: "Server error".to_string(),
                    redirect: None,
                }),
            ).into_response();
        }
    };

    // Create the first user
    let new_user = CreateFullUser {
        name: payload.name,
        email: payload.email,
        address: payload.address,
        tax_id: payload.tax_id,
        password: password_hash,
    };

    // Insert user and get the created user back
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SetupResponse {
                    success: false,
                    message: "Server error".to_string(),
                    redirect: None,
                }),
            ).into_response();
        }
    };

    // Insert user and get ID in a single query using RETURNING clause
    // This eliminates the N+1 query pattern (see focus_issues.md #12)
    let user_id: i32 = match diesel::insert_into(user::table)
        .values(&new_user)
        .returning(user::id)
        .get_result(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Error creating user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SetupResponse {
                    success: false,
                    message: "Failed to create user".to_string(),
                    redirect: None,
                }),
            ).into_response();
        }
    };

    // Generate JWT and refresh token
    let config = JwtConfig::new();
    let jwt_token = match generate_jwt(user_id, &new_user.email, &config) {
        Ok(token) => token,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SetupResponse {
                    success: false,
                    message: "Failed to generate token".to_string(),
                    redirect: None,
                }),
            ).into_response();
        }
    };

    // Store JWT in database
    if store_jwt(&pool, user_id, &jwt_token).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupResponse {
                success: false,
                message: "Failed to store token".to_string(),
                redirect: None,
            }),
        ).into_response();
    }

    // Generate and store refresh token
    let refresh_token = generate_refresh_token();
    if store_refresh_token(&pool, user_id, &refresh_token).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupResponse {
                success: false,
                message: "Failed to store refresh token".to_string(),
                redirect: None,
            }),
        ).into_response();
    }

    // Set cookies
    let mut jwt_cookie = Cookie::new(COOKIE_NAME, jwt_token);
    jwt_cookie.set_http_only(true);
    jwt_cookie.set_secure(true);
    jwt_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    jwt_cookie.set_path("/");
    cookies.add(jwt_cookie);

    let mut refresh_cookie = Cookie::new(REFRESH_COOKIE_NAME, refresh_token);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(true);
    refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    refresh_cookie.set_path("/");
    cookies.add(refresh_cookie);

    // Reset rate limit on successful setup
    rate_limiter.reset_attempts(client_ip).await;

    (
        StatusCode::CREATED,
        Json(SetupResponse {
            success: true,
            message: "Setup complete! Welcome to PixlW Invoices.".to_string(),
            redirect: Some("/dashboard".to_string()),
        }),
    ).into_response()
}

// Get current user profile
pub async fn get_current_user(
    user: AuthUser,
    State(pool): State<DbPool>,
) -> Response {
    match get_user_by_email(&pool, &user.email).await {
        Ok(user) => {
            let profile = UserProfileResponse {
                id: user.id,
                name: user.name,
                email: user.email,
                address: user.address,
                tax_id: user.tax_id,
            };
            (StatusCode::OK, Json(profile)).into_response()
        }
        Err(e) => {
            tracing::error!("Error fetching user profile: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserProfileResponse {
                    id: 0,
                    name: String::new(),
                    email: String::new(),
                    address: String::new(),
                    tax_id: String::new(),
                }),
            ).into_response()
        }
    }
}

// Update current user profile
pub async fn update_user(
    user: AuthUser,
    State(pool): State<DbPool>,
    Json(payload): Json<UpdateUserRequest>,
) -> Response {
    // Validate input lengths to prevent DoS (see focus_issues_2.md #7)
    const MAX_NAME_LEN: usize = 200;
    const MAX_EMAIL_LEN: usize = 255;
    const MAX_ADDRESS_LEN: usize = 1000;
    const MAX_TAX_ID_LEN: usize = 100;
    
    if payload.name.len() > MAX_NAME_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(UpdateUserResponse {
                success: false,
                message: format!("Name exceeds maximum length of {} characters", MAX_NAME_LEN),
            }),
        ).into_response();
    }
    
    if payload.email.len() > MAX_EMAIL_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(UpdateUserResponse {
                success: false,
                message: format!("Email exceeds maximum length of {} characters", MAX_EMAIL_LEN),
            }),
        ).into_response();
    }
    
    // Basic email format validation
    if !payload.email.contains('@') || !payload.email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(UpdateUserResponse {
                success: false,
                message: "Invalid email format".to_string(),
            }),
        ).into_response();
    }
    
    if payload.address.len() > MAX_ADDRESS_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(UpdateUserResponse {
                success: false,
                message: format!("Address exceeds maximum length of {} characters", MAX_ADDRESS_LEN),
            }),
        ).into_response();
    }
    
    if payload.tax_id.len() > MAX_TAX_ID_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(UpdateUserResponse {
                success: false,
                message: format!("Tax ID exceeds maximum length of {} characters", MAX_TAX_ID_LEN),
            }),
        ).into_response();
    }
    
    // Validate password length if provided
    if let Some(ref new_pass) = payload.new_password {
        if new_pass.len() < 8 {
            return (
                StatusCode::BAD_REQUEST,
                Json(UpdateUserResponse {
                    success: false,
                    message: "New password must be at least 8 characters".to_string(),
                }),
            ).into_response();
        }
        if new_pass.len() > 128 {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(UpdateUserResponse {
                    success: false,
                    message: "Password exceeds maximum length of 128 characters".to_string(),
                }),
            ).into_response();
        }
    }

    // Get current user details
    let current_user = match get_user_by_email(&pool, &user.email).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Error fetching user for update: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UpdateUserResponse {
                    success: false,
                    message: "Failed to fetch user details".to_string(),
                }),
            ).into_response();
        }
    };

    // If new password is provided, verify current password first
    let new_password_hash = if let Some(ref new_pass) = payload.new_password {
        // Check if current password was provided
        let current_pass = match payload.current_password {
            Some(ref p) => p,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(UpdateUserResponse {
                        success: false,
                        message: "Current password is required to change password".to_string(),
                    }),
                ).into_response();
            }
        };

        // Verify current password
        match verify_password(current_pass, &current_user.password) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(UpdateUserResponse {
                        success: false,
                        message: "Current password is incorrect".to_string(),
                    }),
                ).into_response();
            }
            Err(e) => {
                tracing::error!("Password verification error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(UpdateUserResponse {
                        success: false,
                        message: "Server error".to_string(),
                    }),
                ).into_response();
            }
        }

        // Hash new password
        match hash(new_pass, bcrypt::DEFAULT_COST) {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::error!("Password hashing error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(UpdateUserResponse {
                        success: false,
                        message: "Failed to hash new password".to_string(),
                    }),
                ).into_response();
            }
        }
    } else {
        None
    };

    // Update user in database
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UpdateUserResponse {
                    success: false,
                    message: "Database connection error".to_string(),
                }),
            ).into_response();
        }
    };

    let update_result = if let Some(password_hash) = new_password_hash {
        // Update with new password
        diesel::update(user::table.filter(user::id.eq(current_user.id)))
            .set((
                user::name.eq(&payload.name),
                user::email.eq(&payload.email),
                user::address.eq(&payload.address),
                user::tax_id.eq(&payload.tax_id),
                user::password.eq(password_hash),
            ))
            .execute(&mut conn)
            .await
    } else {
        // Update without changing password
        diesel::update(user::table.filter(user::id.eq(current_user.id)))
            .set((
                user::name.eq(&payload.name),
                user::email.eq(&payload.email),
                user::address.eq(&payload.address),
                user::tax_id.eq(&payload.tax_id),
            ))
            .execute(&mut conn)
            .await
    };

    match update_result {
        Ok(_) => (
            StatusCode::OK,
            Json(UpdateUserResponse {
                success: true,
                message: "Profile updated successfully".to_string(),
            }),
        ).into_response(),
        Err(e) => {
            tracing::error!("Error updating user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UpdateUserResponse {
                    success: false,
                    message: "Failed to update profile".to_string(),
                }),
            ).into_response()
        }
    }
}
