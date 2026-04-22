use axum::{
    extract::{Path, State, DefaultBodyLimit},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension,
    Router,
};
use askama::Template;
use askama_web::WebTemplate;
use tower_cookies::CookieManagerLayer;
use std::sync::Arc;
use rust_decimal::Decimal;

mod models;
mod db;
mod schema;
mod config;
mod auth;
mod handlers;
mod crypto;
mod rate_limit;

use handlers::auth::{login, logout, verify_auth, check_setup, setup_first_user, get_current_user, update_user};
use handlers::crud::crud_router;
use handlers::contracts::{
    list_contracts, create_contract, get_contract_admin, update_contract, delete_contract,
    view_contract_for_signing, sign_contract, contract_signed_success, verify_contract, download_proof
};
use auth::{apply_refreshed_cookies, get_user_by_email, AuthUser};
use db::DbPool;
use models::{Customer, Invoice, User};

#[derive(Template, WebTemplate)]
#[template(path = "index.html")]
struct IndexTemplate {
    title: String,
    message: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginTemplate;

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    user_email: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "edit_profile.html")]
struct EditProfileTemplate;

#[derive(Template, WebTemplate)]
#[template(path = "invoice_view.html")]
struct InvoiceViewTemplate {
    user: User,              // Company/issuer information
    user_address_lines: Vec<String>,  // Split address lines
    invoice: Invoice,
    customer: Customer,
    customer_address_lines: Vec<String>,  // Split address lines
    line_items: Vec<LineItem>,
    after_items: Vec<AfterLineItemDisplay>,
    subtotal: Decimal,
    total: Decimal,  // Calculated from amount stored as TEXT (sqlite3) for precision
    payment_made: Option<Decimal>,
    balance_due: Option<Decimal>,
    show_payment_info: bool,
}

// Helper structs for template rendering
#[derive(Debug)]
struct LineItem {
    description: String,
    amount: Decimal,
}

#[derive(Debug)]
struct AfterLineItemDisplay {
    name: String,
    percentage_display: String,  // e.g., "5.0%" or "-10.0%"
    calculated_amount: Decimal,       // subtotal × percentage
    is_discount: bool,
}

#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into())
        )
        .init();
    
    // Validate critical environment variables at startup before server starts
    // This ensures the service fails fast on startup rather than on first auth attempt
    let _jwt_config = config::JwtConfig::new();
    tracing::info!("✓ JWT_SECRET validated successfully");
    
    let pool = db::create_pool().await;
    let rate_limiter = Arc::new(rate_limit::RateLimiter::new());

    let app = Router::new()
        // Public routes
        .route("/", get(handler))
        .route("/login", get(login_page).post(login))
        .route("/verify", get(verify_auth))
        .route("/check-setup", get(check_setup))
        .route("/setup", post(setup_first_user))

        // Public contract routes (NO AUTH REQUIRED)
        .route("/contracts/sign/{uuid}", get(view_contract_for_signing).post(sign_contract))
        .route("/contracts/signed/{uuid}/{code}", get(contract_signed_success))
        .route("/contracts/verify/{uuid}/{code}", get(verify_contract))
        .route("/contracts/proof/{uuid}/{code}", get(download_proof))

        // Protected routes
        .route("/dashboard", get(dashboard_handler))
        .route("/profile", get(profile_page))
        .route("/view_invoice/{id}", get(view_invoice_handler))
        .route("/logout", get(logout).post(logout))
        
        // User profile API routes
        .route("/api/user/profile", get(get_current_user).put(update_user))

        // Admin contract routes (REQUIRES AUTH)
        .route("/admin/contracts", get(list_contracts).post(create_contract))
        .route("/admin/contracts/{id}", get(get_contract_admin).put(update_contract).delete(delete_contract))

        // CRUD routes
        .nest("/customers", crud_router::<Customer>(pool.clone()))
        .nest("/invoices",  crud_router::<Invoice>(pool.clone()))

        // Limit request body size ->
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        // Cookie layer for JWT management
        .layer(CookieManagerLayer::new())
        .layer(Extension(rate_limiter))
        .with_state(pool);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect(&format!("Failed to bind to {} - port may be in use or insufficient permissions", bind_addr));
    
    println!("Listening on: {}", listener.local_addr()
        .expect("Failed to get local address from listener"));
    
    tracing::info!("Server started on {}", listener.local_addr()
        .expect("Failed to get local address from listener"));
    
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>()
    )
    .await
    .expect("Server error: failed to serve application");
}

async fn handler() -> IndexTemplate {
    IndexTemplate {
        title: "Invoices&Contracts v0.1".to_string(),
        message: "@2026".to_string(),
    }
}

async fn login_page() -> LoginTemplate {
    LoginTemplate
}

async fn dashboard_handler(user: AuthUser) -> impl IntoResponse {
    let template = DashboardTemplate { user_email: user.email.clone() };
    apply_refreshed_cookies(&user, template.into_response())
}

async fn profile_page(user: AuthUser) -> impl IntoResponse {
    let template = EditProfileTemplate;
    apply_refreshed_cookies(&user, template.into_response())
}

async fn view_invoice_handler(
    auth_user: AuthUser,
    State(pool): State<DbPool>,
    Path(invoice_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    use crate::handlers::crud::CrudModel;
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection error in view_invoice: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Fetch the logged-in user's full information (for company header)
    let user = get_user_by_email(&pool, &auth_user.email)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by email '{}': {}", auth_user.email, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Fetch invoice
    let invoice = Invoice::find(&mut conn, &invoice_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to find invoice '{}': {}", invoice_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // Fetch associated customer
    let customer = Customer::find(&mut conn, &invoice.customer_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to find customer '{}': {}", invoice.customer_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // Split addresses by <sp> separator
    let user_address_lines: Vec<String> = user.address
        .split("<sp>")
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
        })
        .collect();
    
    let customer_address_lines: Vec<String> = customer.address
        .as_ref()
        .map(|addr| addr.split("<sp>")
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
            })
            .collect())
        .unwrap_or_default();
    
    // Parse line_charges JSON into line items
    // Convert JSON f64 values to Decimal for precise financial calculations
    let line_items: Vec<LineItem> = invoice.line_charges
        .as_ref()
        .and_then(|s| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s).ok())
        .map(|map| map.into_iter()
            .filter_map(|(desc, val)| {
                val.as_f64().and_then(|amount| {
                    Decimal::try_from(amount).ok().map(|dec| LineItem {
                        description: desc,
                        amount: dec,
                    })
                })
            })
            .collect())
        .unwrap_or_default();
    
    // Calculate subtotal from line items (using Decimal for precision)
    let subtotal: Decimal = line_items.iter().map(|item| item.amount).sum();
    
    // Parse after_line_items JSON and calculate amounts (percentages applied to subtotal)
    let after_items: Vec<AfterLineItemDisplay> = invoice.after_line_items
        .as_ref()
        .and_then(|s| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s).ok())
        .map(|map| map.into_iter()
            .filter_map(|(name, val)| {
                val.as_f64().and_then(|percentage| {
                    Decimal::try_from(percentage).ok().map(|percentage_dec| {
                        let percentage_value = percentage_dec * Decimal::from(100);
                        let percentage_display = format!("{:.2}%", percentage_value);
                        let is_discount = percentage_dec < Decimal::ZERO;
                        AfterLineItemDisplay {
                            name,
                            percentage_display,
                            calculated_amount: subtotal * percentage_dec,
                            is_discount,
                        }
                    })
                })
            })
            .collect())
        .unwrap_or_default();
    
    // Calculate total from subtotal + after-line items (computed dynamically)
    // This ensures perfect precision - total is never stored, only computed from source data
    let after_items_sum: Decimal = after_items.iter().map(|item| item.calculated_amount).sum();
    let total = subtotal + after_items_sum;
    
    // Calculate payment and balance using computed total
    let payment_made = invoice.payment_made_decimal();
    let balance_due = payment_made.map(|paid| total - paid);
    let show_payment_info = payment_made.is_some_and(|p| p > Decimal::ZERO);
    
    let template = InvoiceViewTemplate {
        user,
        user_address_lines,
        invoice,
        customer,
        customer_address_lines,
        line_items,
        after_items,
        subtotal,
        total,
        payment_made,
        balance_due,
        show_payment_info,
    };
    
    Ok(apply_refreshed_cookies(&auth_user, template.into_response()))
}
