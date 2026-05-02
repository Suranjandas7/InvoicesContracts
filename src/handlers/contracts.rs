use axum::{
    extract::{Path, State, ConnectInfo, Query},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Extension,
    Json,
};
use diesel::prelude::*;
use diesel_async::{RunQueryDsl, AsyncConnection};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, DateTime, FixedOffset};

use crate::auth::AuthUser;
use crate::db::{DbPool, Conn};
use crate::models::{
    Contract, ContractPayload, ContractSignature, CreateContractSignature,
    SignContractRequest, SignContractResponse, Customer, CustomerUuidQuery,
    ContractSignatureSlot, CreateContractSignatureSlot,
    CreateContractRequest, SignatureProgress,
};
use crate::crypto;
use crate::handlers::crud::CrudModel;
use crate::rate_limit::RateLimiter;

// ── Helper functions ─────────────────────────────────────────────────────────

/// Convert UTC timestamp string to IST (UTC+5:30) formatted string
fn utc_to_ist(utc_str: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(utc_str) {
        // IST is UTC+5:30
        let ist_offset = FixedOffset::east_opt(5 * 3600 + 30 * 60)
            .expect("IST timezone offset (UTC+5:30) should always be valid");
        let ist_time = dt.with_timezone(&ist_offset);
        ist_time.format("%Y-%m-%d %H:%M:%S IST").to_string()
    } else {
        utc_str.to_string() // Fallback to original if parsing fails
    }
}

/// Validate UUID format (RFC4122)
fn is_valid_uuid(uuid_str: &str) -> bool {
    Uuid::parse_str(uuid_str).is_ok()
}

/// Mask a UUID or verification code for display (show only last 4 characters)
fn mask_id(id: &str) -> String {
    let len = id.len();
    if len <= 4 {
        return id.to_string();
    }
    format!("****-{}", &id[len.saturating_sub(4)..])
}

/// Verify customer UUID matches contract's customer_id
/// Returns the Customer if valid, or StatusCode error if invalid
async fn verify_customer_uuid(
    conn: &mut Conn,
    contract_id: &str,
    customer_uuid: &str,
) -> Result<(Contract, Customer), StatusCode> {
    use crate::schema::contracts::dsl as contract_dsl;
    use crate::schema::customer::dsl as customer_dsl;
    
    // 1. Validate UUID format
    if !is_valid_uuid(customer_uuid) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // 2. Fetch contract
    let contract = contract_dsl::contracts
        .filter(contract_dsl::id.eq(contract_id))
        .select(Contract::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // 3. Fetch customer by UUID
    let customer = customer_dsl::customer
        .filter(customer_dsl::id.eq(customer_uuid))
        .select(Customer::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    // 4. Verify customer ID matches contract's customer_id
    if customer.id.as_ref() != Some(&contract.customer_id) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    Ok((contract, customer))
}

// ── Admin CRUD handlers (protected) ──────────────────────────────────────────

/// List all contracts (admin only)
pub async fn list_contracts(
    _user: AuthUser,
    State(pool): State<DbPool>,
) -> Result<Json<Vec<Contract>>, StatusCode> {
    use crate::schema::contracts::dsl;
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    let contracts = dsl::contracts
        .select(Contract::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(Json(contracts))
}

/// Create a new contract with signature slots (admin only)
pub async fn create_contract(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Json(request): Json<CreateContractRequest>,
) -> Result<(StatusCode, Json<Contract>), StatusCode> {
    use crate::schema::contracts::dsl as contract_dsl;
    use crate::schema::contract_signature_slots::dsl as slot_dsl;
    
    // Validate field lengths to prevent DoS attacks
    const MAX_TITLE_LEN: usize = 500;
    const MAX_CONTENT_LEN: usize = 1_000_000;  // 1MB
    const MAX_TYPE_LEN: usize = 100;
    const MAX_ID_LEN: usize = 200;
    
    if request.title.len() > MAX_TITLE_LEN {
        tracing::warn!("Contract title too long: {} bytes", request.title.len());
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if request.content.len() > MAX_CONTENT_LEN {
        tracing::warn!("Contract content too long: {} bytes", request.content.len());
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if request.contract_type.len() > MAX_TYPE_LEN {
        tracing::warn!("Contract type too long: {} bytes", request.contract_type.len());
        return Err(StatusCode::BAD_REQUEST);
    }
    if request.customer_id.len() > MAX_ID_LEN {
        tracing::warn!("Customer ID too long: {} bytes", request.customer_id.len());
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Validate signature slots
    if request.signature_slots.is_empty() {
        tracing::warn!("Contract creation rejected: no signature slots provided");
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Generate UUID for contract
    let contract_id = Uuid::new_v4().to_string();
    let num_slots = request.signature_slots.len() as i32;
    let signature_slots = request.signature_slots;
    
    // Create contract payload
    let payload = ContractPayload {
        id: Some(contract_id.clone()),
        customer_id: request.customer_id,
        contract_type: request.contract_type,
        title: request.title,
        content: request.content,
        created_at: Utc::now().to_rfc3339(),
        expires_at: request.expires_at,
        status: "pending".to_string(),
        required_signatures: num_slots,
        completed_signatures: 0,
        final_hash: None,
    };
    
    // Transaction: Insert contract + create slots
    let result: Result<Contract, diesel::result::Error> = conn.transaction(|conn| {
        Box::pin(async move {
            // Insert contract
            diesel::insert_into(contract_dsl::contracts)
                .values(&payload)
                .execute(conn)
                .await?;
            
            // Fetch inserted contract
            let contract = contract_dsl::contracts
                .filter(contract_dsl::id.eq(&contract_id))
                .select(Contract::as_select())
                .first(conn)
                .await?;
            
            // Create signature slots
            for slot_def in signature_slots.iter() {
                let slot = CreateContractSignatureSlot {
                    contract_id: contract_id.clone(),
                    slot_name: slot_def.name.clone(),
                    slot_order: slot_def.order,
                    is_filled: false,
                };
                
                diesel::insert_into(slot_dsl::contract_signature_slots)
                    .values(&slot)
                    .execute(conn)
                    .await?;
            }
            
            Ok(contract)
        })
    }).await;
    
    let contract = result.map_err(|e| {
        tracing::error!("Database transaction error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    Ok((StatusCode::CREATED, Json(contract)))
}

/// Get a single contract (admin only)
pub async fn get_contract_admin(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Path(contract_id): Path<String>,
) -> Result<Json<Contract>, StatusCode> {
    use crate::schema::contracts::dsl;
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    let contract = dsl::contracts
        .filter(dsl::id.eq(&contract_id))
        .select(Contract::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(contract))
}

/// Update a contract (admin only)
pub async fn update_contract(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Path(contract_id): Path<String>,
    Json(payload): Json<ContractPayload>,
) -> Result<Json<Contract>, StatusCode> {
    use crate::schema::contracts::dsl;
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Note: payload.id is not set here - ID is immutable and specified in the filter
    
    let updated = diesel::update(dsl::contracts.filter(dsl::id.eq(&contract_id)))
        .set(&payload)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    if updated == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    
    let contract = dsl::contracts
        .filter(dsl::id.eq(&contract_id))
        .select(Contract::as_select())
        .first(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(Json(contract))
}

/// Delete a contract (admin only)
pub async fn delete_contract(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Path(contract_id): Path<String>,
) -> StatusCode {
    use crate::schema::contracts::dsl;
    
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    
    match diesel::delete(dsl::contracts.filter(dsl::id.eq(&contract_id)))
        .execute(&mut conn)
        .await
    {
        Ok(deleted) if deleted > 0 => StatusCode::NO_CONTENT,
        Ok(_) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ── Public signing handlers (no auth) ────────────────────────────────────────

/// View contract for signing (public, requires customer UUID)
/// GET /contracts/sign/:contract_id?customer_uuid=xxx
pub async fn view_contract_for_signing(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(contract_id): Path<String>,
    Query(query): Query<CustomerUuidQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    use crate::schema::contract_signatures::dsl as sig_dsl;
    use crate::schema::contract_signature_slots::dsl as slot_dsl;
    use askama::Template;
    use askama_web::WebTemplate;
    
    // Check if customer_uuid is provided
    if query.customer_uuid.is_none() {
        // Show UUID gate template
        #[derive(Template, WebTemplate)]
        #[template(path = "contract_uuid_gate.html")]
        struct UuidGateTemplate {
            contract_id_masked: String,
        }
        
        let template = UuidGateTemplate {
            contract_id_masked: mask_id(&contract_id),
        };
        
        return Ok(template.into_response());
    }
    
    // Extract customer_uuid from query (we already checked is_none above)
    let customer_uuid = query.customer_uuid
        .expect("customer_uuid should be present after is_none check");
    
    // Check rate limit
    let client_ip = addr.ip();
    if rate_limiter.check_rate_limit(client_ip).await.is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Verify customer UUID matches contract
    let (contract, customer) = match verify_customer_uuid(&mut conn, &contract_id, &customer_uuid).await {
        Ok(result) => {
            // Reset rate limit on successful verification
            rate_limiter.reset_attempts(client_ip).await;
            result
        }
        Err(e) => {
            // Record failed attempt
            rate_limiter.record_failed_attempt(client_ip).await;
            return Err(e);
        }
    };
    
    // Load all signature slots for this contract
    let slots: Vec<ContractSignatureSlot> = slot_dsl::contract_signature_slots
        .filter(slot_dsl::contract_id.eq(&contract_id))
        .order(slot_dsl::slot_order.asc())
        .select(ContractSignatureSlot::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error loading slots: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Load all signatures for this contract
    let signatures: Vec<ContractSignature> = sig_dsl::contract_signatures
        .filter(sig_dsl::contract_id.eq(&contract_id))
        .select(ContractSignature::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error loading signatures: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Check if contract is fully signed
    let fully_signed = contract.status == "signed";
    
    // Render contract view template with full details
    #[derive(Template, WebTemplate)]
    #[template(path = "contract_view.html")]
    struct ContractViewTemplate<'a> {
        #[allow(dead_code)] // Used in contract_view.html template
        contract_id: &'a str,
        contract_title: &'a str,
        contract_type: &'a str,
        contract_created_at: &'a str,
        contract_expires_at: &'a str,
        contract_content: &'a str,
        customer_name: &'a str,
        customer_uuid: &'a str,
        fully_signed: bool,
        progress_completed: i32,
        progress_required: i32,
        slots: &'a [ContractSignatureSlot],
        signatures: &'a [ContractSignature],
    }
    
    // Pre-compute values that need ownership for defaults
    let default_id = String::new();
    let default_expires = String::new();
    
    let template = ContractViewTemplate {
        contract_id: contract.id.as_ref().unwrap_or(&default_id),
        contract_title: &contract.title,
        contract_type: &contract.contract_type,
        contract_created_at: &contract.created_at,
        contract_expires_at: contract.expires_at.as_ref().unwrap_or(&default_expires),
        contract_content: &contract.content,
        customer_name: &customer.name,
        customer_uuid: &customer_uuid,
        fully_signed,
        progress_completed: contract.completed_signatures,
        progress_required: contract.required_signatures,
        slots: &slots,
        signatures: &signatures,
    };
    
    Ok(template.into_response())
}

/// Sign contract (public, POST)
/// POST /contracts/sign/:contract_id
pub async fn sign_contract(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(contract_id): Path<String>,
    Json(request): Json<SignContractRequest>,
) -> Result<Json<SignContractResponse>, StatusCode> {
    use crate::schema::contracts::dsl as contract_dsl;
    use crate::schema::contract_signatures::dsl as sig_dsl;
    use crate::schema::contract_signature_slots::dsl as slot_dsl;
    
    if !request.accepted {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Check rate limit
    let client_ip = addr.ip();
    if rate_limiter.check_rate_limit(client_ip).await.is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Verify customer UUID and get contract + customer
    let (contract, _customer) = match verify_customer_uuid(&mut conn, &contract_id, &request.customer_uuid).await {
        Ok(result) => {
            // Reset rate limit on successful verification
            rate_limiter.reset_attempts(client_ip).await;
            result
        }
        Err(e) => {
            // Record failed attempt
            rate_limiter.record_failed_attempt(client_ip).await;
            return Err(e);
        }
    };
    
    // Load the signature slot
    let slot: ContractSignatureSlot = slot_dsl::contract_signature_slots
        .filter(slot_dsl::id.eq(request.slot_id))
        .filter(slot_dsl::contract_id.eq(&contract_id))
        .select(ContractSignatureSlot::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("Database error loading slot: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::BAD_REQUEST)?; // Slot not found or doesn't belong to contract
    
    // Check if slot is already filled
    if slot.is_filled {
        return Err(StatusCode::CONFLICT); // 409 - Slot already signed
    }
    
    // Check contract status
    if contract.status != "pending" {
        return Err(StatusCode::CONFLICT);
    }
    
    // Check if contract has expired
    if let Some(ref expires_at) = contract.expires_at {
        use chrono::DateTime;
        if let Ok(expiry_time) = DateTime::parse_from_rfc3339(expires_at) {
            if Utc::now() > expiry_time {
                // Contract has expired - cannot be signed
                return Err(StatusCode::GONE); // 410 Gone
            }
        }
    }
    
    // Generate cryptographic signature
    let timestamp = Utc::now().to_rfc3339();
    let content_hash = crypto::hash_content(&contract.content);
    let (public_key, private_key) = crypto::generate_keypair();
    
    let signature_hash = crypto::sign_contract(
        &private_key,
        &contract_id,
        &content_hash,
        &timestamp,
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Generate verification code
    let verification_code = crypto::generate_verification_code();
    
    // Extract client info
    let client_ip_str = addr.ip().to_string();
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    // Move values into the closure by creating owned copies
    let contract_id_tx = contract_id.clone();
    let slot_id_tx: i32 = request.slot_id;
    let completed_tx: i32 = contract.completed_signatures;
    let required_tx: i32 = contract.required_signatures;
    
    // Create signature record
    let new_signature = CreateContractSignature {
        contract_id: contract_id.clone(),
        verification_code: verification_code.clone(),
        signature_hash: signature_hash.clone(),
        public_key,
        content_hash: content_hash.clone(),
        signed_at: timestamp.clone(),
        signer_name: request.signer_name,
        client_ip: Some(client_ip_str),
        user_agent,
        slot_id: Some(slot_id_tx),
    };
    
    // Generate final hash if this is the last signature
    let final_hash_opt: Option<String> = {
        let new_count = completed_tx + 1;
        let is_fully_signed = new_count >= required_tx;
        
        if is_fully_signed {
            // Load all existing signatures first
            let existing_signatures: Vec<ContractSignature> = sig_dsl::contract_signatures
                .filter(sig_dsl::contract_id.eq(&contract_id))
                .select(ContractSignature::as_select())
                .load(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!("Database error loading signatures: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            
            // Combine with new signature data
            let mut sig_hashes: Vec<String> = existing_signatures.iter()
                .map(|s| s.signature_hash.clone())
                .collect();
            let mut sig_timestamps: Vec<String> = existing_signatures.iter()
                .map(|s| s.signed_at.clone())
                .collect();
            let mut sig_content_hashes: Vec<String> = existing_signatures.iter()
                .map(|s| s.content_hash.clone())
                .collect();
            
            // Add the new signature data
            sig_hashes.push(signature_hash);
            sig_timestamps.push(timestamp.clone());
            sig_content_hashes.push(content_hash);
            
            Some(crypto::generate_final_hash(
                &contract.content,
                &sig_hashes,
                &sig_timestamps,
                &sig_content_hashes,
            ))
        } else {
            None
        }
    };
    
    // Calculate progress values before moving into closure
    let new_count_val = completed_tx + 1;
    let is_fully_signed_val = new_count_val >= required_tx;
    let progress_completed = new_count_val;
    let progress_required = required_tx;
    
    // Execute operations sequentially (SQLite handles atomicity well)
    // Insert signature
    diesel::insert_into(sig_dsl::contract_signatures)
        .values(&new_signature)
        .execute(&mut conn)
        .await
        .map_err(|e| {
            let error_msg = e.to_string();
            if error_msg.contains("UNIQUE constraint failed") || error_msg.contains("idx_slot_signature") {
                tracing::warn!("Slot {} already signed (concurrent request)", slot_id_tx);
                StatusCode::CONFLICT
            } else {
                tracing::error!("Database error inserting signature: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    
    // Mark slot as filled
    diesel::update(slot_dsl::contract_signature_slots.filter(slot_dsl::id.eq(slot_id_tx)))
        .set(slot_dsl::is_filled.eq(true))
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating slot: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Update contract with new signature count and status
    diesel::update(contract_dsl::contracts.filter(contract_dsl::id.eq(&contract_id_tx)))
        .set((
            contract_dsl::completed_signatures.eq(new_count_val),
            contract_dsl::status.eq(if is_fully_signed_val { "signed".to_string() } else { "pending".to_string() }),
            contract_dsl::final_hash.eq(final_hash_opt.clone()),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating contract: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    let progress = SignatureProgress {
        completed: progress_completed,
        required: progress_required,
    };
    let fully_signed = is_fully_signed_val;
    
    Ok(Json(SignContractResponse {
        success: true,
        verification_code,
        signed_at: timestamp,
        progress,
        fully_signed,
    }))
}

/// Success page after signing
/// GET /contracts/signed/:contract_id/:verification_code?customer_uuid=xxx
pub async fn contract_signed_success(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((contract_id, verification_code)): Path<(String, String)>,
    Query(query): Query<CustomerUuidQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    use crate::schema::contract_signatures::dsl as sig_dsl;
    use crate::schema::contract_signature_slots::dsl as slot_dsl;
    use askama::Template;
    use askama_web::WebTemplate;
    
    // Check if customer_uuid is provided
    if query.customer_uuid.is_none() {
        // Show UUID gate template
        #[derive(Template, WebTemplate)]
        #[template(path = "contract_signed_gate.html")]
        struct SignedGateTemplate {
            contract_id_masked: String,
            verification_code_masked: String,
        }
        
        let template = SignedGateTemplate {
            contract_id_masked: mask_id(&contract_id),
            verification_code_masked: mask_id(&verification_code),
        };
        
        return Ok(template.into_response());
    }
    
    // Extract customer_uuid from query (we already checked is_none above)
    let customer_uuid = query.customer_uuid
        .expect("customer_uuid should be present after is_none check");
    
    // Check rate limit
    let client_ip = addr.ip();
    if rate_limiter.check_rate_limit(client_ip).await.is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Verify customer UUID matches contract
    let (contract, _customer) = match verify_customer_uuid(&mut conn, &contract_id, &customer_uuid).await {
        Ok(result) => {
            rate_limiter.reset_attempts(client_ip).await;
            result
        }
        Err(e) => {
            rate_limiter.record_failed_attempt(client_ip).await;
            return Err(e);
        }
    };
    
    // Fetch signature and verify it belongs to this contract
    let signature = sig_dsl::contract_signatures
        .filter(sig_dsl::contract_id.eq(&contract_id))
        .filter(sig_dsl::verification_code.eq(&verification_code))
        .select(ContractSignature::as_select())
        .first(&mut conn)
        .await
        .optional()
        .map_err(|e| {
            tracing::error!("Database error in contracts: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // Load all slots to show progress
    let slots: Vec<ContractSignatureSlot> = slot_dsl::contract_signature_slots
        .filter(slot_dsl::contract_id.eq(&contract_id))
        .order(slot_dsl::slot_order.asc())
        .select(ContractSignatureSlot::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error loading slots: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Load all signatures to show who's signed
    let signatures: Vec<ContractSignature> = sig_dsl::contract_signatures
        .filter(sig_dsl::contract_id.eq(&contract_id))
        .select(ContractSignature::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error loading signatures: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Render success template with full details
    #[derive(Template, WebTemplate)]
    #[template(path = "contract_signed.html")]
    struct ContractSignedTemplate<'a> {
        contract_id: &'a str,
        contract_title: &'a str,
        contract_type: &'a str,
        verification_code: &'a str,
        signed_at: &'a str,
        progress_completed: i32,
        progress_required: i32,
        fully_signed: bool,
        slots: &'a [ContractSignatureSlot],
        signatures: &'a [ContractSignature],
    }
    
    // Pre-compute values that need ownership
    let default_id = String::new();
    let signed_at_ist = utc_to_ist(&signature.signed_at);
    
    let template = ContractSignedTemplate {
        contract_id: contract.id.as_ref().unwrap_or(&default_id),
        contract_title: &contract.title,
        contract_type: &contract.contract_type,
        verification_code: &signature.verification_code,
        signed_at: &signed_at_ist,
        progress_completed: contract.completed_signatures,
        progress_required: contract.required_signatures,
        fully_signed: contract.status == "signed",
        slots: &slots,
        signatures: &signatures,
    };
    
    Ok(template.into_response())
}

/// Verify contract signature (public)
/// GET /contracts/verify/:contract_id/:verification_code?customer_uuid=xxx
pub async fn verify_contract(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((contract_id, verification_code)): Path<(String, String)>,
    Query(query): Query<CustomerUuidQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    use crate::schema::contract_signatures::dsl as sig_dsl;
    use crate::schema::contract_signature_slots::dsl as slot_dsl;
    use askama::Template;
    use askama_web::WebTemplate;
    
    // Check if customer_uuid is provided
    if query.customer_uuid.is_none() {
        // Show UUID gate template
        #[derive(Template, WebTemplate)]
        #[template(path = "contract_proof_gate.html")]
        struct ProofGateTemplate {
            contract_id_masked: String,
            verification_code_masked: String,
        }
        
        let template = ProofGateTemplate {
            contract_id_masked: mask_id(&contract_id),
            verification_code_masked: mask_id(&verification_code),
        };
        
        return Ok(template.into_response());
    }
    
    // Extract customer_uuid from query (we already checked is_none above)
    let customer_uuid = query.customer_uuid
        .expect("customer_uuid should be present after is_none check");
    
    // Check rate limit
    let client_ip = addr.ip();
    if rate_limiter.check_rate_limit(client_ip).await.is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection pool error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    // Verify customer UUID matches contract
    let (contract, _customer) = match verify_customer_uuid(&mut conn, &contract_id, &customer_uuid).await {
        Ok(result) => {
            rate_limiter.reset_attempts(client_ip).await;
            result
        }
        Err(e) => {
            rate_limiter.record_failed_attempt(client_ip).await;
            return Err(e);
        }
    };
    
    // Load all signature slots for this contract
    let slots: Vec<ContractSignatureSlot> = slot_dsl::contract_signature_slots
        .filter(slot_dsl::contract_id.eq(&contract_id))
        .order(slot_dsl::slot_order.asc())
        .select(ContractSignatureSlot::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error loading slots: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Load all signatures for this contract
    let signatures: Vec<ContractSignature> = sig_dsl::contract_signatures
        .filter(sig_dsl::contract_id.eq(&contract_id))
        .select(ContractSignature::as_select())
        .load(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error loading signatures: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    // Find the specific signature being verified
    let target_signature = signatures.iter()
        .find(|s| s.verification_code == verification_code)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // Verify each signature individually
    let verified_signatures: Vec<_> = signatures.iter().map(|sig| {
        let is_valid = crypto::verify_signature(
            &sig.public_key,
            &sig.signature_hash,
            &contract_id,
            &sig.content_hash,
            &sig.signed_at,
        );
        
        let current_hash = crypto::hash_content(&contract.content);
        let tampered = current_hash != sig.content_hash;
        
        VerifiedSignature {
            signature: sig.clone(),
            valid: is_valid,
            tampered,
        }
    }).collect();
    
    // Verify final hash if contract is fully signed
    let final_hash_valid = if let Some(ref final_hash) = contract.final_hash {
        if contract.status == "signed" {
            let sig_hashes: Vec<String> = signatures.iter()
                .map(|s| s.signature_hash.clone())
                .collect();
            let sig_timestamps: Vec<String> = signatures.iter()
                .map(|s| s.signed_at.clone())
                .collect();
            let sig_content_hashes: Vec<String> = signatures.iter()
                .map(|s| s.content_hash.clone())
                .collect();
            
            let recalculated = crypto::generate_final_hash(
                &contract.content,
                &sig_hashes,
                &sig_timestamps,
                &sig_content_hashes,
            );
            recalculated == *final_hash
        } else {
            false
        }
    } else {
        false
    };
    
    // Render proof template with full details
    #[derive(Template, WebTemplate)]
    #[template(path = "contract_proof.html")]
    struct ContractProofTemplate {
        contract_id: String,
        contract_title: String,
        contract_type: String,
        contract_customer_id: String,
        contract_status: String,
        contract_created_at: String,
        contract_content: String,
        verification_code: String,
        progress_completed: i32,
        progress_required: i32,
        fully_signed: bool,
        final_hash: Option<String>,
        final_hash_valid: bool,
        slots: Vec<ContractSignatureSlot>,
        verified_signatures: Vec<VerifiedSignature>,
    }
    
    let is_fully_signed = contract.status == "signed";
    
    let template = ContractProofTemplate {
        contract_id: contract.id.unwrap_or_default(),
        contract_title: contract.title,
        contract_type: contract.contract_type,
        contract_customer_id: contract.customer_id,
        contract_status: contract.status,
        contract_created_at: contract.created_at,
        contract_content: contract.content,
        verification_code: target_signature.verification_code,
        progress_completed: contract.completed_signatures,
        progress_required: contract.required_signatures,
        fully_signed: is_fully_signed,
        final_hash: contract.final_hash,
        final_hash_valid,
        slots,
        verified_signatures,
    };
    
    Ok(template.into_response())
}

/// Helper struct for verified signature information
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    pub signature: ContractSignature,
    pub valid: bool,
    pub tampered: bool,
}

/// Download/view printable proof
/// Same as verify_contract - both use the proof template
pub async fn download_proof(
    State(pool): State<DbPool>,
    Extension(rate_limiter): Extension<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((contract_id, verification_code)): Path<(String, String)>,
    Query(query): Query<CustomerUuidQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    verify_contract(State(pool), Extension(rate_limiter), ConnectInfo(addr), Path((contract_id, verification_code)), Query(query)).await
}

// ── CRUD trait implementation ────────────────────────────────────────────────

impl CrudModel for Contract {
    type Row = Contract;
    type Payload = ContractPayload;

    async fn all(conn: &mut crate::db::Conn) -> QueryResult<Vec<Contract>> {
        use crate::schema::contracts::dsl;
        dsl::contracts.select(Contract::as_select()).load(conn).await
    }

    async fn find(conn: &mut crate::db::Conn, id: &str) -> QueryResult<Option<Contract>> {
        use crate::schema::contracts::dsl;
        dsl::contracts
            .filter(dsl::id.eq(id))
            .select(Contract::as_select())
            .first(conn)
            .await
            .optional()
    }

    async fn insert(conn: &mut crate::db::Conn, mut payload: ContractPayload) -> QueryResult<Contract> {
        use crate::schema::contracts::dsl;
        
        let id = Uuid::new_v4().to_string();
        payload.id = Some(id.clone());
        
        if payload.created_at.is_empty() {
            payload.created_at = Utc::now().to_rfc3339();
        }
        
        if payload.status.is_empty() {
            payload.status = "pending".to_string();
        }
        
        // Set default signature counts for backward compatibility
        if payload.required_signatures == 0 {
            payload.required_signatures = 1;
        }
        
        diesel::insert_into(dsl::contracts)
            .values(&payload)
            .execute(conn)
            .await?;
        
        dsl::contracts
            .filter(dsl::id.eq(&id))
            .select(Contract::as_select())
            .first(conn)
            .await
    }

    async fn update(
        conn: &mut crate::db::Conn,
        id: &str,
        payload: ContractPayload,
    ) -> QueryResult<Option<Contract>> {
        use crate::schema::contracts::dsl;
        
        // Note: payload.id is not set here - ID is immutable and specified in the filter
        
        let updated = diesel::update(dsl::contracts.filter(dsl::id.eq(id)))
            .set(&payload)
            .execute(conn)
            .await?;
        
        if updated == 0 {
            return Ok(None);
        }
        
        dsl::contracts
            .filter(dsl::id.eq(id))
            .select(Contract::as_select())
            .first(conn)
            .await
            .optional()
    }

    async fn delete(conn: &mut crate::db::Conn, id: &str) -> QueryResult<bool> {
        use crate::schema::contracts::dsl;
        
        let deleted = diesel::delete(dsl::contracts.filter(dsl::id.eq(id)))
            .execute(conn)
            .await?;
        
        Ok(deleted > 0)
    }
}
