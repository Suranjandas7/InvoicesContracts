use diesel::prelude::*;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::schema::{
    contract_signature_slots, contract_signatures, contracts, customer, invoices, jwt_tokens, refresh_tokens, user,
};

// ── JSON map serde helpers ────────────────────────────────────────────────────
//
// line_charges and after_line_items are stored as JSON strings in SQLite TEXT
// columns.  These helpers make them appear as plain JSON objects in the API.

/// Serialise a DB JSON string as a proper JSON object (for API responses).
fn serialize_json_str<S>(val: &Option<String>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match val {
        None => s.serialize_none(),
        Some(src) => match serde_json::from_str::<serde_json::Value>(src) {
            Ok(v) => v.serialize(s),
            Err(_) => s.serialize_none(),
        },
    }
}

/// Deserialise a JSON object from an API request into a JSON string for DB storage.
fn deserialize_json_obj<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val: Option<serde_json::Value> = Option::deserialize(d)?;
    Ok(val.and_then(|v| {
        if v.is_null() {
            None
        } else {
            serde_json::to_string(&v).ok()
        }
    }))
}

/// Deserializes an optional number or string from JSON into an optional String for TEXT storage.
/// Accepts both `230` (number) and `"230"` (string) from API for nullable fields like payment_made.
fn deserialize_opt_number_to_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let opt_val: Option<serde_json::Value> = Option::deserialize(d)?;
    match opt_val {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => Ok(Some(n.to_string())),
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        _ => Err(D::Error::custom("expected number, string, or null")),
    }
}

// User model (Queryable from existing user table)
#[derive(Debug, Queryable, Selectable, Serialize)]
#[diesel(table_name = user)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub address: String,
    pub tax_id: String,
    #[serde(skip_serializing)]
    pub password: String,
}

// Insert model (no id field - auto-generated)
#[derive(Debug, Insertable, Deserialize)]
#[diesel(table_name = user)]
pub struct CreateUser {
    pub name: String,
    pub email: String,
}

// Insert model for full user creation (first setup)
#[derive(Debug, Insertable)]
#[diesel(table_name = user)]
pub struct CreateFullUser {
    pub name: String,
    pub email: String,
    pub address: String,
    pub tax_id: String,
    pub password: String,
}

// Insert model for JWT tokens
#[derive(Debug, Insertable)]
#[diesel(table_name = jwt_tokens)]
pub struct CreateJwtToken {
    pub user_id: i32,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

// Refresh Token model
#[allow(dead_code)]
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = refresh_tokens)]
pub struct RefreshToken {
    pub id: i32,
    pub user_id: i32,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
    pub revoked: bool,
}

// Insert model for refresh tokens
#[derive(Debug, Insertable)]
#[diesel(table_name = refresh_tokens)]
pub struct CreateRefreshToken {
    pub user_id: i32,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i32,
    pub email: String,
    pub exp: i64, // Expiry timestamp
    pub iat: i64, // Issued at timestamp
}

// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: i32,
    pub name: String,
    pub email: String,
}

// ── Customer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = customer)]
pub struct Customer {
    pub id: Option<String>,
    pub name: String,
    pub address: Option<String>,
    pub currency: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Insertable, AsChangeset, Deserialize)]
#[diesel(table_name = customer)]
pub struct CustomerPayload {
    pub id: Option<String>,
    pub name: String,
    pub address: Option<String>,
    pub currency: Option<String>,
    pub is_active: Option<bool>,
}

// ── Invoice ──────────────────────────────────────────────────────────────────

#[derive(Debug, Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = invoices)]
pub struct Invoice {
    pub id: Option<String>,
    pub serial_no: i32,
    pub customer_id: String,
    // amount field removed - total is computed dynamically from line_charges
    pub due_date: Option<String>,
    pub status: Option<String>,
    /// Stored as TEXT in SQLite for precise payment tracking (nullable).
    /// Use payment_made_decimal() to get the Decimal value.
    pub payment_made: Option<String>,
    /// Key-value line charges, e.g. {"15 hours x $100": 1500.0}.
    /// Stored as a JSON string in SQLite; serialised as an object in the API.
    /// This is the SOURCE OF TRUTH for invoice totals.
    #[serde(serialize_with = "serialize_json_str")]
    pub line_charges: Option<String>,
    /// Key-value after-line items such as taxes/discounts, e.g. {"GST Tax": 0.215}.
    /// Stored as a JSON string in SQLite; serialised as an object in the API.
    /// Percentages are applied to the subtotal to calculate the final total.
    #[serde(serialize_with = "serialize_json_str")]
    pub after_line_items: Option<String>,
    pub memo: Option<String>,
}

impl Invoice {
    /// Get payment_made as Decimal (parsed from TEXT storage).
    pub fn payment_made_decimal(&self) -> Option<Decimal> {
        self.payment_made.as_ref().and_then(|s| Decimal::from_str_exact(s).ok())
    }

    /// Compute subtotal from line_charges JSON.
    /// Returns Decimal sum of all line item amounts.
    #[allow(dead_code)]
    pub fn compute_subtotal(&self) -> Decimal {
        self.line_charges.as_ref().and_then(|s| {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s).ok()
        }).map(|map| {
            map.values()
                .filter_map(|v| v.as_f64())
                .filter_map(|f| Decimal::try_from(f).ok())
                .sum()
        }).unwrap_or(Decimal::ZERO)
    }
    
    /// Compute total from subtotal + after_line_items percentages.
    /// Handles precise percentages like 0.215 (21.5%).
    #[allow(dead_code)]
    pub fn compute_total(&self) -> Decimal {
        let subtotal = self.compute_subtotal();
        let adjustments: Decimal = self.after_line_items.as_ref().and_then(|s| {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s).ok()
        }).map(|map| {
            map.values()
                .filter_map(|v| v.as_f64())
                .filter_map(|f| Decimal::try_from(f).ok())
                .map(|percentage| subtotal * percentage)
                .sum()
        }).unwrap_or(Decimal::ZERO);
        
        subtotal + adjustments
    }
}

#[derive(Debug, Insertable, AsChangeset, Deserialize)]
#[diesel(table_name = invoices)]
pub struct InvoicePayload {
    pub id: Option<String>,
    pub serial_no: i32,
    pub customer_id: String,
    // amount field removed - total is computed dynamically from line_charges
    pub due_date: Option<String>,
    pub status: Option<String>,
    /// Stored as TEXT in SQLite for precise payment tracking (nullable).
    /// Accepts both numbers and strings from the API.
    #[serde(deserialize_with = "deserialize_opt_number_to_string")]
    pub payment_made: Option<String>,
    /// Key-value line charges, e.g. {"15 hours x $100": 1500.0}.
    /// This is the SOURCE OF TRUTH for invoice totals.
    #[serde(deserialize_with = "deserialize_json_obj")]
    pub line_charges: Option<String>,
    /// Key-value after-line items such as taxes/discounts, e.g. {"GST Tax": 0.215}.
    /// Percentages are applied to the subtotal.
    #[serde(deserialize_with = "deserialize_json_obj")]
    pub after_line_items: Option<String>,
    pub memo: Option<String>,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[derive(Debug, Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = contracts)]
pub struct Contract {
    pub id: Option<String>,
    pub customer_id: String,
    pub contract_type: String,
    pub title: String,
    pub content: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
    pub required_signatures: i32,
    pub completed_signatures: i32,
    pub final_hash: Option<String>,
}

#[derive(Debug, Insertable, AsChangeset, Deserialize)]
#[diesel(table_name = contracts)]
pub struct ContractPayload {
    pub id: Option<String>,
    pub customer_id: String,
    pub contract_type: String,
    pub title: String,
    pub content: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
    pub required_signatures: i32,
    pub completed_signatures: i32,
    pub final_hash: Option<String>,
}

// ── Contract Signature ───────────────────────────────────────────────────────

#[derive(Debug, Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = contract_signatures)]
pub struct ContractSignature {
    pub id: i32,
    pub contract_id: String,
    pub verification_code: String,
    pub signature_hash: String,
    pub public_key: String,
    pub content_hash: String,
    pub signed_at: String,
    pub signer_name: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub slot_id: Option<i32>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = contract_signatures)]
pub struct CreateContractSignature {
    pub contract_id: String,
    pub verification_code: String,
    pub signature_hash: String,
    pub public_key: String,
    pub content_hash: String,
    pub signed_at: String,
    pub signer_name: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub slot_id: Option<i32>,
}

// ── Contract Signature Slots ─────────────────────────────────────────────────

#[derive(Debug, Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = contract_signature_slots)]
pub struct ContractSignatureSlot {
    pub id: Option<i32>,
    pub contract_id: String,
    pub slot_name: Option<String>,
    pub slot_order: i32,
    pub is_filled: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = contract_signature_slots)]
pub struct CreateContractSignatureSlot {
    pub contract_id: String,
    pub slot_name: Option<String>,
    pub slot_order: i32,
    pub is_filled: bool,
}

// ── Contract API models ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SignContractRequest {
    pub customer_uuid: String,
    pub slot_id: i32,
    pub signer_name: Option<String>,
    pub accepted: bool,
}

#[derive(Debug, Serialize)]
pub struct SignatureProgress {
    pub completed: i32,
    pub required: i32,
}

#[derive(Debug, Serialize)]
pub struct SignContractResponse {
    pub success: bool,
    pub verification_code: String,
    pub signed_at: String,
    pub progress: SignatureProgress,
    pub fully_signed: bool,
}

// Query parameter for customer UUID verification
#[derive(Debug, Deserialize)]
pub struct CustomerUuidQuery {
    pub customer_uuid: Option<String>,
}

// Signature slot definition for creating contracts
#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureSlotDefinition {
    pub name: Option<String>,  // Optional name like "Manager", "Legal"
    pub order: i32,            // Display order
}

// Request for creating contract with signature slots
#[derive(Debug, Deserialize)]
pub struct CreateContractRequest {
    pub customer_id: String,
    pub contract_type: String,
    pub title: String,
    pub content: String,
    pub expires_at: Option<String>,
    pub signature_slots: Vec<SignatureSlotDefinition>,
}

// Response showing available slots for signing
#[derive(Debug, Serialize)]
pub struct ContractSignatureSlotsResponse {
    pub slots: Vec<ContractSignatureSlot>,
    pub progress: SignatureProgress,
}

// Contract view response with slots
#[derive(Debug, Serialize)]
pub struct ContractViewResponse {
    pub contract: Contract,
    pub slots: Vec<ContractSignatureSlot>,
    pub signatures: Vec<ContractSignature>,
    pub progress: SignatureProgress,
}

// ── First User Setup ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub name: String,
    pub email: String,
    pub address: String,
    pub tax_id: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    pub success: bool,
    pub message: String,
    pub redirect: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckSetupResponse {
    pub needs_setup: bool,
}

// ── User Profile Update ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub name: String,
    pub email: String,
    pub address: String,
    pub tax_id: String,
    pub current_password: Option<String>,
    pub new_password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub address: String,
    pub tax_id: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserResponse {
    pub success: bool,
    pub message: String,
}
