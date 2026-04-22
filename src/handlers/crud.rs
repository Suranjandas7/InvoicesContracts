use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::{de::DeserializeOwned, Serialize};
use std::future::Future;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::db::DbPool;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Implement this trait for each model that needs generic CRUD endpoints.
/// Each method receives an open async connection and returns a Future.
pub trait CrudModel: Send + Sync + 'static {
    type Row: Serialize + Send + 'static;
    type Payload: DeserializeOwned + Send + 'static;

    fn all(
        conn: &mut crate::db::Conn,
    ) -> impl Future<Output = QueryResult<Vec<Self::Row>>> + Send;

    fn find(
        conn: &mut crate::db::Conn,
        id: &str,
    ) -> impl Future<Output = QueryResult<Option<Self::Row>>> + Send;

    fn insert(
        conn: &mut crate::db::Conn,
        payload: Self::Payload,
    ) -> impl Future<Output = QueryResult<Self::Row>> + Send;

    fn update(
        conn: &mut crate::db::Conn,
        id: &str,
        payload: Self::Payload,
    ) -> impl Future<Output = QueryResult<Option<Self::Row>>> + Send;

    fn delete(
        conn: &mut crate::db::Conn,
        id: &str,
    ) -> impl Future<Output = QueryResult<bool>> + Send;
}

// ── Generic handlers ──────────────────────────────────────────────────────────

async fn list<M: CrudModel>(
    _user: AuthUser,
    State(pool): State<DbPool>,
) -> Result<Json<Vec<M::Row>>, StatusCode> {
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection error in list: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    M::all(&mut conn)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Database error fetching all records: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn create<M: CrudModel>(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Json(payload): Json<M::Payload>,
) -> Result<(StatusCode, Json<M::Row>), StatusCode> {
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection error in create: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    M::insert(&mut conn, payload)
        .await
        .map(|row| (StatusCode::CREATED, Json(row)))
        .map_err(|e| {
            tracing::error!("Database error inserting record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn read_one<M: CrudModel>(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Path(id): Path<String>,
) -> Result<Json<M::Row>, StatusCode> {
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection error in read_one: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    M::find(&mut conn, &id)
        .await
        .map_err(|e| {
            tracing::error!("Database error finding record '{}': {}", id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update<M: CrudModel>(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Path(id): Path<String>,
    Json(payload): Json<M::Payload>,
) -> Result<Json<M::Row>, StatusCode> {
    let mut conn = pool.get().await.map_err(|e| {
        tracing::error!("Database connection error in update: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    M::update(&mut conn, &id, payload)
        .await
        .map_err(|e| {
            tracing::error!("Database error updating record '{}': {}", id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn delete_one<M: CrudModel>(
    _user: AuthUser,
    State(pool): State<DbPool>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Database connection error in delete_one: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    match M::delete(&mut conn, &id).await {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(e) => {
            tracing::error!("Database error deleting record '{}': {}", id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// ── Router builder ────────────────────────────────────────────────────────────

pub fn crud_router<M: CrudModel>(pool: DbPool) -> Router<DbPool> {
    Router::new()
        .route("/", get(list::<M>).post(create::<M>))
        .route("/{id}", get(read_one::<M>).put(update::<M>).delete(delete_one::<M>))
        .with_state(pool)
}

// ── Customer impl ─────────────────────────────────────────────────────────────

use crate::models::{Customer, CustomerPayload};
use crate::schema::customer::dsl;

impl CrudModel for Customer {
    type Row = Customer;
    type Payload = CustomerPayload;

    async fn all(conn: &mut crate::db::Conn) -> QueryResult<Vec<Customer>> {
        dsl::customer.select(Customer::as_select()).load(conn).await
    }

    async fn find(conn: &mut crate::db::Conn, id: &str) -> QueryResult<Option<Customer>> {
        dsl::customer
            .filter(dsl::id.eq(id))
            .select(Customer::as_select())
            .first(conn)
            .await
            .optional()
    }

    async fn insert(conn: &mut crate::db::Conn, mut payload: CustomerPayload) -> QueryResult<Customer> {
        let id = Uuid::new_v4().to_string();
        payload.id = Some(id.clone());
        diesel::insert_into(dsl::customer)
            .values(&payload)
            .returning(Customer::as_returning())
            .get_result(conn)
            .await
    }

    async fn update(
        conn: &mut crate::db::Conn,
        id: &str,
        mut payload: CustomerPayload,
    ) -> QueryResult<Option<Customer>> {
        payload.id = Some(id.to_string());
        let updated = diesel::update(dsl::customer.filter(dsl::id.eq(id)))
            .set(&payload)
            .execute(conn)
            .await?;
        if updated == 0 {
            return Ok(None);
        }
        dsl::customer
            .filter(dsl::id.eq(id))
            .select(Customer::as_select())
            .first(conn)
            .await
            .optional()
    }

    async fn delete(conn: &mut crate::db::Conn, id: &str) -> QueryResult<bool> {
        let deleted = diesel::delete(dsl::customer.filter(dsl::id.eq(id)))
            .execute(conn)
            .await?;
        Ok(deleted > 0)
    }
}

// ── Invoice impl ──────────────────────────────────────────────────────────────

use crate::models::{Invoice, InvoicePayload};
use crate::schema::invoices::dsl as inv_dsl;

impl CrudModel for Invoice {
    type Row = Invoice;
    type Payload = InvoicePayload;

    async fn all(conn: &mut crate::db::Conn) -> QueryResult<Vec<Invoice>> {
        inv_dsl::invoices
            .select(Invoice::as_select())
            .load(conn)
            .await
    }

    async fn find(conn: &mut crate::db::Conn, id: &str) -> QueryResult<Option<Invoice>> {
        inv_dsl::invoices
            .filter(inv_dsl::id.eq(id))
            .select(Invoice::as_select())
            .first(conn)
            .await
            .optional()
    }

    async fn insert(conn: &mut crate::db::Conn, mut payload: InvoicePayload) -> QueryResult<Invoice> {
        let id = Uuid::new_v4().to_string();
        payload.id = Some(id.clone());
        diesel::insert_into(inv_dsl::invoices)
            .values(&payload)
            .returning(Invoice::as_returning())
            .get_result(conn)
            .await
    }

    async fn update(
        conn: &mut crate::db::Conn,
        id: &str,
        mut payload: InvoicePayload,
    ) -> QueryResult<Option<Invoice>> {
        payload.id = Some(id.to_string());
        let updated = diesel::update(inv_dsl::invoices.filter(inv_dsl::id.eq(id)))
            .set(&payload)
            .execute(conn)
            .await?;
        if updated == 0 {
            return Ok(None);
        }
        inv_dsl::invoices
            .filter(inv_dsl::id.eq(id))
            .select(Invoice::as_select())
            .first(conn)
            .await
            .optional()
    }

    async fn delete(conn: &mut crate::db::Conn, id: &str) -> QueryResult<bool> {
        let deleted = diesel::delete(inv_dsl::invoices.filter(inv_dsl::id.eq(id)))
            .execute(conn)
            .await?;
        Ok(deleted > 0)
    }
}


