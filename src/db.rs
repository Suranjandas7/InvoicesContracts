use diesel::sqlite::SqliteConnection;
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;
use diesel_async::pooled_connection::{bb8::Pool, AsyncDieselConnectionManager};

pub type DbPool = Pool<SyncConnectionWrapper<SqliteConnection>>;
pub type Conn = SyncConnectionWrapper<SqliteConnection>;

pub async fn create_pool() -> DbPool {
	let config = AsyncDieselConnectionManager::<SyncConnectionWrapper<SqliteConnection>>::new("database.db");
	Pool::builder()
		.max_size(10)  // Limit to 10 connections for SQLite
		.build(config)
		.await
		.expect("Failed to create pool")
}
