//! The sync server (PRD stage S4).
//!
//! # What this server can and cannot do
//!
//! It stores ciphertext and hands it back. It cannot read a vault: every
//! record arrives encrypted under a vault key that never leaves a client
//! (section 9.2), and every key slot arrives already wrapped. The exit
//! criterion for this stage is a dump of the database containing no plaintext
//! issuer, account name, or secret, and `tests/dump.rs` asserts exactly that
//! by putting a known string in a secret and grepping `pg_dump` for it.
//!
//! # What is deliberately absent
//!
//! The sync engine. Stage S4 ends at the dump test; the cycle, the conflict
//! resolution, and the outbox drain are S5, with their own convergence test.
//! The record endpoints here store and return rows — they do not merge.
//!
//! This is a library so that the tests build the same router the binary
//! serves. A test that exercised a second, similar router would prove
//! something about the test rather than about the server.

pub mod account;
pub mod auth;
pub mod crypto;
pub mod error;
pub mod quota;
pub mod ratelimit;
pub mod share;
pub mod vault;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};

/// Shared state. One pool, one server key.
pub struct AppState {
    pub db: sqlx::PgPool,
    /// The key behind the fake prelogin salt (section 9.5). Held only in
    /// memory and in the environment; it never reaches the database, because a
    /// dump that contained it would let an attacker recognise a fabricated
    /// salt and so answer the question the fake exists to refuse.
    pub server_key: Vec<u8>,
    /// A valid Argon2 hash used to equalize unknown-account login work.
    pub fake_auth_hash: String,
}

pub type SharedState = Arc<AppState>;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/prelogin", post(auth::prelogin))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/refresh", post(auth::refresh))
        // Section 9.5. Grouped here rather than under /v1/account because a
        // user thinks of signing out as an authentication action, and the
        // route table is read by people as well as by clients.
        .route("/v1/auth/logout", post(account::sign_out))
        .route("/v1/auth/logout-all", post(account::sign_out_everywhere))
        .route("/v1/devices", get(account::list_devices))
        .route("/v1/devices/{id}", delete(account::revoke_device))
        .route("/v1/account", delete(account::delete_account))
        .route("/v1/vault/records", post(vault::push_records))
        .route("/v1/vault/changes", get(vault::pull_changes))
        .route("/v1/shares", post(share::create))
        .route(
            "/v1/shares/{id}",
            get(share::retrieve).delete(share::revoke),
        )
        .route("/v1/health", get(|| async { "ok" }))
        // Keep unauthenticated JSON allocation and authenticated batch input
        // within a known process-memory bound.
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state)
}

/// Applies the migrations. Embedded at compile time, so a deployment cannot
/// run against a schema it was not built for.
pub async fn migrate(db: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(db).await
}
