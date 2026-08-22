//! The server binary. Everything of substance is in the library beside it,
//! so the tests exercise the same router this serves.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use authserver::{AppState, SharedState, migrate, router};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://authcore:devonly@127.0.0.1:15432/authcore".to_string());

    let server_key = load_server_key()?;

    let db = PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    migrate(&db).await?;

    let state: SharedState = Arc::new(AppState { db, server_key });
    let address: SocketAddr = std::env::var("BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!("listening on {}", listener.local_addr()?);

    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// Reads the server key from the environment.
///
/// Required in a release build. A generated-at-startup key would change on
/// every restart, and the fake salts with it — which would tell an attacker
/// that an address has no account, because a real account's salt is stable
/// across restarts and a fabricated one would not be.
fn load_server_key() -> anyhow::Result<Vec<u8>> {
    match std::env::var("SERVER_KEY") {
        Ok(value) if !value.is_empty() => Ok(value.into_bytes()),
        _ if cfg!(debug_assertions) => {
            tracing::warn!(
                "SERVER_KEY is not set; using a fixed development key. Fake                  prelogin salts are predictable with this key."
            );
            Ok(b"development-only-server-key".to_vec())
        }
        _ => anyhow::bail!(
            "SERVER_KEY must be set. Without it the fake prelogin salts in              section 9.5 change at every restart, which tells an attacker              which addresses have no account."
        ),
    }
}
