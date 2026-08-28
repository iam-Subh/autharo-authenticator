//! The server binary. Everything of substance is in the library beside it,
//! so the tests exercise the same router this serves.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use authserver::{AppState, SharedState, crypto, migrate, router};
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

    let max_connections = database_max_connections()?;
    let db = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    migrate(&db).await?;

    let fake_auth_hash = crypto::hash_auth_key(&[0u8; 32])
        .expect("the server must be able to create its login timing hash");
    let passkeys = authserver::passkey::PasskeyService::from_environment()?;
    let push = authserver::push::FcmDispatcher::from_environment().await?;
    let identity =
        authserver::identity::FirebaseIdentityVerifier::from_environment()?.map(Arc::new);
    if identity.is_none() && !cfg!(debug_assertions) {
        anyhow::bail!(
            "FIREBASE_AUTH_PROJECT_ID must be set for a release server. Account registration requires a verified email identity."
        );
    }
    let state: SharedState = Arc::new(AppState {
        db,
        server_key,
        fake_auth_hash,
        passkeys,
        push,
        identity,
    });
    let address = bind_address(
        std::env::var("BIND").ok().as_deref(),
        std::env::var("PORT").ok().as_deref(),
    )?;

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!("listening on {}", listener.local_addr()?);

    axum::serve(
        listener,
        // ConnectInfo, so section 9.5's per-address rate limit can see who is
        // calling. Without it the extractor fails and every sign-in 500s.
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Uses an explicit local bind first, then the port supplied by a cloud host.
fn bind_address(bind: Option<&str>, port: Option<&str>) -> anyhow::Result<SocketAddr> {
    let value = match (bind.map(str::trim), port.map(str::trim)) {
        (Some(bind), _) if !bind.is_empty() => bind.to_string(),
        (_, Some(port)) if !port.is_empty() => format!("0.0.0.0:{port}"),
        _ => "127.0.0.1:8080".to_string(),
    };
    value
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid server bind address {value:?}: {error}"))
}

fn database_max_connections() -> anyhow::Result<u32> {
    let value = std::env::var("DATABASE_MAX_CONNECTIONS").unwrap_or_else(|_| "16".to_string());
    let parsed = value
        .parse::<u32>()
        .map_err(|error| anyhow::anyhow!("DATABASE_MAX_CONNECTIONS must be an integer: {error}"))?;
    if !(1..=64).contains(&parsed) {
        anyhow::bail!("DATABASE_MAX_CONNECTIONS must be between 1 and 64");
    }
    Ok(parsed)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "could not install the Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "could not install the SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}

/// Reads the server key from the environment.
///
/// Required in a release build. A generated-at-startup key would change on
/// every restart, and the fake salts with it — which would tell an attacker
/// that an address has no account, because a real account's salt is stable
/// across restarts and a fabricated one would not be.
fn load_server_key() -> anyhow::Result<Vec<u8>> {
    match std::env::var("SERVER_KEY") {
        Ok(value) if value.len() >= 32 => Ok(value.into_bytes()),
        Ok(_) => anyhow::bail!(
            "SERVER_KEY must contain at least 32 bytes of random data. A short key lets an attacker predict fabricated prelogin salts."
        ),
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

#[cfg(test)]
mod deployment_tests {
    use super::bind_address;

    #[test]
    fn explicit_bind_has_priority() {
        let address = bind_address(Some("127.0.0.1:9090"), Some("10000")).unwrap();
        assert_eq!(address.to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn cloud_port_binds_all_interfaces() {
        let address = bind_address(None, Some("10000")).unwrap();
        assert_eq!(address.to_string(), "0.0.0.0:10000");
    }

    #[test]
    fn local_default_remains_private() {
        let address = bind_address(None, None).unwrap();
        assert_eq!(address.to_string(), "127.0.0.1:8080");
    }
}
