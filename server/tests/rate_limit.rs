//! Section 9.5's sign-in rate limit, and the trap inside it.
//!
//! "Rate-limit sign-in to 10 attempts per account per hour and 100 per IP
//! address per hour."
//!
//! The interesting test here is not that the eleventh attempt is refused. It is
//! that a *made-up* address is refused on the same attempt as a real one.
//!
//! The obvious implementation counts against an account, which means looking the
//! account up first, which means an unknown address cannot be counted — so the
//! eleventh attempt returns `429` for a real account and `401` for an invented
//! one, and the status code answers precisely the question that `prelogin`'s
//! fake salt and timing floor exist to refuse. All of that work, undone by a
//! counter, with every individual piece still passing its own test.
//!
//! Requires the development database from README.md.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

/// These tests share one counter, so they run one at a time.
///
/// Every test here clears `auth_attempt` before it starts, and the per-address
/// limit is keyed on 127.0.0.1 for all of them. Run in parallel they wipe each
/// other's counts — which showed up as the eleventh attempt returning 401,
/// looking exactly like a broken limiter. The defect was in the test setup.
///
/// Clearing is still needed: the address count would otherwise accumulate
/// across repeated `cargo test` runs until every test failed for the wrong
/// reason.
static SERIAL: Mutex<()> = Mutex::const_new(());

use authserver::{AppState, SharedState, migrate, router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://authcore:devonly@127.0.0.1:15432/authcore".to_string())
}

async fn start_server() -> (
    SocketAddr,
    sqlx::PgPool,
    tokio::sync::MutexGuard<'static, ()>,
) {
    let guard = SERIAL.lock().await;
    let db = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url())
        .await
        .expect("the development database must be running: docker start authcore-pg");
    migrate(&db).await.expect("migrations must apply");

    // Every test here counts attempts, and the counter is shared. Cleared so a
    // previous run cannot make this one pass or fail.
    sqlx::query("DELETE FROM auth_attempt")
        .execute(&db)
        .await
        .unwrap();

    let state: SharedState = Arc::new(AppState {
        db: db.clone(),
        server_key: b"test-server-key".to_vec(),
        fake_auth_hash: authserver::crypto::hash_auth_key(&[0u8; 32]).unwrap(),
        passkeys: None,
        push: None,
        identity: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (address, db, guard)
}

fn unique_email(prefix: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{stamp:x}@example.invalid")
}

/// One sign-in attempt with a deliberately wrong key. Returns the status.
async fn attempt(client: &reqwest::Client, base: &str, email: &str) -> reqwest::StatusCode {
    client
        .post(format!("{base}/v1/auth/login"))
        .json(&json!({
            "email": email,
            "auth_key": B64.encode([0x99u8; 32]),
        }))
        .send()
        .await
        .unwrap()
        .status()
}

/// The eleventh attempt is refused, with the header section 13 requires.
#[tokio::test]
async fn a_run_of_sign_in_attempts_is_refused() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let email = unique_email("limited");

    for i in 1..=10 {
        assert_eq!(
            attempt(&client, &base, &email).await,
            reqwest::StatusCode::UNAUTHORIZED,
            "attempt {i} is within section 9.5's ten per hour"
        );
    }

    let response = client
        .post(format!("{base}/v1/auth/login"))
        .json(&json!({ "email": email, "auth_key": B64.encode([0x99u8; 32]) }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "the eleventh must be refused"
    );

    // Section 13. Without it a client guesses, and a client that guesses short
    // comes straight back — which is the traffic the limit exists to stop.
    let retry_after = response
        .headers()
        .get("retry-after")
        .expect("section 13 requires a Retry-After header")
        .to_str()
        .unwrap()
        .parse::<i64>()
        .expect("Retry-After must be a number of seconds");

    assert!(
        retry_after > 0 && retry_after <= 3600,
        "a wait of {retry_after}s is outside the one-hour window"
    );
}

/// The one that matters: an unknown address is limited exactly like a known one.
///
/// If it were not, the status code on the eleventh attempt would say whether an
/// account exists — and that is the question section 9.5's fake salt and timing
/// floor are built to refuse.
#[tokio::test]
async fn an_unknown_address_is_limited_exactly_like_a_real_one() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    // A real account.
    let real = unique_email("real");
    let slot = json!({
        "wrapped_key": B64.encode([0x11u8; 48]),
        "nonce": B64.encode([0x22u8; 24]),
    });
    let registered = client
        .post(format!("{base}/v1/auth/register"))
        .json(&json!({
            "email": real,
            "auth_key": B64.encode([0x33u8; 32]),
            "recovery_auth_key": B64.encode([0x77u8; 32]),
            "kdf_params": { "m": 65536, "t": 3, "p": 4 },
            "client_salt": B64.encode([0x44u8; 16]),
            "password_slot": slot,
            "recovery_slot": slot,
        }))
        .send()
        .await
        .unwrap();
    assert!(registered.status().is_success());

    // And one that was never registered.
    let invented = unique_email("invented");

    let mut real_statuses = Vec::new();
    let mut invented_statuses = Vec::new();
    for _ in 1..=11 {
        real_statuses.push(attempt(&client, &base, &real).await);
        invented_statuses.push(attempt(&client, &base, &invented).await);
    }

    assert_eq!(
        real_statuses, invented_statuses,
        "the two addresses were answered differently, so the sequence of status \
         codes tells an attacker which one exists. The limit must count the \
         submitted address whether or not it names an account."
    );
    assert_eq!(
        real_statuses.last(),
        Some(&reqwest::StatusCode::TOO_MANY_REQUESTS),
        "and both must actually reach the limit, or this proves nothing"
    );
}

/// One address hitting the limit does not lock out another.
///
/// Otherwise anyone could take any account offline by spending ten attempts an
/// hour on it, which is a denial of service handed out for free.
#[tokio::test]
async fn one_address_being_limited_does_not_affect_another() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let victim = unique_email("victim");
    let bystander = unique_email("bystander");

    for _ in 1..=11 {
        attempt(&client, &base, &victim).await;
    }
    assert_eq!(
        attempt(&client, &base, &victim).await,
        reqwest::StatusCode::TOO_MANY_REQUESTS
    );

    assert_eq!(
        attempt(&client, &base, &bystander).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "a different address must still be able to try"
    );
}

/// A forged `X-Forwarded-For` does not sidestep the per-address limit.
///
/// Trusting that header unconditionally turns the limit into a formality: an
/// attacker sends a different value each time and is never counted. It is read
/// only when the direct peer belongs to `TRUSTED_PROXY_CIDRS`.
#[tokio::test]
async fn a_forged_forwarded_header_is_ignored_by_default() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let email = unique_email("forged");

    for i in 1..=11 {
        let response = client
            .post(format!("{base}/v1/auth/login"))
            .header("x-forwarded-for", format!("10.0.0.{i}"))
            .json(&json!({ "email": email, "auth_key": B64.encode([0x99u8; 32]) }))
            .send()
            .await
            .unwrap();
        if i <= 10 {
            assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        }
    }

    let response = client
        .post(format!("{base}/v1/auth/login"))
        .header("x-forwarded-for", "10.0.0.250")
        .json(&json!({ "email": email, "auth_key": B64.encode([0x99u8; 32]) }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "a new forwarded address per request must not reset the count"
    );
}

/// Prelogin must use only the caller address. A constant account subject would
/// make the eleventh request block prelogin for the complete service.
#[tokio::test]
async fn prelogin_requests_do_not_create_a_global_ten_request_limit() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    for i in 1..=11 {
        let response = client
            .post(format!("{base}/v1/auth/prelogin"))
            .json(&json!({ "email": unique_email(&format!("prelogin-{i}")) }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "request {i} was blocked by a shared prelogin subject"
        );
    }
}

/// Invalid registration requests still consume the address budget. The
/// limiter runs before decoding and before Argon2 work.
#[tokio::test]
async fn registration_is_limited_before_expensive_hashing() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    for i in 1..=10 {
        let response = client
            .post(format!("{base}/v1/auth/register"))
            .json(&json!({
                "email": unique_email(&format!("registration-{i}")),
                "auth_key": "invalid",
                "recovery_auth_key": "invalid",
                "kdf_params": {"m": 65536, "t": 3, "p": 4},
                "client_salt": "invalid",
                "password_slot": {"wrapped_key": "invalid", "nonce": "invalid"},
                "recovery_slot": {"wrapped_key": "invalid", "nonce": "invalid"},
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }

    let response = client
        .post(format!("{base}/v1/auth/register"))
        .json(&json!({
            "email": unique_email("registration-limited"),
            "auth_key": "invalid",
            "recovery_auth_key": "invalid",
            "kdf_params": {"m": 65536, "t": 3, "p": 4},
            "client_salt": "invalid",
            "password_slot": {"wrapped_key": "invalid", "nonce": "invalid"},
            "recovery_slot": {"wrapped_key": "invalid", "nonce": "invalid"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
}
