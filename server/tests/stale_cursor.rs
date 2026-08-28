//! The status a client acts on (PRD section 10.6).
//!
//! # Why a whole file for one status code
//!
//! Because it is the one response the client must treat differently from every
//! other failure, and it was indistinguishable from an unrelated one.
//!
//! A cursor at or below the prune watermark means the device may have missed a
//! delete that has since been pruned, so only a full re-sync is correct. That
//! came back as `409 Conflict` under the error code `conflict` — the same
//! status and the same code as "this email is already registered". The only
//! thing separating them was the human-readable message, and a client that
//! matched on prose would break the first time the prose was reworded.
//!
//! Both failures are plausible, and both are quiet. Treating a stale cursor as
//! an ordinary retry loops forever on a cursor that can never advance; treating
//! an ordinary conflict as a stale cursor throws away local state to re-download
//! everything for no reason.
//!
//! Neither the client's own tests nor the property harness could catch it: the
//! in-memory transport returns `SyncError::CursorTooOld` directly and no HTTP
//! status is involved. It takes a test on this side of the wire.
//!
//! Requires the development database from README.md.

use std::net::SocketAddr;
use std::sync::Arc;

use authserver::{AppState, SharedState, migrate, router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://authcore:devonly@127.0.0.1:15432/authcore".to_string())
}

async fn start_server() -> (SocketAddr, sqlx::PgPool) {
    let db = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url())
        .await
        .expect("the development database must be running: docker start authcore-pg");
    migrate(&db).await.expect("migrations must apply");

    sqlx::query(
        "DELETE FROM auth_attempt
          WHERE kind = 'address'
            AND subject IN ('127.0.0.1', 'register:127.0.0.1')",
    )
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
            // ConnectInfo, so section 9.5's per-address rate limit can see who is
            // calling. Without it the extractor fails and every sign-in 500s.
            router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (address, db)
}

/// Registers an account and returns its identifier and access token.
async fn sign_up(client: &reqwest::Client, base: &str) -> (Uuid, String) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("stale-cursor-{stamp:x}@example.invalid");
    let auth_key = B64.encode([0x33u8; 32]);
    let slot = json!({
        "wrapped_key": B64.encode([0x11u8; 48]),
        "nonce": B64.encode([0x22u8; 24]),
    });

    let registered = client
        .post(format!("{base}/v1/auth/register"))
        .json(&json!({
            "email": email,
            "auth_key": auth_key,
            "recovery_auth_key": B64.encode([0x77u8; 32]),
            "kdf_params": { "m": 65536, "t": 3, "p": 4 },
            "client_salt": B64.encode([0x44u8; 16]),
            "password_slot": slot,
            "recovery_slot": slot,
        }))
        .send()
        .await
        .unwrap();
    assert!(registered.status().is_success(), "registration failed");
    let account_id: Uuid = registered.json::<serde_json::Value>().await.unwrap()["account_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let login = client
        .post(format!("{base}/v1/auth/login"))
        .json(&json!({ "email": email, "auth_key": auth_key }))
        .send()
        .await
        .unwrap();
    assert!(login.status().is_success(), "login failed");
    let token = login.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    (account_id, token)
}

#[tokio::test]
async fn a_cursor_below_the_watermark_is_gone_not_a_conflict() {
    let (address, db) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let (account_id, token) = sign_up(&client, &base).await;

    // One record, so the account has a sequence to be behind.
    let pushed = client
        .post(format!("{base}/v1/vault/records"))
        .bearer_auth(&token)
        .json(&json!({
            "records": [{
                "entry_id": Uuid::new_v4(),
                "ciphertext": B64.encode(b"ciphertext"),
                "nonce": B64.encode([9u8; 24]),
                "hlc": "0198c9ecdc00-0000-d000000000000001",
                "deleted": false,
                "base_hlc": null,
            }],
        }))
        .send()
        .await
        .unwrap();
    assert!(pushed.status().is_success(), "the push must be accepted");

    // The prune, done directly: no endpoint moves the watermark, because
    // pruning is the server's own housekeeping and not something a client asks
    // for. The client-side consequence is what is under test.
    sqlx::query("UPDATE sync_state SET prune_watermark = 1 WHERE account_id = $1")
        .bind(account_id)
        .execute(&db)
        .await
        .unwrap();

    let response = client
        .get(format!("{base}/v1/vault/changes"))
        .bearer_auth(&token)
        .query(&[("since", "1")])
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::GONE,
        "a stale cursor must be 410, and must not share 409 with every other conflict"
    );

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["error"], "cursor_too_old",
        "and must carry its own code, so no client has to match on the message"
    );
}

/// The other half of the same rule: a re-sync may read from below the
/// watermark, because that is where its later pages have to ask from.
///
/// The client walks up from zero. Page one is exempt already, since the check
/// only applies to `since > 0`. Page two asks from the sequence page one ended
/// on, which on a vault whose whole history is behind the watermark is below
/// it by construction — so refusing it refuses every re-sync of a vault larger
/// than one page, permanently: the re-sync fails before it stores a cursor, so
/// the next attempt starts from the same place and fails identically.
///
/// The property harness found that at forty thousand operations, once the
/// vault crossed five hundred records. This is the server-side half; the client
/// half is `full_resync` passing `PullMode::FullResync`.
#[tokio::test]
async fn a_full_resync_may_read_from_below_the_watermark() {
    let (address, db) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let (account_id, token) = sign_up(&client, &base).await;

    let pushed = client
        .post(format!("{base}/v1/vault/records"))
        .bearer_auth(&token)
        .json(&json!({
            "records": [{
                "entry_id": Uuid::new_v4(),
                "ciphertext": B64.encode(b"ciphertext"),
                "nonce": B64.encode([9u8; 24]),
                "hlc": "0198c9ecdc00-0000-d000000000000001",
                "deleted": false,
                "base_hlc": null,
            }],
        }))
        .send()
        .await
        .unwrap();
    assert!(pushed.status().is_success());

    sqlx::query("UPDATE sync_state SET prune_watermark = 1 WHERE account_id = $1")
        .bind(account_id)
        .execute(&db)
        .await
        .unwrap();

    // The same request that earns a 410 incrementally.
    let response = client
        .get(format!("{base}/v1/vault/changes"))
        .bearer_auth(&token)
        .query(&[("since", "1"), ("full", "true")])
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a re-sync that cannot read its second page can never finish"
    );
}

/// Section 13: an expired access token is renewed, not a sign-out.
///
/// Without this endpoint a device syncs for fifteen minutes after signing in
/// and then never again. Every cycle gets a 401, the client reports "signed
/// out", and the only way back is the account password — on a device syncing in
/// the background, with nobody watching, until a code added on one device turns
/// out to be missing on another a week later.
///
/// It shipped that way. No test caught it because every test signs in fresh and
/// finishes in under a second.
#[tokio::test]
async fn a_refresh_token_renews_the_session() {
    let (address, _db) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let (_account_id, _token) = sign_up(&client, &base).await;

    // Sign in again to get a refresh token in hand.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("refresh-{stamp:x}@example.invalid");
    let auth_key = B64.encode([0x33u8; 32]);
    let slot = json!({
        "wrapped_key": B64.encode([0x11u8; 48]),
        "nonce": B64.encode([0x22u8; 24]),
    });
    client
        .post(format!("{base}/v1/auth/register"))
        .json(&json!({
            "email": email,
            "auth_key": auth_key,
            "recovery_auth_key": B64.encode([0x77u8; 32]),
            "kdf_params": { "m": 65536, "t": 3, "p": 4 },
            "client_salt": B64.encode([0x44u8; 16]),
            "password_slot": slot,
            "recovery_slot": slot,
        }))
        .send()
        .await
        .unwrap();

    let login: serde_json::Value = client
        .post(format!("{base}/v1/auth/login"))
        .json(&json!({ "email": email, "auth_key": auth_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let refresh_token = login["refresh_token"].as_str().unwrap().to_string();

    // Renew.
    let response = client
        .post(format!("{base}/v1/auth/refresh"))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let renewed: serde_json::Value = response.json().await.unwrap();
    let new_access = renewed["access_token"].as_str().unwrap();
    let new_refresh = renewed["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh, refresh_token, "the pair must rotate");

    // The new access token works.
    let changes = client
        .get(format!("{base}/v1/vault/changes"))
        .bearer_auth(new_access)
        .send()
        .await
        .unwrap();
    assert_eq!(changes.status(), reqwest::StatusCode::OK);

    // And the spent one does not. A thirty-day credential sitting in a file
    // must stop working the moment it is used, or a copied file keeps minting
    // sessions for a month after the device that owned it moved on.
    let replayed = client
        .post(format!("{base}/v1/auth/refresh"))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        replayed.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a spent refresh token must not mint a second session"
    );

    // Replay is evidence that two parties hold one token family. The token
    // issued before the replay must also stop working.
    let descendant = client
        .post(format!("{base}/v1/auth/refresh"))
        .json(&json!({ "refresh_token": new_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(descendant.status(), reqwest::StatusCode::UNAUTHORIZED);

    let descendant_access = client
        .get(format!("{base}/v1/vault/changes"))
        .bearer_auth(new_access)
        .send()
        .await
        .unwrap();
    assert_eq!(
        descendant_access.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}

/// The control: an ordinary conflict must still be a conflict.
///
/// Without this, changing every `Conflict` to `Gone` would pass the test above
/// while making the distinction meaningless again — in the other direction.
#[tokio::test]
async fn an_ordinary_conflict_is_still_409() {
    let (address, _db) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("stale-cursor-control-{stamp:x}@example.invalid");
    let slot = json!({
        "wrapped_key": B64.encode([0x11u8; 48]),
        "nonce": B64.encode([0x22u8; 24]),
    });
    let body = json!({
        "email": email,
        "auth_key": B64.encode([0x33u8; 32]),
        "recovery_auth_key": B64.encode([0x77u8; 32]),
        "kdf_params": { "m": 65536, "t": 3, "p": 4 },
        "client_salt": B64.encode([0x44u8; 16]),
        "password_slot": slot,
        "recovery_slot": slot,
    });

    let first = client
        .post(format!("{base}/v1/auth/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(first.status().is_success());

    // The same address twice.
    let second = client
        .post(format!("{base}/v1/auth/register"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        second.status(),
        reqwest::StatusCode::CONFLICT,
        "an already-registered address is a 409, and stays one"
    );
}
