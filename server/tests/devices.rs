//! Devices, revocation, and account deletion (PRD section 9.5).
//!
//! # Why these are worth a file of their own
//!
//! Everything here is a claim about something *no longer working*, and that is
//! the shape of assertion this project keeps finding it got wrong. A test that
//! calls "revoke" and checks the response said `revoked: true` proves the
//! endpoint wrote a boolean. It does not prove the phone is cut off — and being
//! cut off is the entire product feature.
//!
//! So every test below takes a token that worked, does something, and then
//! shows the same token no longer works. The revoke path is checked in both
//! directions it can leak: the access token it already holds, and the refresh
//! token it would use to get a new one.
//!
//! That second one is not hypothetical. `refresh` did not check the device when
//! this was first written, so a revoked phone could have kept minting fresh
//! access tokens for thirty days. Each would have been refused downstream by
//! the join in `session_for_token` — so the user was safe, and every obvious
//! test would still have passed. `a_revoked_device_cannot_refresh` is the one
//! that fails without the fix.
//!
//! Requires the development database from README.md.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use authserver::{AppState, SharedState, migrate, router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Serialises the whole file, the way `rate_limit.rs` does.
///
/// These tests share one database and one per-address budget. Registration
/// allows ten per address per hour and this file registers about seventeen
/// accounts, so running them at once means some tests spend a budget another
/// test has already cleared — and the failure arrives as "registration failed"
/// on whichever test happened to be unlucky, which is a different set every
/// run.
static SERIAL: Mutex<()> = Mutex::const_new(());

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
        .max_connections(4)
        .connect(&database_url())
        .await
        .expect("the development database must be running: docker start authcore-pg");
    migrate(&db).await.expect("migrations must apply");

    // Section 9.5 allows 100 sign-ins per address per hour, and every test here
    // signs in two or three times from 127.0.0.1. One run fits comfortably;
    // three runs inside an hour do not, and the failure is the worst kind —
    // every test in the file fails at once, with "login failed", pointing at
    // nothing.
    //
    // This was not theoretical. It happened while revert-proving these tests,
    // and for a minute it looked like a revert had broken twelve unrelated
    // things.
    //
    // Every per-address budget, not a named list of them. The endpoint limits
    // store their subject as "<endpoint>:<address>", so each new limited
    // endpoint adds a subject this suite spends — and naming them one at a
    // time means the file breaks again the next time one is added, with
    // "registration failed" or worse pointing at nothing.
    //
    // The per-account budget is left alone: each test registers its own email
    // and never comes close to ten. Cargo runs test binaries one after
    // another, so this cannot race `rate_limit.rs`, which owns this table and
    // clears all of it.
    sqlx::query(
        "DELETE FROM auth_attempt
          WHERE kind = 'address'
            AND (subject = '127.0.0.1' OR subject LIKE '%:127.0.0.1')",
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
            router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (address, db, guard)
}

/// The authentication key every account in this file uses.
const AUTH_KEY: [u8; 32] = [0x33u8; 32];

struct Account {
    email: String,
    id: Uuid,
    sessions: Mutex<Vec<String>>,
}

struct Signed {
    access: String,
    refresh: String,
}

async fn register(client: &reqwest::Client, base: &str) -> Account {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let email = format!("devices-{stamp:x}@example.invalid");
    let slot = json!({
        "wrapped_key": B64.encode([0x11u8; 48]),
        "nonce": B64.encode([0x22u8; 24]),
    });

    let response = client
        .post(format!("{base}/v1/auth/register"))
        .json(&json!({
            "email": email,
            "auth_key": B64.encode(AUTH_KEY),
            "recovery_auth_key": B64.encode([0x77u8; 32]),
            "kdf_params": { "m": 65536, "t": 3, "p": 4 },
            "client_salt": B64.encode([0x44u8; 16]),
            "password_slot": slot,
            "recovery_slot": slot,
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "registration failed");

    let id: Uuid = response.json::<Value>().await.unwrap()["account_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    Account {
        email,
        id,
        sessions: Mutex::new(Vec::new()),
    }
}

/// Signs in, which also creates a device row.
async fn sign_in(client: &reqwest::Client, base: &str, account: &Account, name: &str) -> Signed {
    let existing = account.sessions.lock().await.clone();
    let mut approval_token = None;
    for access in existing.iter().rev() {
        let Ok(security) = request_elevation(client, base, access, &["security:read"]).await else {
            continue;
        };
        let response = client
            .post(format!("{base}/v1/device-approvals"))
            .bearer_auth(&security)
            .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
            .send()
            .await
            .unwrap();
        if response.status().is_success() {
            approval_token = response.json::<Value>().await.unwrap()["token"]
                .as_str()
                .map(str::to_string);
            break;
        }
    }
    let use_recovery = approval_token.is_none();
    let response = client
        .post(format!("{base}/v1/auth/login"))
        .json(&json!({
            "email": account.email,
            "auth_key": B64.encode(AUTH_KEY),
            "device_name": name,
            "device_platform": "test",
            "device_approval_token": approval_token,
            "recovery_auth_key": if use_recovery {
                Some(B64.encode([0x77u8; 32]))
            } else {
                None
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "login failed for {name}");

    let body = response.json::<Value>().await.unwrap();
    let signed = Signed {
        access: body["access_token"].as_str().unwrap().to_string(),
        refresh: body["refresh_token"].as_str().unwrap().to_string(),
    };
    account.sessions.lock().await.push(signed.access.clone());
    signed
}

async fn elevate(client: &reqwest::Client, base: &str, access: &str, scopes: &[&str]) -> String {
    request_elevation(client, base, access, scopes)
        .await
        .unwrap_or_else(|error| panic!("elevation failed: {error}"))
}

async fn request_elevation(
    client: &reqwest::Client,
    base: &str,
    access: &str,
    scopes: &[&str],
) -> Result<String, String> {
    let response = client
        .post(format!("{base}/v1/auth/elevate"))
        .bearer_auth(access)
        .json(&json!({
            "auth_key": B64.encode(AUTH_KEY),
            "scopes": scopes,
        }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    if !status.is_success() {
        return Err(format!("{status}: {body}"));
    }
    Ok(
        serde_json::from_str::<Value>(&body).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

async fn devices(client: &reqwest::Client, base: &str, token: &str) -> Vec<Value> {
    let security = elevate(client, base, token, &["security:read"]).await;
    let response = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(security)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "the device list failed");
    response.json::<Value>().await.unwrap()["devices"]
        .as_array()
        .unwrap()
        .clone()
}

/// Whether a token can still reach an authenticated endpoint.
///
/// Deliberately not `/v1/devices` in every case — this asks the question the
/// user actually cares about, which is whether the lost phone can still read
/// their vault.
async fn can_still_sync(client: &reqwest::Client, base: &str, token: &str) -> bool {
    client
        .get(format!("{base}/v1/vault/changes?since=0"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .is_success()
}

async fn raw_login(
    client: &reqwest::Client,
    base: &str,
    account: &Account,
    name: &str,
    approval: Option<&str>,
    recovery: bool,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/auth/login"))
        .json(&json!({
            "email": account.email,
            "auth_key": B64.encode(AUTH_KEY),
            "device_name": name,
            "device_platform": "test",
            "device_approval_token": approval,
            "recovery_auth_key": recovery.then(|| B64.encode([0x77u8; 32])),
        }))
        .send()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_password_alone_cannot_add_a_second_device() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let _first = sign_in(&client, &base, &account, "First").await;

    let response = raw_login(&client, &base, &account, "Unapproved", None, false).await;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], json!("device_approval_required"));
}

#[tokio::test]
async fn a_device_approval_code_works_only_once() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let first = sign_in(&client, &base, &account, "First").await;
    let security = elevate(&client, &base, &first.access, &["security:read"]).await;
    let approval = client
        .post(format!("{base}/v1/device-approvals"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let accepted = raw_login(&client, &base, &account, "Second", Some(&approval), false).await;
    assert!(accepted.status().is_success());
    let replay = raw_login(&client, &base, &account, "Third", Some(&approval), false).await;
    assert_eq!(replay.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn persistent_and_capability_scopes_are_isolated() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;

    let security = elevate(&client, &base, &session.access, &["security:read"]).await;
    let base_security = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(&session.access)
        .send()
        .await
        .unwrap();
    assert_eq!(base_security.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        base_security.json::<Value>().await.unwrap()["error"],
        "elevation_required"
    );

    let capability_vault = client
        .get(format!("{base}/v1/vault/changes?since=0"))
        .bearer_auth(&security)
        .send()
        .await
        .unwrap();
    assert_eq!(capability_vault.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(devices(&client, &base, &session.access).await.len() == 1);

    let (scopes,): (Vec<String>,) =
        sqlx::query_as("SELECT scopes FROM session WHERE account_id = $1 AND NOT revoked LIMIT 1")
            .bind(account.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(scopes, vec!["vault:sync", "session:self"]);
}

#[tokio::test]
async fn a_push_route_is_private_to_the_device_and_removed_on_sign_out() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Push phone").await;

    let registered = client
        .put(format!("{base}/v1/devices/push-token"))
        .bearer_auth(&session.access)
        .json(&json!({ "token": "fcm-installation-route" }))
        .send()
        .await
        .unwrap();
    assert!(registered.status().is_success());
    assert_eq!(
        registered.json::<Value>().await.unwrap()["registered"],
        true
    );

    let (stored,): (Option<String>,) =
        sqlx::query_as("SELECT push_token FROM device WHERE account_id = $1 AND name = $2")
            .bind(account.id)
            .bind("Push phone")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some("fcm-installation-route"));

    let signed_out = client
        .post(format!("{base}/v1/auth/logout"))
        .bearer_auth(&session.access)
        .send()
        .await
        .unwrap();
    assert!(signed_out.status().is_success());

    let (stored, revoked): (Option<String>, bool) = sqlx::query_as(
        "SELECT push_token, revoked FROM device WHERE account_id = $1 AND name = $2",
    )
    .bind(account.id)
    .bind("Push phone")
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(stored.is_none());
    assert!(revoked);
}

#[tokio::test]
async fn an_expired_capability_is_rejected_with_its_own_error() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;
    let security = elevate(&client, &base, &session.access, &["security:read"]).await;

    sqlx::query(
        "UPDATE capability_session SET expires_at = now() - interval '1 second'
          WHERE parent_session_id IN (SELECT id FROM session WHERE account_id = $1)",
    )
    .bind(account.id)
    .execute(&db)
    .await
    .unwrap();

    let response = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(security)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "capability_expired"
    );
}

#[tokio::test]
async fn refreshing_a_session_does_not_add_elevated_scopes() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;

    let response = client
        .post(format!("{base}/v1/auth/refresh"))
        .json(&json!({ "refresh_token": session.refresh }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let renewed = response.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let denied = client
        .get(format!("{base}/v1/devices"))
        .bearer_auth(renewed)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    let (scopes,): (Vec<String>,) =
        sqlx::query_as("SELECT scopes FROM session WHERE account_id = $1 AND NOT revoked LIMIT 1")
            .bind(account.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(scopes, vec!["vault:sync", "session:self"]);
}

#[tokio::test]
async fn device_changes_appear_in_security_activity() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;
    let security = elevate(&client, &base, &session.access, &["security:read"]).await;
    let response = client
        .get(format!("{base}/v1/security/activity"))
        .bearer_auth(&security)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let events = response.json::<Value>().await.unwrap()["events"]
        .as_array()
        .unwrap()
        .clone();
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "device_added")
    );
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "account_registered")
    );
}

#[tokio::test]
async fn an_existing_account_can_enable_recovery_device_approval() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();
    let account = register(&client, &base).await;
    let first = sign_in(&client, &base, &account, "First").await;
    let security = elevate(&client, &base, &first.access, &["security:read"]).await;
    sqlx::query("UPDATE key_slot SET auth_hash = NULL WHERE account_id = $1 AND type = 'recovery'")
        .bind(account.id)
        .execute(&db)
        .await
        .unwrap();

    let refused = raw_login(&client, &base, &account, "Recovery", None, true).await;
    assert_eq!(refused.status(), reqwest::StatusCode::FORBIDDEN);
    let enrolled = client
        .post(format!("{base}/v1/recovery/enroll"))
        .bearer_auth(&security)
        .json(&json!({
            "auth_key": B64.encode(AUTH_KEY),
            "recovery_auth_key": B64.encode([0x77u8; 32]),
            "recovery_slot": {
                "wrapped_key": B64.encode([0x11u8; 48]),
                "nonce": B64.encode([0x22u8; 24]),
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(enrolled.status().is_success());
    let accepted = raw_login(&client, &base, &account, "Recovery", None, true).await;
    assert!(accepted.status().is_success());
}

#[tokio::test]
async fn the_device_list_names_the_caller() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let phone = sign_in(&client, &base, &account, "Phone").await;
    let _laptop = sign_in(&client, &base, &account, "Laptop").await;

    let listed = devices(&client, &base, &phone.access).await;
    assert_eq!(listed.len(), 2);

    // Exactly one is the caller. Without this the screen cannot warn someone
    // that they are about to sign out the device in their hand.
    let current: Vec<&Value> = listed
        .iter()
        .filter(|device| device["current"] == json!(true))
        .collect();
    assert_eq!(current.len(), 1, "exactly one device is the caller");
    assert_eq!(current[0]["name"], json!("Phone"));
}

/// The assertion the whole feature rests on.
#[tokio::test]
async fn a_revoked_device_cannot_read_the_vault() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let lost = sign_in(&client, &base, &account, "Lost phone").await;
    let kept = sign_in(&client, &base, &account, "Laptop").await;

    // It worked before. Otherwise "it does not work now" proves nothing — the
    // token might never have worked at all.
    assert!(
        can_still_sync(&client, &base, &lost.access).await,
        "the token must work before it is revoked, or this test proves nothing"
    );

    let listed = devices(&client, &base, &kept.access).await;
    let lost_id = listed
        .iter()
        .find(|device| device["name"] == json!("Lost phone"))
        .expect("the lost phone is listed")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let security = elevate(&client, &base, &kept.access, &["security:read"]).await;

    let revoked = client
        .delete(format!("{base}/v1/devices/{lost_id}"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();
    assert!(revoked.status().is_success());

    // Immediately, not in fifteen minutes when the access token expires. Those
    // fifteen minutes are the entire reason someone pressed the button.
    assert!(
        !can_still_sync(&client, &base, &lost.access).await,
        "a revoked device could still read the vault"
    );

    // And the device doing the revoking is untouched.
    assert!(
        can_still_sync(&client, &base, &kept.access).await,
        "revoking one device signed out another"
    );
}

/// The refresh path, tested where only the device check can decide it.
///
/// # This test was vacuous when first written
///
/// It used to revoke through the endpoint and assert that `refresh` returned
/// 401 — and it passed with the device check removed, because revoking also
/// kills the device's sessions and the `NOT revoked` clause caught the refresh
/// on its own. The assertion was true, the fix was real, and the test proved
/// neither.
///
/// Proven by reverting: with the device clause deleted from the `UPDATE`, the
/// old version stayed green and this version fails.
///
/// So the state is written directly — a revoked device whose refresh session is
/// still live. That is what a partial failure, a restore from an older backup,
/// or any future path that issues a session without re-reading the device would
/// leave behind, and it is the only state in which the clause is what answers.
#[tokio::test]
async fn a_revoked_device_cannot_refresh() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let lost = sign_in(&client, &base, &account, "Lost phone").await;

    // The device is revoked and its sessions are deliberately left alive.
    sqlx::query("UPDATE device SET revoked = TRUE WHERE account_id = $1")
        .bind(account.id)
        .execute(&db)
        .await
        .unwrap();

    let (live,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM session WHERE account_id = $1 AND NOT revoked")
            .bind(account.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(
        live > 0,
        "the session must still be live, or the session check answers instead          of the device check and this test proves nothing"
    );

    // A revoke should stop the device asking, not merely stop it being
    // answered. Thirty days of fresh tokens for a phone someone reported lost
    // is not a state to be relaxed about, even if every one of them is refused
    // downstream.
    let refreshed = client
        .post(format!("{base}/v1/auth/refresh"))
        .json(&json!({ "refresh_token": lost.refresh }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        refreshed.status(),
        401,
        "a revoked device was issued a fresh token"
    );
}

/// And the ordinary path still works, so the clause above cannot be a blanket
/// refusal that happens to look correct.
#[tokio::test]
async fn an_ordinary_device_can_still_refresh() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;

    let refreshed = client
        .post(format!("{base}/v1/auth/refresh"))
        .json(&json!({ "refresh_token": session.refresh }))
        .send()
        .await
        .unwrap();
    assert!(
        refreshed.status().is_success(),
        "a healthy device could not renew its session"
    );

    let renewed = refreshed.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(can_still_sync(&client, &base, &renewed).await);
}

#[tokio::test]
async fn a_revoked_device_stays_in_the_list() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let lost = sign_in(&client, &base, &account, "Lost phone").await;
    let kept = sign_in(&client, &base, &account, "Laptop").await;
    let _ = lost;

    let listed = devices(&client, &base, &kept.access).await;
    let lost_id = listed
        .iter()
        .find(|device| device["name"] == json!("Lost phone"))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let security = elevate(&client, &base, &kept.access, &["security:read"]).await;

    client
        .delete(format!("{base}/v1/devices/{lost_id}"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();

    // Someone checking that the phone they lost is really cut off needs to see
    // it listed as cut off. A list that has simply stopped mentioning it is
    // indistinguishable from a list that forgot.
    let after = devices(&client, &base, &kept.access).await;
    let entry = after
        .iter()
        .find(|device| device["id"] == json!(lost_id))
        .expect("a revoked device must remain visible");
    assert_eq!(entry["revoked"], json!(true));
}

#[tokio::test]
async fn another_accounts_device_cannot_be_revoked() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let mine = register(&client, &base).await;
    let theirs = register(&client, &base).await;

    let my_session = sign_in(&client, &base, &mine, "Mine").await;
    let their_session = sign_in(&client, &base, &theirs, "Theirs").await;

    let their_id = devices(&client, &base, &their_session.access).await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let my_security = elevate(&client, &base, &my_session.access, &["security:read"]).await;

    let attempt = client
        .delete(format!("{base}/v1/devices/{their_id}"))
        .bearer_auth(&my_security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();

    // 404, and the same 404 a device id that never existed would get.
    // Distinguishing "not yours" from "no such thing" would turn this into a
    // way of asking whether an identifier is real.
    assert_eq!(attempt.status(), 404);
    let invented = client
        .delete(format!("{base}/v1/devices/{}", Uuid::new_v4()))
        .bearer_auth(&my_security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        invented.status(),
        404,
        "a real device on another account must look the same as no device"
    );

    assert!(
        can_still_sync(&client, &base, &their_session.access).await,
        "another account's device was revoked"
    );
}

#[tokio::test]
async fn signing_out_everywhere_ends_every_session() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let one = sign_in(&client, &base, &account, "One").await;
    let two = sign_in(&client, &base, &account, "Two").await;
    let security = elevate(&client, &base, &one.access, &["security:read"]).await;

    let response = client
        .post(format!("{base}/v1/auth/logout-all"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Including the one that asked. "Everywhere" that spared the caller would
    // be the single most useless reading of the word.
    assert!(!can_still_sync(&client, &base, &one.access).await);
    assert!(!can_still_sync(&client, &base, &two.access).await);

    // Recovery remains possible after every device is revoked. A password
    // alone must not silently restore device access.
    let back = sign_in(&client, &base, &account, "One").await;
    assert!(can_still_sync(&client, &base, &back.access).await);
}

#[tokio::test]
async fn signing_out_ends_only_the_caller() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let one = sign_in(&client, &base, &account, "One").await;
    let two = sign_in(&client, &base, &account, "Two").await;

    client
        .post(format!("{base}/v1/auth/logout"))
        .bearer_auth(&one.access)
        .send()
        .await
        .unwrap();

    assert!(!can_still_sync(&client, &base, &one.access).await);
    assert!(
        can_still_sync(&client, &base, &two.access).await,
        "an ordinary sign-out took every other device with it"
    );
}

#[tokio::test]
async fn deleting_the_account_removes_every_record() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;

    client
        .post(format!("{base}/v1/vault/records"))
        .bearer_auth(&session.access)
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
    let security = elevate(&client, &base, &session.access, &["security:read"]).await;

    let deleted = client
        .delete(format!("{base}/v1/account"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();
    assert!(deleted.status().is_success());
    assert_eq!(
        deleted.json::<Value>().await.unwrap()["records_deleted"],
        json!(1)
    );

    // Asserted on the database, not on the response. A endpoint that returned
    // a count and deleted nothing would pass every check above — and this is
    // the one operation whose whole promise is that the data is gone.
    for table in ["record", "key_slot", "device", "session"] {
        let (remaining,): (i64,) = sqlx::query_as(&format!(
            "SELECT count(*) FROM {table} WHERE account_id = $1"
        ))
        .bind(account.id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            remaining, 0,
            "{table} still holds rows for a deleted account"
        );
    }

    let (accounts,): (i64,) = sqlx::query_as("SELECT count(*) FROM account WHERE id = $1")
        .bind(account.id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(accounts, 0);

    assert!(!can_still_sync(&client, &base, &session.access).await);
}

#[tokio::test]
async fn deleting_the_account_needs_the_password() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;
    let security = elevate(&client, &base, &session.access, &["security:read"]).await;

    // A stolen access token is exactly the situation the rest of section 9.5
    // exists for. Whoever holds one must not be able to destroy the account
    // its owner is trying to save.
    let attempt = client
        .delete(format!("{base}/v1/account"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode([0xFFu8; 32]) }))
        .send()
        .await
        .unwrap();
    assert_eq!(attempt.status(), 401);

    let (accounts,): (i64,) = sqlx::query_as("SELECT count(*) FROM account WHERE id = $1")
        .bind(account.id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(accounts, 1, "a wrong password deleted the account");

    assert!(
        can_still_sync(&client, &base, &session.access).await,
        "a failed deletion signed the user out"
    );
}

#[tokio::test]
async fn the_endpoints_refuse_an_unauthenticated_caller() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    // Every one of them, rather than one representative. They were written at
    // different moments and each takes its own path to `authenticate`; a
    // missing call would be invisible until someone found it.
    let listed = client
        .get(format!("{base}/v1/devices"))
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 401);

    let revoked = client
        .delete(format!("{base}/v1/devices/{}", Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 401);

    let out = client
        .post(format!("{base}/v1/auth/logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), 401);

    let out_all = client
        .post(format!("{base}/v1/auth/logout-all"))
        .send()
        .await
        .unwrap();
    assert_eq!(out_all.status(), 401);

    let gone = client
        .delete(format!("{base}/v1/account"))
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 401);
}

/// The third layer, tested where nothing else can reach it.
///
/// # Why this one needs the database directly
///
/// Revoking marks the device *and* kills its sessions in the same request, so
/// every test above would still pass with the device join removed from
/// `session_for_token` — the session check alone catches them. That makes the
/// join genuinely belt-and-braces, and untested belt-and-braces is just code
/// somebody deletes during a tidy-up.
///
/// It exists for the states the endpoint cannot produce: a session created
/// between the two statements, a future code path that issues one without
/// re-reading the device, or a restore of `session` from a backup taken before
/// the revoke. All three look the same from here — a live session row belonging
/// to a revoked device — so that state is written directly and the token tried.
#[tokio::test]
async fn a_live_session_on_a_revoked_device_is_still_refused() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;

    assert!(
        can_still_sync(&client, &base, &session.access).await,
        "the token must work first, or this proves nothing"
    );

    // The device is revoked, and its sessions are deliberately left alive —
    // the state a partial failure or an out-of-date restore would leave.
    sqlx::query("UPDATE device SET revoked = TRUE WHERE account_id = $1")
        .bind(account.id)
        .execute(&db)
        .await
        .unwrap();

    let (live,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM session WHERE account_id = $1 AND NOT revoked")
            .bind(account.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(
        live > 0,
        "the session must still be live for this to test the join"
    );

    assert!(
        !can_still_sync(&client, &base, &session.access).await,
        "a live session on a revoked device was accepted"
    );
}

/// The first layer: revoking ends the sessions, it does not merely make them
/// unusable.
///
/// # Why this needs its own assertion
///
/// Deleting the session update from `revoke_device` fails none of the
/// behavioural tests above, because the device join in `session_for_token`
/// refuses those tokens anyway. Proven by reverting: with the update removed,
/// every other test in this file stayed green.
///
/// That redundancy is the point of defence in depth, and it is also how a layer
/// gets quietly deleted. Two things are actually lost without it:
///
/// - `sessions_ended` in the response becomes a lie. It is shown to the user.
/// - The rows stay live. They are dead only for as long as the device row keeps
///   saying `revoked`, so anything that ever cleared that flag — an
///   un-revoke, a restore, a support action — would bring every one of them
///   back.
#[tokio::test]
async fn revoking_ends_the_sessions_rather_than_only_blocking_them() {
    let (address, db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let lost = sign_in(&client, &base, &account, "Lost phone").await;
    let kept = sign_in(&client, &base, &account, "Laptop").await;
    let _ = lost;

    let listed = devices(&client, &base, &kept.access).await;
    let lost_id = listed
        .iter()
        .find(|device| device["name"] == json!("Lost phone"))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let security = elevate(&client, &base, &kept.access, &["security:read"]).await;

    let response = client
        .delete(format!("{base}/v1/devices/{lost_id}"))
        .bearer_auth(&security)
        .json(&json!({ "auth_key": B64.encode(AUTH_KEY) }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // The count the user is shown has to be true.
    assert_eq!(
        response.json::<Value>().await.unwrap()["sessions_ended"],
        json!(1),
        "the endpoint reported ending a number of sessions it did not end"
    );

    // And the rows are actually marked, so nothing that later cleared the
    // device flag could resurrect them.
    let lost_uuid: Uuid = lost_id.parse().unwrap();
    let (still_live,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM session WHERE device_id = $1 AND NOT revoked")
            .bind(lost_uuid)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        still_live, 0,
        "a revoked device kept live session rows, which would come back if the \
         device were ever un-revoked"
    );

    // The other device's session is untouched.
    let (others,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM session WHERE account_id = $1 AND device_id <> $2 AND NOT revoked",
    )
    .bind(account.id)
    .bind(lost_uuid)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(others > 0, "revoking one device ended another's sessions");
}

// ---------------------------------------------------------------------------
// Sharing (section 9.5's neighbour: the only unauthenticated read path)
// ---------------------------------------------------------------------------

/// The share endpoints are the one place the server hands bytes to somebody
/// with no account, so the limits around them are the whole defence.
#[tokio::test]
async fn retrieving_a_share_is_rate_limited() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;
    let sharing = elevate(&client, &base, &session.access, &["share:write"]).await;

    let created = client
        .post(format!("{base}/v1/shares"))
        .bearer_auth(&sharing)
        .json(&json!({
            "payload": "ciphertext-the-server-cannot-read",
            "expires_in_seconds": 3600,
            "one_time": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success(), "the share was not created");
    let id = created.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Unauthenticated, which is correct: the recipient has no account.
    let first = client
        .get(format!("{base}/v1/shares/{id}"))
        .send()
        .await
        .unwrap();
    assert!(
        first.status().is_success(),
        "a recipient must be able to read it"
    );

    // Then past the limit. Without one this endpoint was an unauthenticated,
    // database-touching call anyone could run as fast as they liked.
    let mut limited = false;
    for _ in 0..80 {
        let response = client
            .get(format!("{base}/v1/shares/{id}"))
            .send()
            .await
            .unwrap();
        if response.status() == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "share retrieval was never rate limited");
}

/// One-time shares are consumed exactly once, even under a race.
#[tokio::test]
async fn a_one_time_share_can_only_be_read_once() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;
    let session = sign_in(&client, &base, &account, "Phone").await;
    let sharing = elevate(&client, &base, &session.access, &["share:write"]).await;

    let created = client
        .post(format!("{base}/v1/shares"))
        .bearer_auth(&sharing)
        .json(&json!({
            "payload": "ciphertext",
            "expires_in_seconds": 3600,
            "one_time": true,
        }))
        .send()
        .await
        .unwrap();
    let id = created.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let first = client
        .get(format!("{base}/v1/shares/{id}"))
        .send()
        .await
        .unwrap();
    assert!(first.status().is_success());

    let second = client
        .get(format!("{base}/v1/shares/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 404, "a one-time share was readable twice");
}

// ---------------------------------------------------------------------------
// Passkeys: the enumeration question
// ---------------------------------------------------------------------------

/// Section 9.5 applied to WebAuthn.
///
/// `start_authentication` used to answer 401 for an address with no account and
/// 200 with a ceremony for one that had a passkey. That told an attacker in a
/// single request what `prelogin`'s fake salt, `fake_auth_hash` and padded
/// refusal are all built to refuse.
///
/// Passkeys are not configured in these tests, so both paths return the same
/// "not configured" answer and this cannot check the fabricated ceremony end to
/// end. What it can check is the property that matters most and is easiest to
/// lose: that the *shape* of the answer does not depend on whether the address
/// exists.
#[tokio::test]
async fn a_passkey_challenge_does_not_reveal_whether_an_account_exists() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let account = register(&client, &base).await;

    let ask = |email: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}/v1/passkeys/authenticate/start"))
                .json(&json!({ "email": email }))
                .send()
                .await
                .unwrap()
        }
    };

    let real = ask(account.email.clone()).await;
    let unknown = ask("nobody-18ce6b49@example.invalid".to_string()).await;

    assert_eq!(
        real.status(),
        unknown.status(),
        "the status told the caller whether the address has an account"
    );

    let real_body = real.text().await.unwrap();
    let unknown_body = unknown.text().await.unwrap();
    assert_eq!(
        real_body.len().abs_diff(unknown_body.len()) < 8,
        true,
        "the body length separated a real address from an unknown one:\n  real:    {real_body}\n  unknown: {unknown_body}"
    );
}

/// The fabricated identifiers must not change between requests.
///
/// A fresh random list each time would be its own signal: a real account's
/// credential identifiers are stable, so an answer that differs on a second ask
/// is obviously fabricated. Asking twice is the cheapest possible probe.
#[tokio::test]
async fn a_fabricated_passkey_challenge_is_stable_for_an_address() {
    let (address, _db, _serial) = start_server().await;
    let base = format!("http://{address}");
    let client = reqwest::Client::new();

    let email = "stable-probe-18ce6b49@example.invalid";
    let mut bodies = Vec::new();
    for _ in 0..2 {
        let response = client
            .post(format!("{base}/v1/passkeys/authenticate/start"))
            .json(&json!({ "email": email }))
            .send()
            .await
            .unwrap();
        bodies.push(response.text().await.unwrap());
    }

    // Without passkeys configured both answers are the same refusal, which
    // satisfies this trivially. With passkeys configured the credential
    // identifiers are HMAC-derived from the address and must still match; the
    // challenge and ceremony id are random and are expected to differ.
    let credential_ids = |body: &str| -> Vec<String> {
        serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/public_key/publicKey/allowCredentials")?
                    .as_array()
                    .map(|list| {
                        list.iter()
                            .filter_map(|item| item["id"].as_str().map(str::to_string))
                            .collect()
                    })
            })
            .unwrap_or_default()
    };

    assert_eq!(
        credential_ids(&bodies[0]),
        credential_ids(&bodies[1]),
        "the fabricated credential identifiers changed between requests"
    );
}
