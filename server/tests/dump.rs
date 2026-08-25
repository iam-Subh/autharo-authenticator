//! The stage S4 exit criterion: **the database dump holds no plaintext
//! issuer, account name, or secret.**
//!
//! # How this is tested, and why that way
//!
//! Not by checking that the endpoints return the right thing. An endpoint can
//! be correct and the database still hold something it should not — a debug
//! column, a log table, a stray index on a decrypted value. So the assertion
//! is made against `pg_dump`, which is the artifact the criterion is about:
//! run the whole sign-up and record push, dump the database, and search the
//! bytes.
//!
//! # The controls, and why one has to be in a `bytea` column
//!
//! A test that greps a dump for a string and finds nothing proves one of two
//! things: the string is absent, or the search is broken. They are
//! indistinguishable from a passing test.
//!
//! The first version of this file had a control, and it was still vacuous.
//! The control was a device name — a `text` column, which `pg_dump` writes as
//! readable text — while the secret lives in `record.ciphertext`, a `bytea`
//! column, which `pg_dump` writes as a hex escape. An ASCII search therefore
//! could not find a plaintext secret even when one was there: pushing the
//! payload unencrypted on purpose produced a PASSING test.
//!
//! So there are now two controls and two searches. `dump_contains` looks for a
//! marker both as literal text and as the hex a `bytea` dump carries, and the
//! `bytea` control is a record pushed with its ciphertext field set to
//! plaintext. If either control is not found, the search is broken and every
//! absence below means nothing.
//!
//! Requires the development database from README.md.

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use authserver::{AppState, SharedState, crypto, migrate, router};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

/// Inside the encrypted payload. Must never reach the dump.
const SECRET_MARKER: &str = "MARKER-SECRET-JBSWY3DPEHPK3PXP-DO-NOT-LEAK";
const ISSUER_MARKER: &str = "MARKER-ISSUER-AcmeBankOfNowhere";
const ACCOUNT_MARKER: &str = "MARKER-ACCOUNT-rupsa-at-nowhere";

/// Deliberately stored in the clear in a `text` column, proving the literal
/// search works.
const CONTROL_TEXT_MARKER: &str = "MARKER-CONTROL-TEXT-SHOULD-APPEAR";

/// Deliberately stored in the clear in a `bytea` column — the same column the
/// secret lives in — proving the hex search works. Without this control, a
/// leak in `record.ciphertext` is invisible to an ASCII search.
const CONTROL_BYTEA_MARKER: &str = "MARKER-CONTROL-BYTEA-SHOULD-APPEAR";

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://authcore:devonly@127.0.0.1:15432/authcore".to_string())
}

async fn start_server() -> (SocketAddr, sqlx::PgPool) {
    let db = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url())
        .await
        .expect(
            "the development database must be running: \
             docker start authcore-pg",
        );
    migrate(&db).await.expect("migrations must apply");

    let state: SharedState = Arc::new(AppState {
        db: db.clone(),
        server_key: b"test-server-key".to_vec(),
        fake_auth_hash: crypto::hash_auth_key(&[0u8; 32]).unwrap(),
        passkeys: None,
        push: None,
    });

    // Port 0: the operating system picks a free one, so a test run cannot
    // collide with a development server on the usual port.
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

/// Seals a payload the way the client's record cipher does (section 9.3):
/// XChaCha20-Poly1305, a random 192-bit nonce, and the entry id and record
/// version as associated data.
fn seal(vault_key: &[u8; 32], entry_id: &str, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).unwrap();

    let mut aad = Vec::new();
    aad.extend_from_slice(&(entry_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(entry_id.as_bytes());
    aad.extend_from_slice(&1u32.to_be_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(vault_key).unwrap();
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    (ciphertext, nonce.to_vec())
}

/// Searches a dump for a marker in both forms it could take.
///
/// `text` columns dump as readable characters. `bytea` columns dump as `\x`
/// followed by lowercase hex, so a marker stored in one appears as the hex of
/// its bytes and an ASCII search misses it entirely.
fn dump_contains(dump: &str, marker: &str) -> bool {
    if dump.contains(marker) {
        return true;
    }
    let hex: String = marker.bytes().map(|b| format!("{b:02x}")).collect();
    dump.contains(&hex)
}

fn pg_dump() -> String {
    // Dumped from inside the container, so the test needs no local psql
    // client. `--data-only` would hide a column definition that named a
    // secret, so the whole dump is searched.
    let output = Command::new("docker")
        .args([
            "exec",
            "authcore-pg",
            "pg_dump",
            "-U",
            "authcore",
            "authcore",
        ])
        .output()
        .expect("docker must be available to dump the database");

    assert!(
        output.status.success(),
        "pg_dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Lossy on purpose: a dump holds binary bytea escapes, and a marker that
    // survived as mangled UTF-8 should still be found.
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test]
async fn the_database_dump_holds_no_plaintext_secret() {
    let (address, db) = start_server().await;
    let base = format!("http://{address}/v1");
    let client = reqwest::Client::new();

    // A unique address per run, so repeated runs do not collide on the
    // account table's unique index.
    let email = format!("dump-test-{}@example.com", uuid::Uuid::new_v4());

    // The vault key. In the real client this comes from the device slot and
    // is wrapped before it ever leaves; here it stands in for one.
    let vault_key = [0x5Au8; 32];
    let auth_key = [0x3Cu8; 32];

    // ---- sign-up -------------------------------------------------------
    let (password_wrapped, password_nonce) = seal(&vault_key, "password-slot", &vault_key);
    let (recovery_wrapped, recovery_nonce) = seal(&vault_key, "recovery-slot", &vault_key);

    let response = client
        .post(format!("{base}/auth/register"))
        .json(&json!({
            "email": email,
            "auth_key": crypto::b64_encode(&auth_key),
            "recovery_auth_key": crypto::b64_encode(&[0x77u8; 32]),
            "kdf_params": {"m": 65536, "t": 3, "p": 4},
            "client_salt": crypto::b64_encode(&[9u8; 16]),
            "password_slot": {
                "wrapped_key": crypto::b64_encode(&password_wrapped),
                "nonce": crypto::b64_encode(&password_nonce),
            },
            "recovery_slot": {
                "wrapped_key": crypto::b64_encode(&recovery_wrapped),
                "nonce": crypto::b64_encode(&recovery_nonce),
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        201,
        "register: {:?}",
        response.text().await
    );

    // ---- sign-in, with the control marker as the device name -----------
    let response = client
        .post(format!("{base}/auth/login"))
        .json(&json!({
            "email": email,
            "auth_key": crypto::b64_encode(&auth_key),
            "device_name": CONTROL_TEXT_MARKER,
            "device_platform": "test",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "login: {:?}", response.text().await);
    let login: serde_json::Value = response.json().await.unwrap();
    let token = login["access_token"].as_str().unwrap().to_string();

    // ---- push a record whose payload holds the markers -----------------
    let entry_id = uuid::Uuid::new_v4();
    let payload = json!({
        "v": 1,
        "type": "totp",
        "issuer": ISSUER_MARKER,
        "account": ACCOUNT_MARKER,
        "secret": SECRET_MARKER,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    .to_string();

    let (ciphertext, nonce) = seal(&vault_key, &entry_id.to_string(), payload.as_bytes());

    let response = client
        .post(format!("{base}/vault/records"))
        .bearer_auth(&token)
        .json(&json!({
            "records": [
                {
                    "entry_id": entry_id,
                    "ciphertext": crypto::b64_encode(&ciphertext),
                    "nonce": crypto::b64_encode(&nonce),
                    "hlc": "01931f4a2c10-0000-a91b7f0e44d2c318",
                    "deleted": false,
                    "base_hlc": null,
                },
                // The bytea control: a record whose "ciphertext" is plaintext.
                // It lands in the same column as the real one, so finding it
                // proves the hex search reaches that column.
                {
                    "entry_id": uuid::Uuid::new_v4(),
                    "ciphertext": crypto::b64_encode(CONTROL_BYTEA_MARKER.as_bytes()),
                    "nonce": crypto::b64_encode(&[0u8; 24]),
                    "hlc": "01931f4a2c10-0001-a91b7f0e44d2c318",
                    "deleted": false,
                    "base_hlc": null,
                }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "push: {:?}", response.text().await);

    // The record really is stored, so the absence below is not the absence of
    // any data at all.
    let (stored,): (i64,) = sqlx::query_as("SELECT count(*) FROM record WHERE entry_id = $1")
        .bind(entry_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        stored, 1,
        "the record was not stored, so the dump proves nothing"
    );

    // ---- the dump ------------------------------------------------------
    let dump = pg_dump();

    // The controls first. If either fails, the search is broken and every
    // assertion after it is meaningless.
    assert!(
        dump_contains(&dump, CONTROL_TEXT_MARKER),
        "the text control is missing, so the literal search is broken"
    );
    assert!(
        dump_contains(&dump, CONTROL_BYTEA_MARKER),
        "the bytea control is missing, so the search cannot see into the \
         column the secret lives in. This is exactly the failure that made the \
         first version of this test pass while the payload was pushed in the \
         clear. Fix the search before trusting anything below."
    );

    for (what, marker) in [
        ("the secret", SECRET_MARKER),
        ("the issuer", ISSUER_MARKER),
        ("the account name", ACCOUNT_MARKER),
    ] {
        assert!(
            !dump_contains(&dump, marker),
            "{what} appears in the database dump. The stage S4 exit criterion \
             is that it does not."
        );
    }

    // The vault key itself must not be there either, in any encoding a
    // careless implementation might have used.
    assert!(
        !dump.contains(&crypto::b64_encode(&vault_key)),
        "the vault key appears in the dump, base64url encoded"
    );
    let vault_hex: String = vault_key.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !dump.contains(&vault_hex),
        "the vault key appears in the dump as hex, which is how a bytea column \
         carries it"
    );

    // And the authentication key: section 9.2.1 step 5 stores a hash of it,
    // never the key. A dump holding it would let anyone sign in.
    assert!(
        !dump.contains(&crypto::b64_encode(&auth_key)),
        "the authentication key appears in the dump; only its hash may be stored"
    );
    let auth_hex: String = auth_key.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !dump.contains(&auth_hex),
        "the authentication key appears in the dump as hex"
    );
}

/// Section 9.5: an address with no account must be indistinguishable from one
/// that has an account — in the body and in the time.
#[tokio::test]
async fn prelogin_does_not_reveal_whether_an_account_exists() {
    let (address, _db) = start_server().await;
    let base = format!("http://{address}/v1");
    let client = reqwest::Client::new();

    let real_email = format!("real-{}@example.com", uuid::Uuid::new_v4());
    let unknown_email = format!("unknown-{}@example.com", uuid::Uuid::new_v4());

    let vault_key = [0x11u8; 32];
    let (wrapped, nonce) = seal(&vault_key, "slot", &vault_key);
    let slot = json!({
        "wrapped_key": crypto::b64_encode(&wrapped),
        "nonce": crypto::b64_encode(&nonce),
    });

    client
        .post(format!("{base}/auth/register"))
        .json(&json!({
            "email": real_email,
            "auth_key": crypto::b64_encode(&[1u8; 32]),
            "recovery_auth_key": crypto::b64_encode(&[0x77u8; 32]),
            "kdf_params": {"m": 65536, "t": 3, "p": 4},
            "client_salt": crypto::b64_encode(&[2u8; 16]),
            "password_slot": slot,
            "recovery_slot": slot,
        }))
        .send()
        .await
        .unwrap();

    let prelogin = |email: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            let started = std::time::Instant::now();
            let response = client
                .post(format!("{base}/auth/prelogin"))
                .json(&json!({ "email": email }))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap();
            (status, body, started.elapsed())
        }
    };

    let (real_status, real_body, _) = prelogin(real_email.clone()).await;
    let (fake_status, fake_body, _) = prelogin(unknown_email.clone()).await;

    assert_eq!(real_status, fake_status, "the status codes differ");
    assert_eq!(
        real_body.as_object().unwrap().keys().collect::<Vec<_>>(),
        fake_body.as_object().unwrap().keys().collect::<Vec<_>>(),
        "the response shapes differ"
    );
    assert_eq!(
        real_body["client_salt"].as_str().unwrap().len(),
        fake_body["client_salt"].as_str().unwrap().len(),
        "the salt lengths differ, which is as good as a label"
    );
    assert_eq!(
        real_body["kdf_params"], fake_body["kdf_params"],
        "the parameters differ"
    );
    assert_eq!(real_body["slot_types"], fake_body["slot_types"]);

    // Stable per address, or asking twice answers the question.
    let (_, again, _) = prelogin(unknown_email.clone()).await;
    assert_eq!(
        fake_body["client_salt"], again["client_salt"],
        "the fabricated salt changed between requests"
    );

    // And the timing. Averaged over several requests, because a single pair
    // is noise. The floor in `auth::prelogin` is what makes this hold.
    let mut real_total = std::time::Duration::ZERO;
    let mut fake_total = std::time::Duration::ZERO;
    for _ in 0..5 {
        real_total += prelogin(real_email.clone()).await.2;
        fake_total += prelogin(unknown_email.clone()).await.2;
    }

    let difference = real_total.abs_diff(fake_total).as_millis();
    assert!(
        difference < 100,
        "the two paths differ by {difference}ms over five requests, which is \
         enough to tell them apart. Section 9.5 requires the response times to \
         match."
    );
}
