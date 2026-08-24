//! The convergence harness over real HTTP, against a real server.
//!
//! # What this adds over `convergence.rs`
//!
//! The in-memory backend hands `WireRecord` values straight across, so no
//! number of passing runs says anything about serialisation, base64url, UUID
//! parsing, or which status the server chose for which condition. Those are
//! where a mismatch sits quietly: both sides compile, both have tests, and the
//! two disagree.
//!
//! It has already found two. The stale cursor came back as `409 Conflict`,
//! sharing a status and an error code with "this email is already registered",
//! so the only thing separating them was the message string. And the in-memory
//! model server disagreed with the real one about a push whose base the server
//! cannot check, which stranded three devices on their own creations for sixty
//! thousand operations.
//!
//! # The transport under test is the transport that ships
//!
//! [`ServerTransport`] and [`SessionClient`] come from `authcore`. This file
//! adds only the socket — a `reqwest` implementation of [`HttpClient`] — and
//! the observation the coverage floor needs.
//!
//! That is deliberate. An earlier version of this file had its own HTTP client,
//! its own URL building and its own status mapping, which meant the thing under
//! test was a second implementation that resembled the shipped one. Being a
//! second implementation nobody compared is exactly how the model server's
//! disagreement survived so long.
//!
//! # What it does not cover
//!
//! Nothing here can move the server's prune watermark: no endpoint writes it,
//! and this test holds no database connection. The stale-cursor and
//! full-re-sync parts of the coverage floor are therefore switched off through
//! [`Backend::can_prune`] rather than quietly left at zero. Both are covered
//! against the in-memory server, and the 410 itself is pinned on the server
//! side by `server/tests/stale_cursor.rs` and on the client side by the unit
//! tests in `authcore::transport`.
//!
//! # Running it
//!
//! ```text
//! cargo run -p authserver                       # in another terminal
//! cargo test --test convergence_http -- --ignored --nocapture
//! ```

mod harness;

use authcore::account::{Account, PasswordSlot, RecoverySlot};
use authcore::pin::KdfParams;
use authcore::secret::SecretString;
use authcore::session::SessionClient;
use authcore::sync::{PullMode, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport};
use authcore::transport::{HttpClient, HttpRequest, HttpResponse, Method, ServerTransport};

use harness::{Backend, Observed, go};

use zeroize::Zeroizing;

/// Small on purpose. The point is the wire, not the number of interleavings —
/// those are covered in memory, and each operation here is a real round trip.
const HTTP_OPS: usize = 800;
const SEED: u64 = 0xA77B_0001;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

fn base_url() -> String {
    std::env::var("AUTHCORE_SYNC_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

// ---------------------------------------------------------------------------
// The socket, and nothing else
// ---------------------------------------------------------------------------

/// The only thing this file adds to the shipped client.
///
/// Blocking, because [`SyncTransport`] is synchronous: the app calls it from a
/// worker thread, and an async client here would exercise a shape nothing uses.
#[derive(Clone)]
struct ReqwestClient {
    inner: reqwest::blocking::Client,
}

impl ReqwestClient {
    fn new() -> Self {
        Self {
            inner: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .expect("a blocking HTTP client"),
        }
    }
}

impl HttpClient for ReqwestClient {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let mut builder = match request.method {
            Method::Get => self.inner.get(&request.url),
            Method::Post => self.inner.post(&request.url),
            Method::Delete => self.inner.delete(&request.url),
        };
        if let Some(token) = &request.bearer {
            builder = builder.bearer_auth(token);
        }
        if let Some(body) = request.json {
            builder = builder
                .header("content-type", "application/json")
                .body(body);
        }

        // FR-37: the device clock either side of the request. This mirrors
        // `app/rust/src/http.rs`, which is unavoidable duplication — the two
        // live in different crates and `authcore` cannot depend on the bridge.
        // Keeping them the same shape at least means the harness exercises the
        // measurement path rather than a simpler one.
        let sent_ms = now_ms();
        let response = builder.send().map_err(|error| {
            format!(
                "{error}. Is a server running at {}? Start one with `cargo run -p authserver`.",
                base_url()
            )
        })?;
        let received_ms = now_ms();

        let date = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        Ok(HttpResponse {
            status: response.status().as_u16(),
            body: response
                .bytes()
                .map_err(|error| error.to_string())?
                .to_vec(),
            date,
            sent_ms,
            received_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// An account, signed up for the run
// ---------------------------------------------------------------------------

/// Registers a fresh account and signs in, returning the access token.
///
/// All three devices share it, because all three are the *same* vault — which
/// is what makes their records conflict. Real devices hold their own sessions;
/// the difference does not reach the sync endpoints, which key on the account.
fn sign_up() -> SecretString {
    let client = SessionClient::new(ReqwestClient::new(), &base_url());

    // Unique per run, so repeated runs do not collide on the address.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let email = format!("convergence-{SEED:x}-{stamp:x}@example.invalid");

    // Shaped like real slots but not derived from a password: this file is
    // about the sync endpoints, and section 9.2.1's derivation is tested in
    // `account.rs`.
    let account = Account {
        email: email.clone(),
        password_slot: Some(PasswordSlot {
            salt: [0x44; 16],
            params: KdfParams::default(),
            wrapped_key: vec![0x11; 48],
            nonce: vec![0x22; 24],
        }),
        recovery_slot: RecoverySlot {
            wrapped_key: vec![0x11; 48],
            nonce: vec![0x22; 24],
        },
    };
    let auth_key = Zeroizing::new([0x33u8; 32]);

    client
        .register(&account, &auth_key)
        .expect("the harness needs a running server");
    client
        .login(&email, &auth_key, Some("convergence harness"))
        .expect("sign-in must succeed straight after registering")
        .access_token
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

struct HttpServer {
    transport: ServerTransport<ReqwestClient>,
}

impl HttpServer {
    fn new() -> Self {
        Self {
            transport: ServerTransport::new(ReqwestClient::new(), &base_url(), sign_up()),
        }
    }
}

/// A thin observer over the shipped transport.
///
/// It adds no protocol of its own: the conflicts it reports are the ones
/// [`ServerTransport`] already returns, and the stale flag comes from the error
/// that transport already produces.
struct HttpLink<'a> {
    transport: &'a mut ServerTransport<ReqwestClient>,
    partitioned: bool,
    conflicted: Vec<String>,
    stale: bool,
}

impl SyncTransport for HttpLink<'_> {
    fn pull(&mut self, since: i64, limit: i64, mode: PullMode) -> Result<PullResponse, SyncError> {
        if self.partitioned {
            return Err(SyncError::Transport {
                detail: "the device is partitioned".to_string(),
            });
        }
        let result = self.transport.pull(since, limit, mode);
        if let Err(SyncError::CursorTooOld) = result {
            self.stale = true;
        }
        result
    }

    fn push(&mut self, records: &[PushRecord]) -> Result<PushResponse, SyncError> {
        if self.partitioned {
            return Err(SyncError::Transport {
                detail: "the device is partitioned".to_string(),
            });
        }
        let response = self.transport.push(records)?;
        self.conflicted.extend(
            response
                .conflicts
                .iter()
                .map(|record| record.entry_id.clone()),
        );
        Ok(response)
    }
}

impl Observed for HttpLink<'_> {
    fn conflicted(&self) -> &[String] {
        &self.conflicted
    }

    fn stale(&self) -> bool {
        self.stale
    }
}

impl Backend for HttpServer {
    fn open(&mut self, partitioned: bool) -> Box<dyn Observed + '_> {
        Box::new(HttpLink {
            transport: &mut self.transport,
            partitioned,
            conflicted: Vec::new(),
            stale: false,
        })
    }

    fn prune(&mut self) -> bool {
        false
    }

    fn can_prune(&self) -> bool {
        // No endpoint moves the watermark, and this test holds no database
        // connection. Declared rather than left silently at zero, so the floor
        // names the gap instead of lowering itself.
        false
    }

    fn can_replay_pushes(&self) -> bool {
        // Re-sending a push byte for byte needs the exact request that was
        // sent, and this backend does not keep one — the shipped transport
        // builds each request and discards it. Idempotency is covered against
        // the in-memory server, which keeps them. Declared for the same reason
        // as `can_prune`.
        false
    }

    fn shrink_budget(&self) -> usize {
        // Operations, not replays. Each one is a real round trip and every
        // replay registers a fresh account, so the whole shrink gets about
        // thirty runs of the default length.
        25_000
    }

    fn replay_push(&mut self, _which: usize) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a running server: cargo run -p authserver"]
fn three_devices_converge_over_http() {
    go(SEED, HTTP_OPS, &HttpServer::new);
}
