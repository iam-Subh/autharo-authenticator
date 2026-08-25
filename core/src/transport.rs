//! Talking to the sync server (PRD sections 10.3, 10.6, 14.2).
//!
//! # What is here and what is not
//!
//! Everything about *what to say*: the paths, the query parameters, the
//! base64url, the JSON shapes, and — the part that has already been wrong once
//! — which HTTP status means which thing to the client.
//!
//! Nothing about *how to say it*. Opening a socket is the platform's job, and
//! it arrives through [`HttpClient`], which has one method and no knowledge of
//! this protocol.
//!
//! # Why the split
//!
//! Two reasons, and the second is the important one.
//!
//! The first is the build. A real HTTP stack drags in a TLS implementation that
//! has to cross-compile to every target this project ships to, and this
//! codebase has already lost a week to exactly that (see the note on SQLCipher
//! and OpenSSL in README.md). Keeping it out of `authcore` means the crate that
//! holds the cryptography and the storage builds anywhere, with no C toolchain
//! and no TLS to configure.
//!
//! The second: the bugs in a client like this are not in the socket. They are
//! in a status code mapped to the wrong action, a parameter left off a request,
//! a field base64'd the wrong way. All of that is here, and all of it is tested
//! without a network — the fake client in the tests below asserts the exact URL
//! and body, which a test against a live server could not do without becoming a
//! test of the server.
//!
//! It also means the transport the property harness drives over real HTTP is
//! *this* one, rather than a second implementation written to look like it. A
//! second implementation is how the model server in the convergence harness
//! came to disagree with the real one for sixty thousand operations.

use core::fmt;

use crate::hlc::Hlc;
use crate::secret::SecretString;
use crate::sync::{
    PullMode, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport, WireRecord,
};

/// The HTTP verbs this client uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    /// Section 9.5's device revocation and account deletion.
    Delete,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        })
    }
}

/// One request, fully formed. The client adds nothing but the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: Method,
    /// Absolute, with the query string already on it.
    pub url: String,
    /// Sent as `Authorization: Bearer <token>`.
    pub bearer: Option<String>,
    /// Sent as `Content-Type: application/json` when present.
    pub json: Option<Vec<u8>>,
}

/// What came back. The status is kept as a number because this module, not the
/// client, decides what each one means.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// The `Date` header, for FR-37's clock measurement.
    ///
    /// Section 13 requires the server to send an accurate one on every
    /// response. Reading it here costs nothing: the request was already being
    /// made, so a device that syncs measures its clock for free and needs no
    /// second protocol and no UDP port that a captive portal will block.
    pub date: Option<String>,
    /// The device clock when the request went out and when it came back.
    ///
    /// Supplied by the client because it is the thing that owns a clock. The
    /// core reads none — see [`crate::time_offset`] for why the round trip has
    /// to be known rather than assumed away.
    pub sent_ms: i64,
    pub received_ms: i64,
}

impl HttpResponse {
    /// A response with no timing, for callers that are not measuring.
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            ..Default::default()
        }
    }
}

/// A way to send one request and get one response.
///
/// Deliberately tiny. Everything this trait could plausibly grow — retries,
/// backoff, tokens, JSON — belongs above it, where it can be tested without a
/// socket. An implementation that did any of those would be duplicating logic
/// that already exists here, differently.
pub trait HttpClient {
    /// The error is a string because the only thing this module does with it is
    /// put it in front of the user inside [`SyncError::Transport`]. A typed
    /// error would mean this module deciding what a platform's failures mean,
    /// which it cannot know.
    fn send(&self, request: HttpRequest) -> core::result::Result<HttpResponse, String>;
}

/// The sync endpoints, over an injected client.
pub struct ServerTransport<C: HttpClient> {
    client: C,
    /// No trailing slash.
    base: String,
    /// A bearer token is a credential: wrapped so it is wiped on drop and
    /// redacted in `Debug` (section 9.4), like every other secret here.
    token: SecretString,
    /// The most recent usable clock reading (FR-37).
    ///
    /// Kept rather than acted on, because acting on it means writing to the
    /// store and this module has none. The caller takes it after a cycle.
    latest_sample: Option<crate::time_offset::Sample>,
}

impl<C: HttpClient> ServerTransport<C> {
    pub fn new(client: C, base_url: &str, token: SecretString) -> Self {
        Self {
            client,
            base: base_url.trim_end_matches('/').to_string(),
            token,
            latest_sample: None,
        }
    }

    /// The newest clock reading taken during this transport's requests.
    ///
    /// `None` when nothing measurable has happened — no request yet, or a
    /// server that sent no usable `Date`. Not the same as an offset of zero.
    pub fn latest_sample(&self) -> Option<crate::time_offset::Sample> {
        self.latest_sample
    }

    /// Swaps in a token obtained by refreshing the session.
    pub fn set_token(&mut self, token: SecretString) {
        self.token = token;
    }

    fn get(&self, path: &str) -> HttpRequest {
        HttpRequest {
            method: Method::Get,
            url: format!("{}{path}", self.base),
            bearer: Some(self.token.expose().to_string()),
            json: None,
        }
    }

    fn post(&self, path: &str, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: Method::Post,
            url: format!("{}{path}", self.base),
            bearer: Some(self.token.expose().to_string()),
            json: Some(body),
        }
    }

    fn send(&mut self, request: HttpRequest) -> core::result::Result<Vec<u8>, SyncError> {
        let response = self
            .client
            .send(request)
            .map_err(|detail| SyncError::Transport { detail })?;

        // FR-37, taken from a request that was happening anyway. Recorded even
        // when the response is an error: a 409 carries just as accurate a
        // `Date` as a 200, and a device whose every request fails is a device
        // that especially needs to know its clock is wrong.
        if let Some(date) = &response.date
            && let Ok(reference_ms) = crate::time_offset::parse_http_date(date)
        {
            self.latest_sample = Some(crate::time_offset::Sample {
                reference_ms,
                sent_ms: response.sent_ms,
                received_ms: response.received_ms,
            });
        }

        if (200..300).contains(&response.status) {
            return Ok(response.body);
        }
        Err(error_for(response.status, &response.body))
    }
}

/// What a status means to the client.
///
/// # The three that are not interchangeable
///
/// - **410** is the only one that says "your cursor is unusable, re-sync in
///   full". It had to be given its own status: it used to be a `409`, which is
///   also what "this email is already registered" returns, and a client left to
///   tell them apart by the message string breaks the first time the message is
///   reworded. See `server/tests/stale_cursor.rs`.
/// - **401** means the session is over. Retrying with the same token loops
///   forever; the client has to log in again. Folding it into the retry bucket
///   is the same mistake as the 409, one layer up.
/// - Everything else is worth retrying with backoff (OFF-06).
///
/// The body is included in the detail because the server puts a human-readable
/// message there, and a user looking at "sync failed" deserves the reason.
fn error_for(status: u16, body: &[u8]) -> SyncError {
    let detail = String::from_utf8_lossy(body).trim().to_string();
    match status {
        410 => SyncError::CursorTooOld,
        401 | 403 if detail.contains("unauthorized") || detail.contains("authentication") => {
            SyncError::Unauthorized
        }
        401 => SyncError::Unauthorized,
        _ => SyncError::Transport {
            detail: format!("the server returned {status}: {detail}"),
        },
    }
}

impl<C: HttpClient> SyncTransport for ServerTransport<C> {
    fn pull(
        &mut self,
        since: i64,
        limit: i64,
        mode: PullMode,
    ) -> core::result::Result<PullResponse, SyncError> {
        // `full` is not optional decoration. Without it the server refuses page
        // two of every re-sync on a vault larger than one page, and the re-sync
        // can then never complete. See `PullMode`.
        let full = matches!(mode, PullMode::FullResync);
        let request = self.get(&format!(
            "/v1/vault/changes?since={since}&limit={limit}&full={full}"
        ));

        let body = self.send(request)?;
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(bad_response)?;

        let mut records = Vec::new();
        for record in value["records"].as_array().into_iter().flatten() {
            records.push(WireRecord {
                entry_id: string_field(record, "entry_id")?,
                ciphertext: optional_base64(record, "ciphertext")?,
                nonce: optional_base64(record, "nonce")?,
                hlc: hlc_field(record, "hlc")?,
                deleted: record["deleted"].as_bool().unwrap_or(false),
                server_seq: record["seq"]
                    .as_i64()
                    .ok_or_else(|| bad_response("a record came back without a sequence number"))?,
            });
        }

        Ok(PullResponse {
            records,
            cursor: value["cursor"].as_i64().unwrap_or(since),
            has_more: value["has_more"].as_bool().unwrap_or(false),
        })
    }

    fn push(&mut self, records: &[PushRecord]) -> core::result::Result<PushResponse, SyncError> {
        let payload = serde_json::json!({
            "records": records.iter().map(encode_push).collect::<Vec<_>>(),
        });
        let request = self.post(
            "/v1/vault/records",
            serde_json::to_vec(&payload).map_err(bad_response)?,
        );

        let body = self.send(request)?;
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(bad_response)?;

        let accepted: Vec<String> = value["accepted"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str().map(str::to_string))
            .collect();

        let mut conflicts = Vec::new();
        for conflict in value["conflicts"].as_array().into_iter().flatten() {
            conflicts.push(WireRecord {
                entry_id: string_field(conflict, "entry_id")?,
                ciphertext: optional_base64(conflict, "ciphertext")?,
                nonce: optional_base64(conflict, "nonce")?,
                hlc: hlc_field(conflict, "hlc")?,
                deleted: conflict["deleted"].as_bool().unwrap_or(false),
                // A conflict carries no sequence number, and nothing on this
                // path reads one: the record is compared by timestamp and
                // either taken or kept, and the cursor comes from the pull.
                server_seq: 0,
            });
        }

        Ok(PushResponse {
            accepted,
            conflicts,
        })
    }
}

fn encode_push(record: &PushRecord) -> serde_json::Value {
    serde_json::json!({
        "entry_id": record.entry_id,
        "ciphertext": record.ciphertext.as_deref().map(b64_encode),
        "nonce": record.nonce.as_deref().map(b64_encode),
        "hlc": record.hlc.to_string(),
        "deleted": record.deleted,
        "base_hlc": record.base_hlc.map(|hlc| hlc.to_string()),
    })
}

fn bad_response(detail: impl fmt::Display) -> SyncError {
    SyncError::Transport {
        detail: format!("the server sent a response this client cannot read: {detail}"),
    }
}

fn string_field(value: &serde_json::Value, field: &str) -> core::result::Result<String, SyncError> {
    value[field]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| bad_response(format!("a record came back without {field}")))
}

fn hlc_field(value: &serde_json::Value, field: &str) -> core::result::Result<Hlc, SyncError> {
    string_field(value, field)?
        .parse()
        .map_err(|_| bad_response(format!("a record came back with an unreadable {field}")))
}

fn optional_base64(
    value: &serde_json::Value,
    field: &str,
) -> core::result::Result<Option<Vec<u8>>, SyncError> {
    match value[field].as_str() {
        None => Ok(None),
        Some(text) => b64_decode(text)
            .map(Some)
            .map_err(|_| bad_response(format!("{field} is not valid base64url"))),
    }
}

// ---------------------------------------------------------------------------
// base64url, unpadded
// ---------------------------------------------------------------------------
//
// Written out rather than taken from a crate. It is thirty lines, the alphabet
// is fixed by the server, and it keeps `authcore`'s dependency list to things
// that are load-bearing. The tests below check it against the vectors in
// RFC 4648 section 10, adjusted for the URL alphabet and no padding.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding, as section 14.2's wire format uses.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let digits = [
            ALPHABET[(n >> 18 & 63) as usize],
            ALPHABET[(n >> 12 & 63) as usize],
            ALPHABET[(n >> 6 & 63) as usize],
            ALPHABET[(n & 63) as usize],
        ];
        // Three bytes make four digits, two make three, one makes two.
        let keep = chunk.len() + 1;
        for digit in digits.iter().take(keep) {
            out.push(*digit as char);
        }
    }
    out
}

/// The inverse. Rejects padding, whitespace and the standard alphabet's `+/`,
/// rather than accepting them quietly: a record that decoded from the wrong
/// alphabet would fail to authenticate later, much further from the cause.
pub fn b64_decode(text: &str) -> core::result::Result<Vec<u8>, Base64Error> {
    let mut value = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);

    for byte in text.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(Base64Error),
        };
        value = value << 6 | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
        }
    }

    // Leftover bits must be zero. Anything else is a truncated or altered
    // string dressed up as a valid one.
    if value & ((1 << bits) - 1) != 0 {
        return Err(Base64Error);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Error;

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("this value is not unpadded base64url")
    }
}

impl std::error::Error for Base64Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records what was asked for and answers with what the test chose. The
    /// point of the whole split: the request can be asserted exactly, which is
    /// not possible against a live server without testing the server instead.
    struct FakeClient {
        seen: RefCell<Vec<HttpRequest>>,
        reply: RefCell<Vec<HttpResponse>>,
    }

    impl FakeClient {
        fn answering(status: u16, body: &str) -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                reply: RefCell::new(vec![HttpResponse::new(status, body.as_bytes().to_vec())]),
            }
        }
    }

    impl HttpClient for &FakeClient {
        fn send(&self, request: HttpRequest) -> core::result::Result<HttpResponse, String> {
            self.seen.borrow_mut().push(request);
            Ok(self
                .reply
                .borrow_mut()
                .pop()
                .unwrap_or(HttpResponse::new(200, b"{}".to_vec())))
        }
    }

    fn transport(client: &FakeClient) -> ServerTransport<&FakeClient> {
        ServerTransport::new(client, "https://example.invalid/", SecretString::new("tok"))
    }

    #[test]
    fn a_full_resync_asks_for_one() {
        let client = FakeClient::answering(200, r#"{"records":[],"cursor":7,"has_more":false}"#);
        let mut transport = transport(&client);

        transport.pull(3, 500, PullMode::FullResync).unwrap();

        let seen = &client.seen.borrow()[0];
        assert_eq!(
            seen.url, "https://example.invalid/v1/vault/changes?since=3&limit=500&full=true",
            "without full=true the server refuses page two of every re-sync"
        );
        assert_eq!(seen.bearer.as_deref(), Some("tok"));
    }

    #[test]
    fn an_incremental_pull_does_not() {
        let client = FakeClient::answering(200, r#"{"records":[],"cursor":7,"has_more":false}"#);
        let mut transport = transport(&client);

        transport.pull(3, 500, PullMode::Incremental).unwrap();

        assert!(
            client.seen.borrow()[0].url.ends_with("full=false"),
            "an incremental pull must still be checked against the watermark"
        );
    }

    #[test]
    fn a_410_is_the_only_status_that_means_re_sync() {
        assert!(matches!(error_for(410, b""), SyncError::CursorTooOld));

        for status in [400, 403, 404, 409, 429, 500, 502, 503] {
            assert!(
                matches!(error_for(status, b""), SyncError::Transport { .. }),
                "{status} must not send the client into a full re-sync"
            );
        }
    }

    #[test]
    fn a_401_says_the_session_is_over_rather_than_retry_forever() {
        assert!(matches!(error_for(401, b""), SyncError::Unauthorized));
    }

    #[test]
    fn a_pushed_record_carries_its_base_revision() {
        let client = FakeClient::answering(200, r#"{"accepted":[],"conflicts":[]}"#);
        let mut transport = transport(&client);

        transport
            .push(&[PushRecord {
                entry_id: "e1".to_string(),
                ciphertext: Some(vec![1, 2, 3]),
                nonce: Some(vec![4, 5, 6]),
                hlc: Hlc::new(7, 1, 9),
                deleted: false,
                base_hlc: Some(Hlc::new(6, 0, 9)),
            }])
            .unwrap();

        let seen = &client.seen.borrow()[0];
        let body: serde_json::Value = serde_json::from_slice(seen.json.as_ref().unwrap()).unwrap();
        let record = &body["records"][0];

        assert_eq!(record["entry_id"], "e1");
        assert_eq!(record["ciphertext"], b64_encode(&[1, 2, 3]));
        assert_eq!(record["hlc"], Hlc::new(7, 1, 9).to_string());
        assert_eq!(
            record["base_hlc"],
            Hlc::new(6, 0, 9).to_string(),
            "without the base revision the server cannot detect a conflict"
        );
    }

    #[test]
    fn a_tombstone_pushes_a_null_ciphertext_rather_than_an_empty_one() {
        let client = FakeClient::answering(200, r#"{"accepted":[],"conflicts":[]}"#);
        let mut transport = transport(&client);

        transport
            .push(&[PushRecord {
                entry_id: "e1".to_string(),
                ciphertext: None,
                nonce: None,
                hlc: Hlc::new(7, 0, 9),
                deleted: true,
                base_hlc: None,
            }])
            .unwrap();

        let seen = &client.seen.borrow()[0];
        let body: serde_json::Value = serde_json::from_slice(seen.json.as_ref().unwrap()).unwrap();
        assert!(body["records"][0]["ciphertext"].is_null());
        assert!(body["records"][0]["base_hlc"].is_null());
    }

    #[test]
    fn a_pulled_record_round_trips() {
        let body = format!(
            r#"{{"records":[{{"entry_id":"e1","ciphertext":"{}","nonce":"{}","hlc":"{}","deleted":false,"seq":12}}],"cursor":12,"has_more":true}}"#,
            b64_encode(&[9, 8, 7]),
            b64_encode(&[1; 24]),
            Hlc::new(5, 2, 3)
        );
        let client = FakeClient::answering(200, &body);
        let mut transport = transport(&client);

        let response = transport.pull(0, 500, PullMode::Incremental).unwrap();

        assert_eq!(response.cursor, 12);
        assert!(response.has_more);
        let record = &response.records[0];
        assert_eq!(record.entry_id, "e1");
        assert_eq!(record.ciphertext.as_deref(), Some(&[9, 8, 7][..]));
        assert_eq!(record.hlc, Hlc::new(5, 2, 3));
        assert_eq!(record.server_seq, 12);
    }

    #[test]
    fn a_response_this_client_cannot_read_is_an_error_not_a_silent_empty() {
        let client = FakeClient::answering(200, r#"{"records":[{"entry_id":"e1"}]}"#);
        let mut transport = transport(&client);

        let error = transport.pull(0, 500, PullMode::Incremental).unwrap_err();
        assert!(
            matches!(error, SyncError::Transport { .. }),
            "a record without a timestamp must not be treated as an empty page"
        );
    }

    #[test]
    fn a_response_measures_the_device_clock() {
        // FR-37, from a request that was happening anyway. The alternative is
        // a second protocol over a UDP port that captive portals block.
        let client = FakeClient::answering(200, r#"{"records":[],"cursor":0,"has_more":false}"#);
        client.reply.borrow_mut().clear();
        client.reply.borrow_mut().push(HttpResponse {
            status: 200,
            body: br#"{"records":[],"cursor":0,"has_more":false}"#.to_vec(),
            date: Some("Sun, 23 Aug 2026 02:22:07 GMT".to_string()),
            // A device forty seconds behind the server.
            sent_ms: 1_787_451_687_000,
            received_ms: 1_787_451_687_100,
        });

        let mut transport = transport(&client);
        transport.pull(0, 500, PullMode::Incremental).unwrap();

        let sample = transport.latest_sample().expect("a Date header was sent");
        assert!(matches!(
            crate::time_offset::measure(sample),
            crate::time_offset::Measurement::Offset { seconds: 40, .. }
        ));
    }

    #[test]
    fn a_failed_response_still_measures_the_clock() {
        // A device whose every request fails is a device that especially needs
        // to know its clock is wrong — a wrong clock is one of the reasons a
        // request fails. Skipping the measurement on an error would hide the
        // cause exactly when it matters.
        let client = FakeClient::answering(500, "");
        client.reply.borrow_mut().clear();
        client.reply.borrow_mut().push(HttpResponse {
            status: 500,
            body: b"upstream on fire".to_vec(),
            date: Some("Sun, 23 Aug 2026 02:22:07 GMT".to_string()),
            sent_ms: 1_787_451_727_000,
            received_ms: 1_787_451_727_000,
        });

        let mut transport = transport(&client);
        assert!(transport.pull(0, 500, PullMode::Incremental).is_err());
        assert!(transport.latest_sample().is_some());
    }

    #[test]
    fn a_server_that_sends_no_date_measures_nothing() {
        // Nothing measured is not an offset of zero. Defaulting to zero would
        // report a clock as checked and correct when it had never been read.
        let client = FakeClient::answering(200, r#"{"records":[],"cursor":0,"has_more":false}"#);
        let mut transport = transport(&client);
        transport.pull(0, 500, PullMode::Incremental).unwrap();
        assert!(transport.latest_sample().is_none());
    }

    #[test]
    fn an_unreadable_date_measures_nothing_rather_than_guessing() {
        let client = FakeClient::answering(200, r#"{"records":[],"cursor":0,"has_more":false}"#);
        client.reply.borrow_mut().clear();
        client.reply.borrow_mut().push(HttpResponse {
            status: 200,
            body: br#"{"records":[],"cursor":0,"has_more":false}"#.to_vec(),
            date: Some("some time on Tuesday".to_string()),
            sent_ms: 1_000,
            received_ms: 1_100,
        });

        let mut transport = transport(&client);
        transport.pull(0, 500, PullMode::Incremental).unwrap();
        assert!(transport.latest_sample().is_none());
    }

    #[test]
    fn base64url_matches_rfc_4648_section_10() {
        // The RFC's vectors, in the URL alphabet without padding.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(plain.as_bytes()), encoded, "encoding {plain:?}");
            assert_eq!(
                b64_decode(encoded).unwrap(),
                plain.as_bytes(),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn base64url_uses_the_url_alphabet_and_no_padding() {
        // 0xFB 0xFF encodes to "+/" in the standard alphabet and "-_" here.
        assert_eq!(b64_encode(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert!(
            b64_decode("+/+/").is_err(),
            "the standard alphabet is not this one"
        );
        assert!(
            b64_decode("Zg==").is_err(),
            "padding is not part of this format"
        );
        assert!(
            b64_decode("Zg ").is_err(),
            "whitespace is not part of this format"
        );
    }

    #[test]
    fn every_byte_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        for len in 0..all.len() {
            let slice = &all[..len];
            assert_eq!(
                b64_decode(&b64_encode(slice)).unwrap(),
                slice,
                "length {len}"
            );
        }
    }

    #[test]
    fn the_token_is_not_printed() {
        let client = FakeClient::answering(200, "{}");
        let transport = ServerTransport::new(
            &client,
            "https://example.invalid",
            SecretString::new("super-secret-token"),
        );
        assert!(
            !format!("{:?}", transport.token).contains("super-secret-token"),
            "a bearer token is a credential and must not reach a log"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_base_url_does_not_double_up() {
        let client = FakeClient::answering(200, r#"{"records":[],"cursor":0,"has_more":false}"#);
        let mut transport = ServerTransport::new(
            &client,
            "https://example.invalid///",
            SecretString::new("t"),
        );

        transport.pull(0, 1, PullMode::Incremental).unwrap();
        assert!(
            client.seen.borrow()[0]
                .url
                .starts_with("https://example.invalid/v1/")
        );
    }
}
