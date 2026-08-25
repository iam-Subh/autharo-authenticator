//! The socket, and nothing else (PRD section 14.2).
//!
//! `authcore::transport` owns every decision about what to say to the server:
//! the paths, the query parameters, the base64url, the JSON shapes, and which
//! status means which thing. This file opens the connection and hands the bytes
//! back.
//!
//! # Why the split lands here
//!
//! Two reasons, and neither is style.
//!
//! A real HTTP stack drags in a TLS implementation that has to cross-compile to
//! every target the app ships to. Keeping it out of `authcore` means the crate
//! holding the cryptography and the storage builds anywhere with no C toolchain
//! — and this project has already lost time to exactly that problem once, with
//! OpenSSL and SQLCipher (see README.md).
//!
//! More importantly: the bugs in a client like this are not in the socket. They
//! are in a status mapped to the wrong action, a parameter left off a request,
//! a field encoded with the wrong alphabet. All of that is in `authcore`, where
//! it is tested against a fake client that asserts the exact URL and body —
//! which a test against a live server could not do without becoming a test of
//! the server. What is left here is small enough to read in one sitting, and
//! has no behaviour worth getting wrong.
//!
//! The property harness drives the same `authcore` transport over real HTTP in
//! `core/tests/convergence_http.rs`, so the code this file feeds is the code
//! that run exercises.

use authcore::transport::{HttpClient, HttpRequest, HttpResponse, Method};
use std::io::Read;

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A blocking client, because `SyncTransport` is synchronous.
///
/// The bridge calls sync from a worker thread — Dart is not blocked by it — and
/// an async client here would mean an executor inside the library for no gain.
pub struct ReqwestClient {
    inner: reqwest::blocking::Client,
}

impl ReqwestClient {
    pub fn new() -> Self {
        Self {
            inner: reqwest::blocking::Client::builder()
                // OFF-06 retries; a request that hangs past this is one the
                // caller should be told about rather than left waiting on.
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("a blocking HTTP client with no unusual configuration"),
        }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
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

        // FR-37: the device clock either side of the request, so the core can
        // correct for the round trip. Taken here because this is the layer that
        // owns a clock — the core reads none.
        let sent_ms = now_ms();
        let response = builder.send().map_err(describe)?;
        let received_ms = now_ms();

        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err("the server reply is larger than 8 MiB".to_string());
        }

        let status = response.status().as_u16();

        let date = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("the response could not be read: {error}"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("the server reply is larger than 8 MiB".to_string());
        }

        Ok(HttpResponse {
            status,
            body,
            date,
            sent_ms,
            received_ms,
        })
    }
}

/// The device's wall clock, in epoch milliseconds.
///
/// Deliberately the uncorrected one: this is the clock being measured, and
/// applying the stored offset here would fold the previous answer into the
/// next measurement and let an error compound.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// Turns a client error into something a user can act on.
///
/// `reqwest`'s own `Display` is written for developers — "error sending
/// request for url (https://…)" tells someone with no network that their URL is
/// somehow at fault. The distinction that matters to a user is whether to check
/// their connection, wait, or report a problem.
fn describe(error: reqwest::Error) -> String {
    if error.is_timeout() {
        return "the server did not answer in time".to_string();
    }
    if error.is_connect() {
        return "this device could not reach the sync server".to_string();
    }
    if error.is_decode() {
        return "the server's reply was not readable".to_string();
    }
    error.to_string()
}
