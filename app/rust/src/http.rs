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
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::Arc;
use x509_parser::parse_x509_certificate;

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
        let mut builder = reqwest::blocking::Client::builder()
            // OFF-06 retries; a request that hangs past this is one the
            // caller should be told about rather than left waiting on.
            .timeout(std::time::Duration::from_secs(30));
        if let Some(verifier) = production_verifier()
            .unwrap_or_else(|error| panic!("the production certificate pins are invalid: {error}"))
        {
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            builder = builder.use_preconfigured_tls(config);
        }
        Self {
            inner: builder
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
        enforce_production_host(&request.url)?;
        let mut builder = match request.method {
            Method::Get => self.inner.get(&request.url),
            Method::Post => self.inner.post(&request.url),
            Method::Put => self.inner.put(&request.url),
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

#[derive(Debug)]
struct SpkiPinVerifier {
    normal: Arc<WebPkiServerVerifier>,
    hostname: String,
    pins: [[u8; 32]; 2],
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.normal.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let requested = match server_name {
            ServerName::DnsName(name) => name.as_ref(),
            _ => return Ok(verified),
        };
        if !requested.eq_ignore_ascii_case(&self.hostname) {
            return Ok(verified);
        }
        let digest = spki_digest(end_entity)?;
        if self.pins.contains(&digest) {
            Ok(verified)
        } else {
            Err(rustls::Error::General(
                "the server certificate public key does not match a trusted application pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.normal
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.normal
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.normal.supported_verify_schemes()
    }
}

fn spki_digest(certificate: &CertificateDer<'_>) -> Result<[u8; 32], rustls::Error> {
    let (_, certificate) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| rustls::Error::General("the server certificate is not valid X.509".into()))?;
    Ok(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
}

fn production_verifier() -> Result<Option<SpkiPinVerifier>, String> {
    let hostname = env!("AUTHCORE_PINNED_HOST").trim();
    if hostname.is_empty() {
        return Ok(None);
    }
    let pins = env!("AUTHCORE_SPKI_PINS")
        .split(',')
        .map(|value| decode_pin(value.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    let pins: [[u8; 32]; 2] = pins
        .try_into()
        .map_err(|_| "exactly two SPKI pins are required".to_string())?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let normal = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| format!("the normal TLS verifier could not be created: {error}"))?;
    Ok(Some(SpkiPinVerifier {
        normal,
        hostname: hostname.to_ascii_lowercase(),
        pins,
    }))
}

fn decode_pin(value: &str) -> Result<[u8; 32], String> {
    let decoded = B64
        .decode(value)
        .map_err(|_| "an SPKI pin is not valid base64".to_string())?;
    decoded
        .try_into()
        .map_err(|_| "an SPKI pin must contain one SHA-256 digest".to_string())
}

fn enforce_production_host(url: &str) -> Result<(), String> {
    let hostname = env!("AUTHCORE_PINNED_HOST").trim();
    if hostname.is_empty() {
        return Ok(());
    }
    let parsed =
        reqwest::Url::parse(url).map_err(|_| "the server address is not valid".to_string())?;
    if parsed.scheme() != "https" || parsed.host_str() != Some(hostname) {
        return Err(format!(
            "this release connects only to the configured server {hostname}"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod pin_tests {
    use std::sync::Arc;

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::RootCertStore;

    use super::{decode_pin, enforce_production_host, spki_digest, SpkiPinVerifier};

    #[test]
    fn a_pin_must_be_one_sha256_digest() {
        assert!(decode_pin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
        assert!(decode_pin("AA==").is_err());
        assert!(decode_pin("not base64").is_err());
    }

    #[test]
    fn debug_without_a_production_identity_does_not_restrict_hosts() {
        if env!("AUTHCORE_PINNED_HOST").is_empty() {
            assert!(enforce_production_host("http://127.0.0.1:8080").is_ok());
            assert!(enforce_production_host("https://example.invalid").is_ok());
        }
    }

    #[test]
    fn current_and_backup_pins_are_accepted() {
        let certificates = Certificates::new();
        let verifier = certificates.verifier([
            spki_digest(&certificates.current).unwrap(),
            spki_digest(&certificates.backup).unwrap(),
        ]);

        assert!(certificates
            .verify(&verifier, &certificates.current, "sync.example.com")
            .is_ok());
        assert!(certificates
            .verify(&verifier, &certificates.backup, "sync.example.com")
            .is_ok());
    }

    #[test]
    fn an_unknown_pin_is_rejected() {
        let certificates = Certificates::new();
        let verifier = certificates.verifier([[41; 32], [42; 32]]);

        assert!(certificates
            .verify(&verifier, &certificates.current, "sync.example.com")
            .is_err());
    }

    #[test]
    fn normal_tls_checks_run_before_the_pin_check() {
        let certificates = Certificates::new();
        let pin = spki_digest(&certificates.current).unwrap();
        let verifier = certificates.verifier([pin, [42; 32]]);

        assert!(certificates
            .verify(&verifier, &certificates.current, "wrong.example.com")
            .is_err());
        assert!(certificates
            .verify(&verifier, &certificates.expired, "sync.example.com")
            .is_err());

        let untrusted = Certificates::new();
        assert!(certificates
            .verify(&verifier, &untrusted.current, "sync.example.com")
            .is_err());
    }

    struct Certificates {
        root: CertificateDer<'static>,
        current: CertificateDer<'static>,
        backup: CertificateDer<'static>,
        expired: CertificateDer<'static>,
    }

    impl Certificates {
        fn new() -> Self {
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca_key = KeyPair::generate().unwrap();
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = Issuer::new(ca_params, ca_key);

            let issue = |expired: bool| {
                let mut params =
                    CertificateParams::new(vec!["sync.example.com".to_string()]).unwrap();
                if expired {
                    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                    params.not_after = rcgen::date_time_ymd(2020, 1, 2);
                }
                let key = KeyPair::generate().unwrap();
                CertificateDer::from(params.signed_by(&key, &issuer).unwrap().der().to_vec())
            };

            Self {
                root: CertificateDer::from(ca.der().to_vec()),
                current: issue(false),
                backup: issue(false),
                expired: issue(true),
            }
        }

        fn verifier(&self, pins: [[u8; 32]; 2]) -> SpkiPinVerifier {
            let mut roots = RootCertStore::empty();
            roots.add(self.root.clone()).unwrap();
            let normal = WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            SpkiPinVerifier {
                normal,
                hostname: "sync.example.com".to_string(),
                pins,
            }
        }

        fn verify(
            &self,
            verifier: &SpkiPinVerifier,
            certificate: &CertificateDer<'static>,
            hostname: &'static str,
        ) -> Result<(), rustls::Error> {
            verifier
                .verify_server_cert(
                    certificate,
                    &[],
                    &ServerName::try_from(hostname).unwrap(),
                    &[],
                    UnixTime::now(),
                )
                .map(|_| ())
        }
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
