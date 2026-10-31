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
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::Arc;

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

/// Accepts the production host only through a chain that ends at a pinned root.
///
/// The pins name root certificate authorities, not the server's own key. The
/// API sits behind Render, which issues and renews the server certificate
/// itself, from Let's Encrypt or Google Trust Services, with a key the project
/// never holds. A leaf pin would break at the first renewal and could not be
/// given a backup. A root key lasts for decades, so pinning the roots those two
/// authorities issue from still refuses a certificate from any other authority
/// while surviving every renewal.
///
/// The restriction is a smaller trust store, not a check after the fact: the
/// chain is built and verified against the pinned roots alone, so a chain that
/// reaches some other root fails the ordinary path validation.
#[derive(Debug)]
struct PinnedRootVerifier {
    normal: Arc<WebPkiServerVerifier>,
    pinned: Arc<WebPkiServerVerifier>,
    hostname: String,
}

impl ServerCertVerifier for PinnedRootVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let production = match server_name {
            ServerName::DnsName(name) => name.as_ref().eq_ignore_ascii_case(&self.hostname),
            _ => false,
        };
        let verifier = if production { &self.pinned } else { &self.normal };
        verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map_err(|error| {
                if production {
                    rustls::Error::General(format!(
                        "the server certificate does not chain to a pinned root: {error}"
                    ))
                } else {
                    error
                }
            })
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

/// The pin of a trust anchor: SHA-256 over its whole DER
/// `SubjectPublicKeyInfo`, which is what the OpenSSL command in
/// docs/production-security.md prints for the root certificate.
///
/// A `TrustAnchor` stores the *contents* of the `SubjectPublicKeyInfo`
/// SEQUENCE without its tag and length, so they are put back before hashing.
/// Hashing the bare contents would produce a value no published pin matches.
fn anchor_digest(anchor: &TrustAnchor<'_>) -> [u8; 32] {
    let contents = anchor.subject_public_key_info.as_ref();
    let mut sequence = vec![0x30];
    match contents.len() {
        length @ 0..=0x7f => sequence.push(length as u8),
        length @ 0x80..=0xff => sequence.extend([0x81, length as u8]),
        length => sequence.extend([0x82, (length >> 8) as u8, length as u8]),
    }
    sequence.extend_from_slice(contents);
    Sha256::digest(&sequence).into()
}

/// The anchors among `anchors` that the pins name, failing if any pin names none.
///
/// A pin that matches nothing would be silently dropped otherwise, and the
/// application would ship trusting fewer authorities than its build declared.
fn pinned_roots(anchors: &[TrustAnchor<'static>], pins: &[[u8; 32]]) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for pin in pins {
        let anchor = anchors
            .iter()
            .find(|anchor| anchor_digest(anchor) == *pin)
            .ok_or_else(|| format!("the pin {} names no bundled root", B64.encode(pin)))?;
        roots.roots.push(anchor.clone());
    }
    Ok(roots)
}

fn production_verifier() -> Result<Option<PinnedRootVerifier>, String> {
    let hostname = env!("AUTHCORE_PINNED_HOST").trim();
    if hostname.is_empty() {
        return Ok(None);
    }
    let pins = env!("AUTHCORE_SPKI_PINS")
        .split(',')
        .map(|value| decode_pin(value.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = webpki_roots::TLS_SERVER_ROOTS;
    let mut all = RootCertStore::empty();
    all.extend(anchors.iter().cloned());
    let build = |roots: RootCertStore| {
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| format!("a TLS verifier could not be created: {error}"))
    };
    Ok(Some(PinnedRootVerifier {
        normal: build(all)?,
        pinned: build(pinned_roots(anchors, &pins)?)?,
        hostname: hostname.to_ascii_lowercase(),
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

    use base64::Engine;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
    use rustls::RootCertStore;
    use sha2::{Digest, Sha256};
    use x509_parser::parse_x509_certificate;

    use super::{anchor_digest, decode_pin, enforce_production_host, pinned_roots, PinnedRootVerifier, B64};

    /// The pin as the documented OpenSSL command computes it from a certificate.
    fn spki_digest(certificate: &CertificateDer<'_>) -> [u8; 32] {
        let (_, certificate) = parse_x509_certificate(certificate.as_ref()).unwrap();
        Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into()
    }

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

    /// The anchor form drops the SEQUENCE header, so this is the test that
    /// catches a pin computed from the wrong bytes.
    #[test]
    fn an_anchor_digest_equals_the_certificate_pin() {
        let authority = Authority::new();
        assert_eq!(anchor_digest(&authority.anchor()), spki_digest(&authority.root));
    }

    /// ISRG Root X1's RSA-4096 key needs the two-byte DER length form, which a
    /// generated test key does not. The value is the pin Let's Encrypt
    /// publishes, as the documented OpenSSL command prints it.
    #[test]
    fn a_long_rsa_root_digest_matches_its_published_pin() {
        let isrg_root_x1 = decode_pin("C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=").unwrap();
        assert!(webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .any(|anchor| anchor_digest(anchor) == isrg_root_x1));
    }

    #[test]
    fn a_chain_to_a_pinned_root_is_accepted() {
        let current = Authority::new();
        let backup = Authority::new();
        let verifier = verifier(&[&current, &backup], &[&current, &backup]);

        assert!(verify(&verifier, &current.leaf, "sync.example.com").is_ok());
        assert!(verify(&verifier, &backup.leaf, "sync.example.com").is_ok());
    }

    /// The case pinning exists for: a certificate any trusted authority would
    /// vouch for, issued by one the application did not pin.
    #[test]
    fn a_chain_to_a_trusted_but_unpinned_root_is_rejected() {
        let pinned = Authority::new();
        let other = Authority::new();
        let verifier = verifier(&[&pinned, &other], &[&pinned]);

        assert!(verify(&verifier, &other.leaf, "sync.example.com").is_err());
        assert!(verify(&verifier, &other.leaf, "elsewhere.example.com").is_ok());
    }

    #[test]
    fn normal_tls_checks_still_apply_to_the_pinned_host() {
        let authority = Authority::new();
        let verifier = verifier(&[&authority], &[&authority]);

        assert!(verify(&verifier, &authority.leaf, "wrong.example.com").is_err());
        assert!(verify(&verifier, &authority.expired, "sync.example.com").is_err());
    }

    #[test]
    fn a_pin_that_names_no_root_is_refused() {
        let authority = Authority::new();
        let anchors = [authority.anchor()];

        assert!(pinned_roots(&anchors, &[spki_digest(&authority.root)]).is_ok());
        assert!(pinned_roots(&anchors, &[[42; 32]]).is_err());
    }

    /// The production pins name real roots, so they must still be in the
    /// bundled store after a `webpki-roots` upgrade.
    #[test]
    fn the_production_pins_name_bundled_roots() {
        let pins = env!("AUTHCORE_SPKI_PINS");
        if pins.trim().is_empty() {
            return;
        }
        let pins = pins
            .split(',')
            .map(|value| decode_pin(value.trim()).unwrap())
            .collect::<Vec<_>>();
        if let Err(error) = pinned_roots(webpki_roots::TLS_SERVER_ROOTS, &pins) {
            panic!("{error}; bundled pins: {}", bundled_pins());
        }
    }

    /// Reaches the real server through the pinned verifier, so it needs the
    /// network and the production environment from scripts/build_release.ps1:
    /// `cargo test --lib -- --ignored live`.
    #[test]
    #[ignore]
    fn live_production_server_passes_the_pinned_verifier() {
        use authcore::transport::{HttpClient, HttpRequest, Method};
        let host = env!("AUTHCORE_PINNED_HOST");
        assert!(!host.is_empty(), "set the production environment first");
        let response = super::ReqwestClient::new()
            .send(HttpRequest {
                method: Method::Get,
                url: format!("https://{host}/v1/health"),
                bearer: None,
                json: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
    }

    fn bundled_pins() -> String {
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|anchor| B64.encode(anchor_digest(anchor)))
            .collect::<Vec<_>>()
            .join(",")
    }

    struct Authority {
        root: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        expired: CertificateDer<'static>,
    }

    impl Authority {
        fn new() -> Self {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = Issuer::new(ca_params, ca_key);

            // Both names on every leaf, so one certificate shows the pinned
            // host refused and an unpinned host accepted.
            let issue = |expired: bool| {
                let mut params = CertificateParams::new(vec![
                    "sync.example.com".to_string(),
                    "elsewhere.example.com".to_string(),
                ])
                .unwrap();
                if expired {
                    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                    params.not_after = rcgen::date_time_ymd(2020, 1, 2);
                }
                let key = KeyPair::generate().unwrap();
                CertificateDer::from(params.signed_by(&key, &issuer).unwrap().der().to_vec())
            };

            Self {
                root: CertificateDer::from(ca.der().to_vec()),
                leaf: issue(false),
                expired: issue(true),
            }
        }

        fn anchor(&self) -> TrustAnchor<'static> {
            let mut store = RootCertStore::empty();
            store.add(self.root.clone()).unwrap();
            store.roots.remove(0)
        }
    }

    /// Trusts every authority in `trusted`, and pins `pinned` for sync.example.com.
    fn verifier(trusted: &[&Authority], pinned: &[&Authority]) -> PinnedRootVerifier {
        let anchors = trusted.iter().map(|authority| authority.anchor()).collect::<Vec<_>>();
        let pins = pinned
            .iter()
            .map(|authority| spki_digest(&authority.root))
            .collect::<Vec<_>>();
        let mut all = RootCertStore::empty();
        all.roots.extend(anchors.iter().cloned());
        let build = |roots| WebPkiServerVerifier::builder(Arc::new(roots)).build().unwrap();
        PinnedRootVerifier {
            normal: build(all),
            pinned: build(pinned_roots(&anchors, &pins).unwrap()),
            hostname: "sync.example.com".to_string(),
        }
    }

    fn verify(
        verifier: &PinnedRootVerifier,
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
