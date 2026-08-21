//! End-to-end test of the stage S1 pipeline.
//!
//! A scanned QR code becomes a URI, the URI becomes a payload, the payload is
//! stored, and the stored record generates the code the user reads. This is
//! the whole of S1 in one path.
//!
//! Encryption arrives in stage S3. Until then the payload bytes go into the
//! `ciphertext` column as they are, which is why this test asserts that the
//! stored bytes are still readable — the assertion inverts once S3 lands, and
//! that inversion is the proof S3 did its job.

use authcore::entry::{OtpEntry, Payload};
use authcore::hlc::HlcClock;
use authcore::otp::totp_at;
use authcore::otpauth::OtpAuthUri;
use authcore::store::{Record, Store, new_entry_id};

/// The RFC 6238 SHA-1 seed, so the generated code can be checked against the
/// published vector rather than against itself.
const SCANNED_QR: &str = "otpauth://totp/GitHub:rupsa%40example.com\
    ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8&period=30";

#[test]
fn a_scanned_code_is_stored_and_read_back_as_a_working_entry() {
    let mut store = Store::open_in_memory().unwrap();
    let device = store.device_id().unwrap();
    let mut clock = HlcClock::new(device);

    // FR-10: parse what the camera read.
    let uri = OtpAuthUri::parse(SCANNED_QR).unwrap();
    assert_eq!(uri.issuer.as_deref(), Some("GitHub"));

    // Section 12.2: build the payload that the vault key will encrypt.
    let payload = OtpEntry::from_uri(&uri, 1_755_734_400_000);
    let bytes = payload.to_json().unwrap();

    // Section 12.1: store it. OFF-02 queues it for the server at the same time.
    let id = new_entry_id();
    let record = Record {
        id: id.clone(),
        ciphertext: bytes.to_vec(),
        nonce: vec![0u8; 24],
        hlc: clock.tick(1_755_734_400_000),
        deleted: false,
        server_seq: None,
        updated_at: 1_755_734_400_000,
    };
    store.write_local(&record, None).unwrap();
    assert_eq!(store.outbox().unwrap().len(), 1);

    // Read it back and generate a code from what was stored.
    let stored = store.get(&id).unwrap().unwrap();
    let restored = Payload::from_json(&stored.ciphertext).unwrap();
    assert_eq!(restored, payload);

    let entry = restored.as_otp().unwrap();
    let secret = authcore::base32::decode(&entry.secret).unwrap();
    let code = totp_at(&secret, 59, entry.period, entry.digits, entry.algorithm).unwrap();

    // RFC 6238 Appendix B, T=59, SHA-1, 8 digits.
    assert_eq!(code, "94287082");
}

/// The HLC written by the store must be the one the clock issued, and it must
/// carry this device's identifier so the section 10.4 tiebreak can work.
#[test]
fn the_stored_timestamp_carries_this_device() {
    let mut store = Store::open_in_memory().unwrap();
    let device = store.device_id().unwrap();
    let mut clock = HlcClock::new(device);

    let id = new_entry_id();
    let hlc = clock.tick(1_755_734_400_000);
    store
        .write_local(
            &Record {
                id: id.clone(),
                ciphertext: b"payload".to_vec(),
                nonce: vec![0u8; 24],
                hlc,
                deleted: false,
                server_seq: None,
                updated_at: 1_755_734_400_000,
            },
            None,
        )
        .unwrap();

    let stored = store.get(&id).unwrap().unwrap();
    assert_eq!(stored.hlc, hlc);
    assert_eq!(stored.hlc.device, device);
}

/// Stage S3 has not encrypted anything yet. This test states that plainly so
/// the gap cannot be mistaken for a finished feature.
#[test]
fn s3_has_not_encrypted_the_payload_yet() {
    let uri = OtpAuthUri::parse(SCANNED_QR).unwrap();
    let bytes = OtpEntry::from_uri(&uri, 0).to_json().unwrap();

    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        text.contains("GEZDGNBVGY3TQOJQ"),
        "the payload is still plaintext at stage S1; S3 must invert this test"
    );
}

/// Section 9.4 forbids a secret reaching any log level. Both types that hold
/// one derive `Debug`, so this pins the redaction against a future change that
/// swaps `SecretString` back for a plain `String`.
#[test]
fn debug_output_never_carries_the_secret() {
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    let uri = OtpAuthUri::parse(SCANNED_QR).unwrap();
    let payload = OtpEntry::from_uri(&uri, 0);

    for rendered in [format!("{uri:?}"), format!("{payload:?}")] {
        assert!(!rendered.contains(SECRET), "Debug leaked the secret");
        assert!(rendered.contains("redacted"));
    }

    // The account name is not a secret and must still be visible for support.
    assert!(format!("{uri:?}").contains("rupsa@example.com"));
}
