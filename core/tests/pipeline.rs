//! End-to-end test of the stage S1 pipeline.
//!
//! A scanned QR code becomes a URI, the URI becomes a payload, the payload is
//! stored, and the stored record generates the code the user reads. This is
//! the whole of S1 in one path.
//!
//! Stage S2 wrote the payload bytes into the `ciphertext` column unchanged,
//! and this file asserted they were still readable so the gap could not be
//! mistaken for a finished feature. Stage S3 inverted that assertion: the same
//! test now fails if a payload can be read off disk.

use authcore::crypto::{VaultKey, XChaChaCipher};
use authcore::entry::{OtpEntry, Payload};
use authcore::hlc::HlcClock;
use authcore::otp::totp_at;
use authcore::otpauth::OtpAuthUri;
use authcore::store::{MetaStore, Record, Store, new_entry_id};
use authcore::vault::Vault;

/// The RFC 6238 SHA-1 seed, so the generated code can be checked against the
/// published vector rather than against itself.
const SCANNED_QR: &str = "otpauth://totp/GitHub:rupsa%40example.com\
    ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8&period=30";

#[test]
fn a_scanned_code_is_stored_and_read_back_as_a_working_entry() {
    let mut store = Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap();
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
    let mut store = Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap();
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

/// The inverted assertion.
///
/// In stage S2 this test asserted the opposite — that the secret was readable
/// in the stored bytes — because nothing encrypted it, and a test that quietly
/// passed either way would have hidden that. This is the same test with the
/// expectation turned around, which is the evidence S3 did its job.
#[test]
fn a_stored_payload_cannot_be_read_off_disk() {
    let key = VaultKey::from_slice(&[3u8; 32]).unwrap();
    let mut vault = Vault::open(
        Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap(),
        XChaChaCipher::new(&key),
    )
    .unwrap();

    let uri = OtpAuthUri::parse(SCANNED_QR).unwrap();
    let payload = OtpEntry::from_uri(&uri, 1_755_734_400_000);
    let id = vault.add(&payload, 1_755_734_400_000).unwrap();

    let stored = vault.store().get(&id).unwrap().unwrap();
    let bytes = &stored.ciphertext;
    let text = String::from_utf8_lossy(bytes);

    for readable in [
        "GEZDGNBVGY3TQOJQ",  // the secret
        "GitHub",            // the issuer
        "rupsa@example.com", // the account name
        "totp",              // even the entry type
        "secret",            // or a JSON field name
    ] {
        assert!(
            !text.contains(readable),
            "{readable:?} is readable in the stored record"
        );
    }

    // Not merely unreadable as text: the plaintext must not appear verbatim
    // anywhere in the ciphertext, and the record must still open with the key.
    let plaintext = payload.to_json().unwrap();
    assert!(
        !bytes.windows(plaintext.len()).any(|w| w == &plaintext[..]),
        "the plaintext appears verbatim inside the ciphertext"
    );
    assert_eq!(vault.get(&id).unwrap().payload, payload);
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
