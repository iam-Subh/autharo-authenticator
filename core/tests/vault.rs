//! Tests for the payload/record seam (PRD sections 9.3, 12.2, FR-16 to FR-18).
//!
//! Written in stage S2 against a cipher that did not encrypt, so that they
//! tested the plumbing. Stage S3 pointed them at `XChaChaCipher` and they
//! passed unchanged, which is what writing them at the seam was for.

use authcore::crypto::{VaultKey, XChaChaCipher};
use authcore::entry::{OtpEntry, Payload};
use authcore::otpauth::OtpAuthUri;
use authcore::store::{MetaStore, Store};
use authcore::vault::{CipherError, RECORD_VERSION, RecordCipher, Vault, VaultError};

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const NOW: i64 = 1_755_734_400_000;

fn key() -> VaultKey {
    VaultKey::from_slice(&[42u8; 32]).unwrap()
}

fn vault() -> Vault<XChaChaCipher> {
    Vault::open(
        Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap(),
        XChaChaCipher::new(&key()),
    )
    .unwrap()
}

fn entry(issuer: &str, account: &str, secret: &str) -> Payload {
    let uri = OtpAuthUri::parse(&format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"
    ))
    .unwrap();
    OtpEntry::from_uri(&uri, NOW)
}

#[test]
fn an_added_entry_reads_back_intact() {
    let mut vault = vault();
    let payload = entry("GitHub", "rupsa", SECRET);

    let id = vault.add(&payload, NOW).unwrap();

    assert_eq!(vault.get(&id).unwrap().payload, payload);
    let (entries, unreadable) = vault.list().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(unreadable, 0);
}

/// FR-17: the issuer and the account name may be edited; the secret may not.
/// The vault does not enforce the second half — the edit screen does — but an
/// update must not disturb anything else.
#[test]
fn an_update_replaces_the_payload_in_place() {
    let mut vault = vault();
    let id = vault.add(&entry("Old", "rupsa", SECRET), NOW).unwrap();
    let before = vault.get(&id).unwrap().hlc;

    vault
        .update(&id, &entry("New", "rupsa", SECRET), NOW + 1000)
        .unwrap();

    let after = vault.get(&id).unwrap();
    assert_eq!(
        after.payload.as_otp().unwrap().issuer.as_deref(),
        Some("New")
    );
    assert!(after.hlc > before, "an edit must advance the timestamp");
    assert_eq!(vault.list().unwrap().0.len(), 1, "still one entry");
}

/// FR-18: a delete hides the entry but leaves a tombstone for the other
/// devices, so the record count and the entry count differ afterwards.
#[test]
fn a_delete_hides_the_entry_and_leaves_a_tombstone() {
    let mut vault = vault();
    let id = vault.add(&entry("GitHub", "rupsa", SECRET), NOW).unwrap();

    vault.delete(&id, NOW + 1000).unwrap();

    assert!(vault.list().unwrap().0.is_empty());
    assert!(matches!(
        vault.get(&id).unwrap_err(),
        VaultError::NotFound { .. }
    ));
    assert_eq!(
        vault.store().list(true).unwrap().len(),
        1,
        "the tombstone must survive for the sync"
    );
}

#[test]
fn deleting_an_unknown_entry_says_so() {
    let mut vault = vault();
    assert!(matches!(
        vault.delete("no-such-entry", NOW).unwrap_err(),
        VaultError::NotFound { .. }
    ));
}

/// FR-16: a duplicate secret is found by comparing decrypted payloads. Two
/// encryptions of the same secret differ, so a ciphertext comparison would
/// never find it — and the server must not be able to find it at all.
#[test]
fn a_duplicate_secret_is_found_by_its_plaintext() {
    let mut vault = vault();
    let id = vault.add(&entry("GitHub", "rupsa", SECRET), NOW).unwrap();
    vault
        .add(&entry("GitLab", "rupsa", "MZXW6YTBOI"), NOW + 1)
        .unwrap();

    assert_eq!(vault.find_by_secret(SECRET).unwrap(), Some(id));
    assert!(vault.find_by_secret("MZXW6YTBOI").unwrap().is_some());
    assert_eq!(vault.find_by_secret("GEZDGNBVGY3TQOJQ").unwrap(), None);
}

/// A restart must not reissue a timestamp this device already used, or the
/// section 10.4 conflict rule would resolve against a stale write.
#[test]
fn the_clock_resumes_above_the_highest_stored_timestamp() {
    let store = Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap();
    let mut vault = Vault::open(store, XChaChaCipher::new(&key())).unwrap();
    let id = vault.add(&entry("GitHub", "rupsa", SECRET), NOW).unwrap();
    let before = vault.get(&id).unwrap().hlc;

    // Reopen over the same store, then write with an earlier wall clock.
    let store = vault.into_store();
    let mut reopened = Vault::open(store, XChaChaCipher::new(&key())).unwrap();
    reopened
        .update(&id, &entry("GitHub", "other", SECRET), NOW - 60_000)
        .unwrap();

    assert!(
        reopened.get(&id).unwrap().hlc > before,
        "a reopened vault must not issue a timestamp below its own last write"
    );
}

/// One damaged record must not hide every other code the user needs.
#[test]
fn an_unreadable_record_is_skipped_rather_than_failing_the_list() {
    /// The real cipher, with one entry made to fail. Delegating rather than
    /// substituting matters: the records under test were sealed by
    /// `XChaChaCipher`, so a stub that returned plaintext would report every
    /// record unreadable and the test would pass for the wrong reason.
    struct FailsOneEntry {
        inner: XChaChaCipher,
        broken_id: String,
    }

    impl RecordCipher for FailsOneEntry {
        fn seal(
            &self,
            id: &str,
            version: u32,
            plaintext: &[u8],
        ) -> Result<authcore::vault::Sealed, CipherError> {
            self.inner.seal(id, version, plaintext)
        }

        fn open(
            &self,
            id: &str,
            version: u32,
            ciphertext: &[u8],
            nonce: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, CipherError> {
            if id == self.broken_id {
                return Err(CipherError::NotAuthentic);
            }
            self.inner.open(id, version, ciphertext, nonce)
        }
    }

    let mut vault = vault();
    let broken = vault.add(&entry("Broken", "rupsa", SECRET), NOW).unwrap();
    vault
        .add(&entry("Fine", "rupsa", "MZXW6YTBOI"), NOW + 1)
        .unwrap();

    let vault = Vault::open(
        vault.into_store(),
        FailsOneEntry {
            inner: XChaChaCipher::new(&key()),
            broken_id: broken,
        },
    )
    .unwrap();
    let (entries, unreadable) = vault.list().unwrap();

    assert_eq!(entries.len(), 1, "the readable entry still appears");
    assert_eq!(unreadable, 1, "and the caller learns one was skipped");
}

/// Section 9.3 requires the entry identifier and the record version in the
/// associated data. `NullCipher` ignores them, so this pins the contract at the
/// trait rather than at the implementation — S3 must honour it.
#[test]
fn the_cipher_receives_the_associated_data_section_9_3_requires() {
    use std::cell::RefCell;

    struct Recording(RefCell<Vec<(String, u32)>>);

    impl RecordCipher for Recording {
        fn seal(
            &self,
            id: &str,
            version: u32,
            plaintext: &[u8],
        ) -> Result<authcore::vault::Sealed, CipherError> {
            self.0.borrow_mut().push((id.to_string(), version));
            Ok(authcore::vault::Sealed {
                ciphertext: plaintext.to_vec(),
                nonce: Vec::new(),
            })
        }

        fn open(
            &self,
            id: &str,
            version: u32,
            ciphertext: &[u8],
            _nonce: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, CipherError> {
            self.0.borrow_mut().push((id.to_string(), version));
            Ok(zeroize::Zeroizing::new(ciphertext.to_vec()))
        }
    }

    let mut vault = Vault::open(
        Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap(),
        Recording(RefCell::new(Vec::new())),
    )
    .unwrap();

    let id = vault.add(&entry("GitHub", "rupsa", SECRET), NOW).unwrap();
    vault.get(&id).unwrap();

    let seen = vault.cipher().0.borrow().clone();
    assert_eq!(seen.len(), 2, "one seal and one open");
    for (seen_id, version) in seen {
        assert_eq!(seen_id, id, "the entry identifier must be bound in");
        assert_eq!(version, RECORD_VERSION);
    }
}

/// The seam now really encrypts. Stage S2's version of this file could not
/// make this assertion at all.
#[test]
fn the_stored_record_is_not_readable() {
    let mut vault = vault();
    let id = vault.add(&entry("GitHub", "rupsa", SECRET), NOW).unwrap();

    let stored = vault.store().get(&id).unwrap().unwrap();
    let text = String::from_utf8_lossy(&stored.ciphertext);

    assert!(!text.contains(SECRET), "the secret is readable on disk");
    assert!(!text.contains("GitHub"), "the issuer is readable on disk");
    assert!(
        !text.contains("rupsa"),
        "the account name is readable on disk"
    );
    assert_eq!(
        stored.nonce.len(),
        24,
        "section 9.3 requires a 192-bit nonce"
    );
}

/// A vault opened with a different key must refuse the records rather than
/// return nonsense.
#[test]
fn another_key_cannot_read_this_vault() {
    let mut vault = vault();
    vault.add(&entry("GitHub", "rupsa", SECRET), NOW).unwrap();

    let other = VaultKey::from_slice(&[7u8; 32]).unwrap();
    let wrong = Vault::open(vault.into_store(), XChaChaCipher::new(&other)).unwrap();

    let (entries, unreadable) = wrong.list().unwrap();
    assert!(
        entries.is_empty(),
        "no entry should decrypt under a wrong key"
    );
    assert_eq!(
        unreadable, 1,
        "and the caller must learn the record was skipped"
    );
}
