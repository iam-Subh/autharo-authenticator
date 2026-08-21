//! The vault key and the record cipher (PRD sections 9.2, 9.3).
//!
//! One key protects everything on the device. It is generated once, on first
//! run, and every unlock method wraps its own copy of it — that is the key
//! slot model in section 9.2. This module owns the key itself and the record
//! encryption in section 9.3; the slots that wrap it live in `device_slot`.
//!
//! # Subkeys
//!
//! The vault key is never used directly. HKDF-SHA-256 splits it into labelled
//! subkeys, one per purpose:
//!
//! - `record` encrypts `EntryPayload` (section 9.3).
//! - `sqlcipher` opens the database file (section 12.1).
//!
//! Using one key for both would mean a weakness in either construction reaches
//! the other. The labels are part of the on-disk format: changing one makes
//! every existing vault undecryptable, so they are constants, not parameters.

use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{CipherError, CipherResult, RecordCipher, Sealed};

/// Length of the vault key and of every subkey derived from it.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length: 192 bits, per section 9.3.
pub const NONCE_LEN: usize = 24;

/// HKDF label for the key that encrypts records.
const INFO_RECORD: &[u8] = b"authcore/v1/record";
/// HKDF label for the key that opens the database file.
const INFO_SQLCIPHER: &[u8] = b"authcore/v1/sqlcipher";

/// Something went wrong producing or handling key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The operating system would not supply random bytes. There is no safe
    /// fallback: a predictable vault key is worse than no vault.
    NoRandomness { reason: String },
    /// A key of the wrong length reached a function that needs exactly
    /// [`KEY_LEN`] bytes.
    BadKeyLength { expected: usize, found: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRandomness { reason } => write!(
                f,
                "This device could not supply secure random numbers, so no vault key can \
                 be created: {reason}"
            ),
            Self::BadKeyLength { expected, found } => write!(
                f,
                "A key of {found} bytes was supplied where {expected} are required."
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

/// The 256-bit key that protects everything on this device.
///
/// It is wiped when dropped, redacted in `Debug`, and compared in constant
/// time. It deliberately has no `Serialize`: the only way it reaches disk is
/// wrapped by a slot.
#[derive(Clone)]
pub struct VaultKey(Zeroizing<[u8; KEY_LEN]>);

impl VaultKey {
    /// Generates a new vault key from the operating system's random source.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|error| CryptoError::NoRandomness {
            reason: error.to_string(),
        })?;
        Ok(Self(bytes))
    }

    /// Adopts key material that a slot just unwrapped.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| CryptoError::BadKeyLength {
            expected: KEY_LEN,
            found: bytes.len(),
        })?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// The raw key, for wrapping by a slot. Every call site should be one that
    /// hands the bytes straight to a wrap operation and then drops them.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derives a labelled subkey. See the module documentation for why the
    /// labels are constants.
    fn subkey(&self, info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        // No salt: the input is already a uniformly random 256-bit key, which
        // is the case RFC 5869 says a salt is unnecessary for.
        Hkdf::<Sha256>::new(None, self.0.as_slice())
            .expand(info, out.as_mut_slice())
            .expect("32 bytes is far below the HKDF output limit");
        out
    }

    /// The key that encrypts records (section 9.3).
    pub fn record_key(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.subkey(INFO_RECORD)
    }

    /// The key that opens the database file (section 12.1).
    ///
    /// Returned as lowercase hex because that is the form SQLCipher's
    /// `PRAGMA key` takes for a raw key.
    pub fn sqlcipher_key(&self) -> Zeroizing<String> {
        let raw = self.subkey(INFO_SQLCIPHER);
        let mut hex = String::with_capacity(KEY_LEN * 2);
        for byte in raw.iter() {
            hex.push_str(&format!("{byte:02x}"));
        }
        Zeroizing::new(hex)
    }
}

/// Redacted, for the same reason as `SecretString`: section 9.4 forbids key
/// material at any log level, and a derived `Debug` on a holder would print it.
impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// Constant time, so that comparing keys cannot leak a prefix by timing.
impl PartialEq for VaultKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for VaultKey {}

impl Zeroize for VaultKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Record encryption with XChaCha20-Poly1305 (section 9.3).
///
/// XChaCha20's 192-bit nonce is what makes random nonces safe here. With a
/// 96-bit nonce, random generation would risk a repeat within the lifetime of
/// a vault, and a repeat under one key breaks confidentiality outright.
pub struct XChaChaCipher {
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl XChaChaCipher {
    pub fn new(vault_key: &VaultKey) -> Self {
        Self {
            key: vault_key.record_key(),
        }
    }

    /// The associated data required by section 9.3: "Bind the entry identifier
    /// and the record version into the associated data. This prevents an
    /// attacker from moving a ciphertext to a different entry."
    ///
    /// The identifier is length-prefixed so that no two different pairs can
    /// produce the same bytes.
    fn associated_data(entry_id: &str, record_version: u32) -> Vec<u8> {
        let id = entry_id.as_bytes();
        let mut aad = Vec::with_capacity(4 + id.len() + 4);
        aad.extend_from_slice(&(id.len() as u32).to_be_bytes());
        aad.extend_from_slice(id);
        aad.extend_from_slice(&record_version.to_be_bytes());
        aad
    }
}

impl RecordCipher for XChaChaCipher {
    fn seal(&self, entry_id: &str, record_version: u32, plaintext: &[u8]) -> CipherResult<Sealed> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|error| CipherError::Unavailable {
            reason: format!("no secure random numbers are available: {error}"),
        })?;

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice()).map_err(|_| {
            CipherError::Unavailable {
                reason: "the record key is the wrong length".to_string(),
            }
        })?;
        let aad = Self::associated_data(entry_id, record_version);

        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce_bytes),
                AeadPayload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CipherError::Unavailable {
                reason: "the record could not be encrypted".to_string(),
            })?;

        Ok(Sealed {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    fn open(
        &self,
        entry_id: &str,
        record_version: u32,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> CipherResult<Zeroizing<Vec<u8>>> {
        if nonce.len() != NONCE_LEN {
            // A wrong nonce length is a damaged record, not a wrong key.
            return Err(CipherError::NotAuthentic);
        }

        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CipherError::NotAuthentic)?;

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice()).map_err(|_| {
            CipherError::Unavailable {
                reason: "the record key is the wrong length".to_string(),
            }
        })?;
        let aad = Self::associated_data(entry_id, record_version);

        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            // Poly1305 has already rejected this in constant time. Every
            // failure reports the same thing: a wrong key, a moved ciphertext,
            // and a flipped bit are indistinguishable, and saying which would
            // hand an attacker an oracle.
            .map_err(|_| CipherError::NotAuthentic)?;

        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> VaultKey {
        VaultKey::from_slice(&[7u8; KEY_LEN]).unwrap()
    }

    #[test]
    fn a_generated_key_is_not_all_zeroes_and_differs_each_time() {
        let first = VaultKey::generate().unwrap();
        let second = VaultKey::generate().unwrap();

        assert_ne!(first.expose(), &[0u8; KEY_LEN]);
        assert_ne!(first, second);
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert_eq!(
            VaultKey::from_slice(&[0u8; 16]).unwrap_err(),
            CryptoError::BadKeyLength {
                expected: 32,
                found: 16
            }
        );
    }

    /// The subkeys must differ from each other and from the vault key, or the
    /// separation the module documentation claims does not exist.
    #[test]
    fn subkeys_are_distinct_and_deterministic() {
        let key = key();

        assert_ne!(key.record_key().as_slice(), key.expose().as_slice());
        assert_ne!(
            key.record_key().as_slice(),
            &hex_to_bytes(&key.sqlcipher_key())[..]
        );
        assert_eq!(key.record_key().as_slice(), key.record_key().as_slice());
        assert_eq!(key.sqlcipher_key().as_str(), key.sqlcipher_key().as_str());
    }

    #[test]
    fn the_sqlcipher_key_is_64_hex_characters() {
        let hex = key().sqlcipher_key();
        assert_eq!(hex.len(), KEY_LEN * 2);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn debug_output_hides_the_key() {
        let rendered = format!("{:?}", key());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains('7'));
    }

    #[test]
    fn a_sealed_record_opens_again() {
        let cipher = XChaChaCipher::new(&key());
        let plaintext = br#"{"type":"totp","secret":"GEZDGNBVGY3TQOJQ"}"#;

        let sealed = cipher.seal("entry-1", 1, plaintext).unwrap();
        assert_ne!(sealed.ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(sealed.nonce.len(), NONCE_LEN);

        let opened = cipher
            .open("entry-1", 1, &sealed.ciphertext, &sealed.nonce)
            .unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// Section 9.3's reason for the associated data: a ciphertext lifted onto
    /// another entry must not open.
    #[test]
    fn a_ciphertext_moved_to_another_entry_will_not_open() {
        let cipher = XChaChaCipher::new(&key());
        let sealed = cipher.seal("entry-1", 1, b"secret payload").unwrap();

        assert_eq!(
            cipher
                .open("entry-2", 1, &sealed.ciphertext, &sealed.nonce)
                .unwrap_err(),
            CipherError::NotAuthentic
        );
    }

    #[test]
    fn a_ciphertext_replayed_at_another_record_version_will_not_open() {
        let cipher = XChaChaCipher::new(&key());
        let sealed = cipher.seal("entry-1", 1, b"secret payload").unwrap();

        assert_eq!(
            cipher
                .open("entry-1", 2, &sealed.ciphertext, &sealed.nonce)
                .unwrap_err(),
            CipherError::NotAuthentic
        );
    }

    #[test]
    fn a_modified_ciphertext_will_not_open() {
        let cipher = XChaChaCipher::new(&key());
        let sealed = cipher.seal("entry-1", 1, b"secret payload").unwrap();

        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            cipher
                .open("entry-1", 1, &tampered, &sealed.nonce)
                .unwrap_err(),
            CipherError::NotAuthentic
        );

        let mut wrong_nonce = sealed.nonce.clone();
        wrong_nonce[0] ^= 0x01;
        assert_eq!(
            cipher
                .open("entry-1", 1, &sealed.ciphertext, &wrong_nonce)
                .unwrap_err(),
            CipherError::NotAuthentic
        );
    }

    #[test]
    fn another_vault_key_will_not_open_the_record() {
        let sealed = XChaChaCipher::new(&key())
            .seal("entry-1", 1, b"secret payload")
            .unwrap();

        let other = XChaChaCipher::new(&VaultKey::from_slice(&[9u8; KEY_LEN]).unwrap());
        assert_eq!(
            other
                .open("entry-1", 1, &sealed.ciphertext, &sealed.nonce)
                .unwrap_err(),
            CipherError::NotAuthentic
        );
    }

    /// A repeated nonce under one key breaks XChaCha20 outright, so the nonce
    /// must be fresh on every write even for identical plaintext.
    #[test]
    fn every_write_uses_a_fresh_nonce() {
        let cipher = XChaChaCipher::new(&key());
        let first = cipher.seal("entry-1", 1, b"same").unwrap();
        let second = cipher.seal("entry-1", 1, b"same").unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_wrong_length_nonce_is_refused_rather_than_panicking() {
        let cipher = XChaChaCipher::new(&key());
        let sealed = cipher.seal("entry-1", 1, b"payload").unwrap();

        assert_eq!(
            cipher
                .open("entry-1", 1, &sealed.ciphertext, &[0u8; 12])
                .unwrap_err(),
            CipherError::NotAuthentic
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
