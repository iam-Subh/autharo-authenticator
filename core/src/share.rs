//! End-to-end encrypted temporary account sharing.
//!
//! The server receives only [`ShareEnvelope`], which contains ciphertext and a
//! random nonce. The 256-bit key belongs in the URL fragment. HTTP clients do
//! not send URL fragments to servers.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::KEY_LEN;
use crate::entry::Payload;

const FORMAT: &str = "authcore-share";
const VERSION: u32 = 1;
const AAD: &[u8] = b"authcore-share/v1";
const SHARE_NONCE_LEN: usize = 12;

#[derive(Debug)]
pub enum ShareError {
    Empty,
    WrongFormat,
    TooNew,
    InvalidKey,
    NotAuthentic,
    Crypto(String),
    Malformed(String),
}

impl core::fmt::Display for ShareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("Select at least one account to share."),
            Self::WrongFormat => f.write_str("This shared account is not in a supported format."),
            Self::TooNew => f.write_str("This shared account was created by a newer app version."),
            Self::InvalidKey => f.write_str("The share key is not valid."),
            Self::NotAuthentic => {
                f.write_str("The shared account is damaged or the link has the wrong key.")
            }
            Self::Crypto(detail) => write!(f, "The shared account could not be secured: {detail}"),
            Self::Malformed(detail) => write!(f, "The shared account could not be read: {detail}"),
        }
    }
}

impl std::error::Error for ShareError {}

#[derive(Debug, Serialize, Deserialize)]
struct ShareEnvelope {
    format: String,
    version: u32,
    algorithm: String,
    nonce: String,
    data: String,
}

pub struct SealedShare {
    /// Opaque JSON for the storage server.
    pub payload: String,
    /// Base64url without padding. Put this value after `#` in the link.
    pub key: Zeroizing<String>,
}

pub fn seal(entries: &[Payload]) -> Result<SealedShare, ShareError> {
    if entries.is_empty() {
        return Err(ShareError::Empty);
    }
    let plaintext = Zeroizing::new(
        serde_json::to_vec(entries).map_err(|error| ShareError::Malformed(error.to_string()))?,
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut_slice()).map_err(|error| ShareError::Crypto(error.to_string()))?;
    let mut nonce = [0u8; SHARE_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| ShareError::Crypto(error.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| ShareError::Crypto("the generated key has the wrong length".to_string()))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            AeadPayload {
                msg: plaintext.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|_| ShareError::Crypto("encryption failed".to_string()))?;
    let envelope = ShareEnvelope {
        format: FORMAT.to_string(),
        version: VERSION,
        algorithm: "AES-256-GCM".to_string(),
        nonce: crate::transport::b64_encode(&nonce),
        data: crate::transport::b64_encode(&ciphertext),
    };
    Ok(SealedShare {
        payload: serde_json::to_string(&envelope)
            .map_err(|error| ShareError::Malformed(error.to_string()))?,
        key: Zeroizing::new(crate::transport::b64_encode(key.as_slice())),
    })
}

pub fn open(payload: &str, key: &str) -> Result<Vec<Payload>, ShareError> {
    let envelope: ShareEnvelope =
        serde_json::from_str(payload).map_err(|_| ShareError::WrongFormat)?;
    if envelope.format != FORMAT {
        return Err(ShareError::WrongFormat);
    }
    if envelope.version > VERSION {
        return Err(ShareError::TooNew);
    }
    if envelope.algorithm != "AES-256-GCM" {
        return Err(ShareError::WrongFormat);
    }
    let mut key =
        Zeroizing::new(crate::transport::b64_decode(key).map_err(|_| ShareError::InvalidKey)?);
    if key.len() != KEY_LEN {
        return Err(ShareError::InvalidKey);
    }
    let nonce = crate::transport::b64_decode(&envelope.nonce)
        .map_err(|_| ShareError::Malformed("the nonce is not valid base64url".to_string()))?;
    let nonce: [u8; SHARE_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| ShareError::Malformed("the nonce has the wrong length".to_string()))?;
    let ciphertext = crate::transport::b64_decode(&envelope.data)
        .map_err(|_| ShareError::Malformed("the data is not valid base64url".to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| ShareError::InvalidKey)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(nonce),
                AeadPayload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| ShareError::NotAuthentic)?,
    );
    key.fill(0);
    serde_json::from_slice(plaintext.as_slice())
        .map_err(|error| ShareError::Malformed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::OtpEntry;
    use crate::otp::Algorithm;
    use crate::secret::SecretString;

    fn entry() -> Payload {
        Payload::Totp(OtpEntry {
            v: 2,
            issuer: Some("Example".to_string()),
            account: "alice@example.com".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP"),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            counter: None,
            folder_id: None,
            icon: None,
            favourite: false,
            order: String::new(),
            created_at: 1,
            note: String::new(),
            tags: Vec::new(),
            trashed_at: None,
            extra: Default::default(),
        })
    }

    #[test]
    fn share_round_trip() {
        let original = vec![entry()];
        let sealed = seal(&original).unwrap();
        assert!(!sealed.payload.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(open(&sealed.payload, &sealed.key).unwrap(), original);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&[entry()]).unwrap();
        let other = seal(&[entry()]).unwrap();
        assert!(matches!(
            open(&sealed.payload, &other.key),
            Err(ShareError::NotAuthentic)
        ));
    }
}
