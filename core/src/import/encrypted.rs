//! Decrypting Aegis, 2FAS, Ente, and Proton Authenticator exports.
//!
//! # These are other people's formats, implemented exactly
//!
//! Nothing here is a design decision. Aegis derives a key with scrypt and seals
//! with AES-256-GCM; 2FAS derives with PBKDF2-HMAC-SHA256 and seals with the
//! same. Both are fixed by what those applications shipped, and the only
//! correct implementation is the one that matches.
//!
//! Section 12.1 rule 2 applies with equal force in this direction: read the
//! parameters out of the file rather than hard-coding them. Aegis stores its
//! scrypt cost in the header precisely so that raising it later does not orphan
//! existing exports, and a reader that assumed today's values would fail on
//! every file written after they changed — with a "wrong password" message, on
//! a correct password.
//!
//! # A wrong password and a damaged file are the same answer
//!
//! AEAD gives one signal: the tag did not verify. That happens for a wrong
//! password, a truncated download and a corrupted card alike, and this module
//! does not pretend to tell them apart. The message says the likely cause first
//! and mentions the others, because guessing confidently would send someone
//! hunting for a backup that was never broken.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::import::{Report, aegis, ente_secretstream, generic, twofas};

use core::fmt;

/// Why an encrypted export could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    /// The tag did not verify. Usually the password; possibly the file.
    WrongPasswordOrDamaged,
    /// The file is not shaped the way the format requires.
    Malformed { detail: String },
    /// The parameters are outside what this app will spend.
    Unreasonable { detail: String },
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPasswordOrDamaged => f.write_str(
                "That password did not open the file. Check it and try again — \
                 if the password is definitely right, the file itself may be \
                 damaged or incomplete.",
            ),
            Self::Malformed { detail } => write!(f, "The file could not be read: {detail}"),
            Self::Unreasonable { detail } => write!(f, "This file cannot be opened here: {detail}"),
        }
    }
}

impl std::error::Error for DecryptError {}

type Result<T> = core::result::Result<T, DecryptError>;

/// The most work this app will do to open somebody else's file.
///
/// Aegis defaults to n = 32768, which is about 32 MiB and a second on a phone.
/// The cost is read from the file, so a crafted header could name a value that
/// exhausts memory and takes the application down — from a file, which is
/// attacker-supplied input. This is the ceiling on that, set well above every
/// value Aegis actually ships.
const MAX_SCRYPT_LOG_N: u8 = 20;
const MAX_SCRYPT_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
// Ente's current "sensitive" export profile uses these exact limits. Higher
// values from an imported file can exhaust a mobile process, so do not accept
// more work than the official profile requires.
const MAX_ARGON2_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARGON2_OPERATIONS: u64 = 16;

// ---------------------------------------------------------------------------
// Aegis
// ---------------------------------------------------------------------------

/// Opens an encrypted Aegis export.
///
/// The vault key is wrapped once per slot, exactly like this project's own key
/// slots in section 9.2 — so a vault with a password and a biometric slot has
/// two copies, and the password opens one of them. Every password slot is
/// tried, because the file does not say which one the password belongs to.
pub fn aegis(text: &str, password: &str) -> Result<Report> {
    let root: Value = serde_json::from_str(text).map_err(|_| DecryptError::Malformed {
        detail: "it is not valid JSON".to_string(),
    })?;

    let slots = root
        .pointer("/header/slots")
        .and_then(Value::as_array)
        .ok_or(DecryptError::Malformed {
            detail: "it has no key slots, so it is not an encrypted export".to_string(),
        })?;

    let params = root
        .pointer("/header/params")
        .ok_or(DecryptError::Malformed {
            detail: "it has no encryption parameters".to_string(),
        })?;

    let database = root
        .get("db")
        .and_then(Value::as_str)
        .ok_or(DecryptError::Malformed {
            detail: "it holds no encrypted database".to_string(),
        })?;

    // Type 1 is the password slot. Others are biometric and hold a key this
    // application has no way to reach.
    //
    // Every password slot is tried, because the file does not say which one the
    // password belongs to — so a slot failing is ordinary and must not stop the
    // loop.
    let mut master: Option<Zeroizing<Vec<u8>>> = None;
    let mut structural: Option<DecryptError> = None;

    for slot in slots {
        if slot.get("type").and_then(Value::as_u64) != Some(1) {
            continue;
        }
        match open_aegis_slot(slot, password) {
            Ok(key) => {
                master = Some(key);
                break;
            }
            // The tag did not verify: this slot is not the one, or the password
            // is wrong. Ordinary, and the next slot may still open.
            Err(DecryptError::WrongPasswordOrDamaged) => {}
            // The slot itself is unreadable or asks for more than this app will
            // spend. Kept, because reporting it as a wrong password would send
            // the user to check something that is not the problem — the exact
            // misdirection this module exists to avoid.
            Err(other) => structural = structural.or(Some(other)),
        }
    }

    let master = match master {
        Some(key) => key,
        None => return Err(structural.unwrap_or(DecryptError::WrongPasswordOrDamaged)),
    };

    let nonce = hex(params.get("nonce"))?;
    let tag = hex(params.get("tag"))?;
    let ciphertext = base64_standard(database).ok_or(DecryptError::Malformed {
        detail: "the database is not valid base64".to_string(),
    })?;

    let plaintext = open_aes_gcm(&master, &nonce, &ciphertext, &tag)?;
    let text = String::from_utf8(plaintext.to_vec()).map_err(|_| DecryptError::Malformed {
        detail: "the decrypted database is not text".to_string(),
    })?;

    // Decrypted, so it is now the plain form, and the plain reader owns every
    // decision about entries. One code path for both variants means a fix to
    // either applies to both.
    let value: Value = serde_json::from_str(&text).map_err(|_| DecryptError::Malformed {
        detail: "the decrypted database is not valid JSON".to_string(),
    })?;

    let entries =
        value
            .get("entries")
            .and_then(Value::as_array)
            .ok_or(DecryptError::Malformed {
                detail: "the decrypted database holds no entries".to_string(),
            })?;

    let mut report = Report::default();
    for entry in entries {
        aegis::read_entry(entry, &mut report);
    }
    Ok(report)
}

fn open_aegis_slot(slot: &Value, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let salt = hex(slot.get("salt"))?;
    let key = hex(slot.get("key"))?;
    let nonce = hex(slot.pointer("/key_params/nonce"))?;
    let tag = hex(slot.pointer("/key_params/tag"))?;

    // Read from the file, never assumed. Aegis stores its cost so that raising
    // it does not orphan existing exports; a reader that hard-coded today's
    // values would fail on every newer file with a "wrong password" message.
    let n = slot.get("n").and_then(Value::as_u64).unwrap_or(32768);
    let r = slot.get("r").and_then(Value::as_u64).unwrap_or(8) as u32;
    let p = slot.get("p").and_then(Value::as_u64).unwrap_or(1) as u32;

    let derived = scrypt_key(password, &salt, n, r, p)?;
    open_aes_gcm(&derived, &nonce, &key, &tag)
}

// ---------------------------------------------------------------------------
// 2FAS
// ---------------------------------------------------------------------------

/// PBKDF2 rounds, as 2FAS ships them.
const TWOFAS_ROUNDS: u32 = 10_000;

/// Opens a password-protected `.2fas` backup.
///
/// `servicesEncrypted` is three base64 fields joined by colons:
/// `ciphertext-with-tag : salt : nonce`.
pub fn twofas(text: &str, password: &str) -> Result<Report> {
    let root: Value = serde_json::from_str(text).map_err(|_| DecryptError::Malformed {
        detail: "it is not valid JSON".to_string(),
    })?;

    let blob = root
        .get("servicesEncrypted")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(DecryptError::Malformed {
            detail: "it is not a password-protected backup".to_string(),
        })?;

    let fields: Vec<&str> = blob.split(':').collect();
    if fields.len() != 3 {
        return Err(DecryptError::Malformed {
            detail: format!("the encrypted block has {} parts, not three", fields.len()),
        });
    }

    let sealed = base64_standard(fields[0]).ok_or(DecryptError::Malformed {
        detail: "the encrypted data is not valid base64".to_string(),
    })?;
    let salt = base64_standard(fields[1]).ok_or(DecryptError::Malformed {
        detail: "the salt is not valid base64".to_string(),
    })?;
    let nonce = base64_standard(fields[2]).ok_or(DecryptError::Malformed {
        detail: "the nonce is not valid base64".to_string(),
    })?;

    let mut derived = Zeroizing::new(vec![0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, TWOFAS_ROUNDS, &mut derived);

    // 2FAS appends the tag to the ciphertext, which is what `aes-gcm` expects,
    // so there is no separate tag to reunite here.
    let cipher = Aes256Gcm::new(&key_of(&derived)?);
    let plaintext = cipher
        .decrypt(
            &nonce_of(&nonce)?,
            AeadPayload {
                msg: &sealed,
                aad: &[],
            },
        )
        .map_err(|_| DecryptError::WrongPasswordOrDamaged)?;
    let plaintext = Zeroizing::new(plaintext);

    let text = String::from_utf8(plaintext.to_vec()).map_err(|_| DecryptError::Malformed {
        detail: "the decrypted backup is not text".to_string(),
    })?;
    let services: Value = serde_json::from_str(&text).map_err(|_| DecryptError::Malformed {
        detail: "the decrypted backup is not valid JSON".to_string(),
    })?;

    let list = services.as_array().ok_or(DecryptError::Malformed {
        detail: "the decrypted backup is not a list of services".to_string(),
    })?;

    let mut report = Report::default();
    for service in list {
        twofas::read_service(service, &mut report);
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Proton Authenticator
// ---------------------------------------------------------------------------

const PROTON_ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const PROTON_ARGON2_OPERATIONS: u32 = 2;
const PROTON_EXPORT_AAD: &[u8] = b"proton.authenticator.export.v1";

/// Opens a version-one Proton Authenticator password export.
///
/// Proton fixes the Argon2id parameters in the format. The AES-GCM nonce is
/// the first 12 bytes of `content`, followed by ciphertext and its 16-byte tag.
pub fn proton(text: &str, password: &str) -> Result<Report> {
    let root: Value = serde_json::from_str(text).map_err(|_| DecryptError::Malformed {
        detail: "it is not valid JSON".to_string(),
    })?;
    require_version_one(&root, "Proton Authenticator")?;

    let salt = base64_field(&root, "salt", "the Proton salt")?;
    if salt.len() != 16 {
        return Err(DecryptError::Malformed {
            detail: format!("the Proton salt is {} bytes, not 16", salt.len()),
        });
    }
    let sealed = base64_field(&root, "content", "the Proton encrypted data")?;
    if sealed.len() < 12 + 16 {
        return Err(DecryptError::Malformed {
            detail: "the Proton encrypted data is too short".to_string(),
        });
    }

    let params = argon2::Params::new(
        PROTON_ARGON2_MEMORY_KIB,
        PROTON_ARGON2_OPERATIONS,
        1,
        Some(32),
    )
    .map_err(|_| DecryptError::Malformed {
        detail: "the Proton key parameters are invalid".to_string(),
    })?;
    let mut derived = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, derived.as_mut())
        .map_err(|_| DecryptError::Malformed {
            detail: "the Proton password key could not be derived".to_string(),
        })?;

    let (nonce, ciphertext) = sealed.split_at(12);
    let cipher = Aes256Gcm::new(&key_of(derived.as_ref())?);
    let plaintext = cipher
        .decrypt(
            &nonce_of(nonce)?,
            AeadPayload {
                msg: ciphertext,
                aad: PROTON_EXPORT_AAD,
            },
        )
        .map_err(|_| DecryptError::WrongPasswordOrDamaged)?;
    let plaintext = Zeroizing::new(plaintext);
    let plain_root: Value =
        serde_json::from_slice(plaintext.as_ref()).map_err(|_| DecryptError::Malformed {
            detail: "the decrypted Proton data is not valid JSON".to_string(),
        })?;
    Ok(generic::proton(&plain_root))
}

// ---------------------------------------------------------------------------
// Ente Authenticator
// ---------------------------------------------------------------------------

/// Opens a version-one Ente Authenticator password export.
///
/// Ente records the Argon2id memory and operation costs in the file. Values
/// above the limits are refused before key derivation to prevent file-based
/// memory and CPU exhaustion.
pub fn ente(text: &str, password: &str) -> Result<Report> {
    let root: Value = serde_json::from_str(text).map_err(|_| DecryptError::Malformed {
        detail: "it is not valid JSON".to_string(),
    })?;
    require_version_one(&root, "Ente")?;

    let kdf = root.get("kdfParams").ok_or(DecryptError::Malformed {
        detail: "the Ente key parameters are missing".to_string(),
    })?;
    let memory_bytes =
        kdf.get("memLimit")
            .and_then(Value::as_u64)
            .ok_or(DecryptError::Malformed {
                detail: "the Ente memory limit is missing or invalid".to_string(),
            })?;
    let operations =
        kdf.get("opsLimit")
            .and_then(Value::as_u64)
            .ok_or(DecryptError::Malformed {
                detail: "the Ente operation limit is missing or invalid".to_string(),
            })?;
    if memory_bytes < 1024 || operations < 1 {
        return Err(DecryptError::Malformed {
            detail: "the Ente key parameters are below the format minimum".to_string(),
        });
    }
    if memory_bytes > MAX_ARGON2_MEMORY_BYTES || operations > MAX_ARGON2_OPERATIONS {
        return Err(DecryptError::Unreasonable {
            detail: format!(
                "the Ente key derivation asks for {} MiB of memory and {operations} operations",
                memory_bytes / (1024 * 1024)
            ),
        });
    }

    let salt_text = kdf
        .get("salt")
        .and_then(Value::as_str)
        .ok_or(DecryptError::Malformed {
            detail: "the Ente salt is missing".to_string(),
        })?;
    let salt = base64_standard(salt_text).ok_or(DecryptError::Malformed {
        detail: "the Ente salt is not valid base64".to_string(),
    })?;
    if salt.len() != 16 {
        return Err(DecryptError::Malformed {
            detail: format!("the Ente salt is {} bytes, not 16", salt.len()),
        });
    }

    let memory_kib =
        u32::try_from(memory_bytes / 1024).map_err(|_| DecryptError::Unreasonable {
            detail: "the Ente memory limit is too large".to_string(),
        })?;
    let operations = u32::try_from(operations).map_err(|_| DecryptError::Unreasonable {
        detail: "the Ente operation limit is too large".to_string(),
    })?;
    let params = argon2::Params::new(memory_kib, operations, 1, Some(32)).map_err(|_| {
        DecryptError::Malformed {
            detail: "the Ente key parameters are invalid".to_string(),
        }
    })?;
    let mut derived = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, derived.as_mut())
        .map_err(|_| DecryptError::Malformed {
            detail: "the Ente password key could not be derived".to_string(),
        })?;

    let encrypted = base64_field(&root, "encryptedData", "the Ente encrypted data")?;
    let header = base64_field(&root, "encryptionNonce", "the Ente encryption nonce")?;
    let plaintext = ente_secretstream::open(&encrypted, &derived, &header)?;
    let plaintext =
        core::str::from_utf8(plaintext.as_ref()).map_err(|_| DecryptError::Malformed {
            detail: "the decrypted Ente data is not text".to_string(),
        })?;
    Ok(generic::uri_lines(plaintext))
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

fn require_version_one(root: &Value, source: &str) -> Result<()> {
    match root.get("version").and_then(Value::as_u64) {
        Some(1) => Ok(()),
        Some(version) => Err(DecryptError::Malformed {
            detail: format!("{source} encrypted export version {version} is not supported"),
        }),
        None => Err(DecryptError::Malformed {
            detail: format!("the {source} export version is missing"),
        }),
    }
}

fn base64_field(root: &Value, field: &str, label: &str) -> Result<Vec<u8>> {
    let encoded = root
        .get(field)
        .and_then(Value::as_str)
        .ok_or(DecryptError::Malformed {
            detail: format!("{label} is missing"),
        })?;
    base64_standard(encoded).ok_or(DecryptError::Malformed {
        detail: format!("{label} is not valid base64"),
    })
}

fn scrypt_key(password: &str, salt: &[u8], n: u64, r: u32, p: u32) -> Result<Zeroizing<Vec<u8>>> {
    if !n.is_power_of_two() || n < 2 {
        return Err(DecryptError::Malformed {
            detail: format!("its scrypt cost ({n}) is not a power of two"),
        });
    }
    let log_n = n.trailing_zeros() as u8;

    // A crafted header can name a cost that exhausts memory and takes the
    // application down. This is a file, which is attacker-supplied input, and a
    // refusal with a reason is better than being killed by the system.
    let memory = 128u64.saturating_mul(u64::from(r)).saturating_mul(n);
    if log_n > MAX_SCRYPT_LOG_N || memory > MAX_SCRYPT_MEMORY_BYTES {
        return Err(DecryptError::Unreasonable {
            detail: format!(
                "it asks for about {} MiB of memory to open, which is more than \
                 this app will use",
                memory / (1024 * 1024)
            ),
        });
    }

    let params = scrypt::Params::new(log_n, r, p).map_err(|_| DecryptError::Malformed {
        detail: "its scrypt parameters are not valid".to_string(),
    })?;

    let mut derived = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut derived).map_err(|_| {
        DecryptError::Malformed {
            detail: "the key could not be derived".to_string(),
        }
    })?;
    Ok(derived)
}

fn open_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // Aegis stores the tag apart from the ciphertext; `aes-gcm` wants them
    // joined. Rejoined here rather than in the caller so both slot and database
    // take the same path.
    let mut sealed = Vec::with_capacity(ciphertext.len() + tag.len());
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(&key_of(key)?);
    let plaintext = cipher
        .decrypt(
            &nonce_of(nonce)?,
            AeadPayload {
                msg: &sealed,
                aad: &[],
            },
        )
        // One signal for a wrong password, a truncated file and a corrupted
        // card. Not distinguished, because AEAD cannot distinguish them and
        // guessing would send someone hunting for a fault that is not there.
        .map_err(|_| DecryptError::WrongPasswordOrDamaged)?;

    Ok(Zeroizing::new(plaintext))
}

/// A twelve-byte nonce, or a refusal.
///
/// `TryFrom` rather than the deprecated `from_slice`, which panics on a wrong
/// length — and the length here comes out of a file, so a panic would be a
/// crash on malformed input rather than a message.
fn nonce_of(bytes: &[u8]) -> Result<Nonce<aes_gcm::aead::consts::U12>> {
    Nonce::try_from(bytes).map_err(|_| DecryptError::Malformed {
        detail: format!("a nonce is {} bytes, not twelve", bytes.len()),
    })
}

/// A 256-bit key, or a refusal. Same reasoning as [`nonce_of`].
fn key_of(bytes: &[u8]) -> Result<Key<Aes256Gcm>> {
    Key::<Aes256Gcm>::try_from(bytes).map_err(|_| DecryptError::Malformed {
        detail: "the key is the wrong length".to_string(),
    })
}

fn hex(value: Option<&Value>) -> Result<Vec<u8>> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(DecryptError::Malformed {
            detail: "a required field is missing".to_string(),
        })?;

    if text.len() % 2 != 0 {
        return Err(DecryptError::Malformed {
            detail: "a hexadecimal field has an odd length".to_string(),
        });
    }

    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| DecryptError::Malformed {
                detail: "a field is not valid hexadecimal".to_string(),
            })
        })
        .collect()
}

/// Standard base64, padded or not.
fn base64_standard(text: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    /// Builds an encrypted Aegis export the way Aegis does, so the reader is
    /// tested against the format rather than against itself.
    ///
    /// Written with the same primitives it will be read with, which is a real
    /// limitation: it proves this module round-trips, not that it matches
    /// Aegis. What makes that acceptable is that every parameter is fixed by
    /// the format — scrypt with the header's own n, r and p, AES-256-GCM with a
    /// 12-byte nonce and a detached 16-byte tag — and each is asserted
    /// separately below. A real exported file is the test that would close the
    /// gap, and needs Aegis to produce one.
    fn aegis_file(password: &str, entries: &str, n: u64) -> String {
        let salt = [0x11u8; 32];
        let slot_nonce = [0x22u8; 12];
        let db_nonce = [0x33u8; 12];
        let master = [0x44u8; 32];

        let derived = scrypt_key(password, &salt, n, 8, 1).unwrap();
        let slot_cipher = Aes256Gcm::new(&key_of(&derived).unwrap());
        let sealed_master = slot_cipher
            .encrypt(&nonce_of(&slot_nonce).unwrap(), master.as_slice())
            .unwrap();
        let (slot_key, slot_tag) = sealed_master.split_at(sealed_master.len() - 16);

        let database = format!(r#"{{"version":3,"entries":[{entries}]}}"#);
        let db_cipher = Aes256Gcm::new(&key_of(&master).unwrap());
        let sealed_db = db_cipher
            .encrypt(&nonce_of(&db_nonce).unwrap(), database.as_bytes())
            .unwrap();
        let (db_body, db_tag) = sealed_db.split_at(sealed_db.len() - 16);

        format!(
            r#"{{"version":1,"header":{{"slots":[{{"type":1,"uuid":"s","key":"{}",
                 "key_params":{{"nonce":"{}","tag":"{}"}},
                 "n":{n},"r":8,"p":1,"salt":"{}"}}],
                 "params":{{"nonce":"{}","tag":"{}"}}}},"db":"{}"}}"#,
            to_hex(slot_key),
            to_hex(&slot_nonce),
            to_hex(slot_tag),
            to_hex(&salt),
            to_hex(&db_nonce),
            to_hex(db_tag),
            to_base64(db_body),
        )
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn to_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let value = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    out.push(ALPHABET[(value >> (18 - index * 6) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    const ENTRY: &str = r#"{"type":"totp","name":"alice","issuer":"Example",
        "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}"#;

    // A low cost, so the tests do not each spend a second on key derivation.
    const FAST: u64 = 1024;

    #[test]
    fn the_right_password_opens_an_aegis_export() {
        let file = aegis_file("correct horse", ENTRY, FAST);
        let report = aegis(&file, "correct horse").unwrap();

        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.secret.expose(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.account, "alice");
    }

    #[test]
    fn a_wrong_password_is_refused_rather_than_producing_nonsense() {
        let file = aegis_file("correct horse", ENTRY, FAST);
        assert_eq!(
            aegis(&file, "wrong"),
            Err(DecryptError::WrongPasswordOrDamaged)
        );
    }

    #[test]
    fn the_scrypt_cost_is_read_from_the_file() {
        // Section 12.1 rule 2 in the other direction. Aegis stores the cost so
        // that raising it does not orphan existing exports; a reader that
        // assumed today's value would fail on every newer file — reporting a
        // wrong password, on a correct one.
        for n in [512u64, 1024, 2048] {
            let file = aegis_file("pw", ENTRY, n);
            assert!(aegis(&file, "pw").is_ok(), "cost {n} was not honoured");
        }
    }

    /// The refusal happens *before* any memory is asked for.
    ///
    /// Refusing is only half the property. What the bound exists to prevent is
    /// the attempt — a crafted header naming n = 2^30 would have the system
    /// kill the application before any code got the chance to return an error.
    /// A test that only checks the return value cannot tell a guard that runs
    /// first from one that runs after `scrypt` has already tried.
    ///
    /// Timing separates them. Deriving at that cost takes seconds at best and
    /// never completes at worst, so a refusal inside a few milliseconds can
    /// only mean nothing was allocated. The threshold is loose on purpose: it
    /// is distinguishing "did not run" from "ran", not measuring anything.
    #[test]
    fn an_unreasonable_cost_is_refused_before_any_memory_is_claimed() {
        let file = aegis_file("pw", ENTRY, FAST).replace("\"n\":1024", "\"n\":1073741824");

        let started = std::time::Instant::now();
        let result = aegis(&file, "pw");
        let elapsed = started.elapsed();

        assert!(matches!(result, Err(DecryptError::Unreasonable { .. })));
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "the refusal took {elapsed:?}, so the cost was attempted before it              was checked. The guard has to run before scrypt, not after."
        );
    }

    #[test]
    fn an_unreasonable_cost_is_refused_rather_than_attempted() {
        // A crafted header naming a huge cost would exhaust memory and have the
        // application killed by the system — from a file, which is
        // attacker-supplied input.
        let file = aegis_file("pw", ENTRY, FAST).replace("\"n\":1024", "\"n\":1073741824");
        assert!(matches!(
            aegis(&file, "pw"),
            Err(DecryptError::Unreasonable { .. })
        ));
    }

    #[test]
    fn a_cost_that_is_not_a_power_of_two_is_refused() {
        let file = aegis_file("pw", ENTRY, FAST).replace("\"n\":1024", "\"n\":1000");
        assert!(matches!(
            aegis(&file, "pw"),
            Err(DecryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_damaged_file_and_a_wrong_password_give_the_same_answer() {
        // AEAD cannot tell them apart, and pretending otherwise would send
        // someone hunting for a backup fault that does not exist.
        let file = aegis_file("pw", ENTRY, FAST);
        let damaged = file.replace("\"db\":\"", "\"db\":\"AA");
        assert!(matches!(
            aegis(&damaged, "pw"),
            Err(DecryptError::WrongPasswordOrDamaged) | Err(DecryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_plain_export_is_not_mistaken_for_an_encrypted_one() {
        let plain = r#"{"version":1,"header":{"slots":null,"params":null},
                        "db":{"version":3,"entries":[]}}"#;
        assert!(matches!(
            aegis(plain, "pw"),
            Err(DecryptError::Malformed { .. })
        ));
    }

    #[test]
    fn entries_go_through_the_same_reader_as_a_plain_export() {
        // One code path for both variants, so a fix to either applies to both.
        // Here: the HOTP-without-a-counter refusal from the plain reader.
        let hotp = r#"{"type":"hotp","name":"h","issuer":"Y",
                       "info":{"secret":"JBSWY3DPEHPK3PXP"}}"#;
        let file = aegis_file("pw", hotp, FAST);
        let report = aegis(&file, "pw").unwrap();

        assert!(report.entries.is_empty());
        assert!(report.refused[0].reason.contains("counter"));
    }

    /// Builds a protected `.2fas` the way 2FAS does.
    fn twofas_file(password: &str, services: &str) -> String {
        let salt = [0x55u8; 16];
        let nonce = [0x66u8; 12];

        let mut derived = Zeroizing::new(vec![0u8; 32]);
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            password.as_bytes(),
            &salt,
            TWOFAS_ROUNDS,
            &mut derived,
        );

        let cipher = Aes256Gcm::new(&key_of(&derived).unwrap());
        let sealed = cipher
            .encrypt(
                &nonce_of(&nonce).unwrap(),
                format!("[{services}]").as_bytes(),
            )
            .unwrap();

        format!(
            r#"{{"services":[],"servicesEncrypted":"{}:{}:{}","schemaVersion":4}}"#,
            to_base64(&sealed),
            to_base64(&salt),
            to_base64(&nonce),
        )
    }

    const SERVICE: &str = r#"{"name":"Example","secret":"JBSWY3DPEHPK3PXP",
        "otp":{"account":"alice","issuer":"Example","digits":6,"period":30,
               "algorithm":"SHA1","tokenType":"TOTP"}}"#;

    #[test]
    fn the_right_password_opens_a_2fas_backup() {
        let file = twofas_file("hunter2", SERVICE);
        let report = twofas(&file, "hunter2").unwrap();

        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            report.entries[0].as_otp().unwrap().secret.expose(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn a_wrong_2fas_password_is_refused() {
        let file = twofas_file("hunter2", SERVICE);
        assert_eq!(
            twofas(&file, "hunter3"),
            Err(DecryptError::WrongPasswordOrDamaged)
        );
    }

    #[test]
    fn a_block_with_the_wrong_number_of_parts_is_refused() {
        let file = r#"{"servicesEncrypted":"onlyonepart","schemaVersion":4}"#;
        assert!(matches!(
            twofas(file, "pw"),
            Err(DecryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_plain_backup_is_not_mistaken_for_a_protected_one() {
        let plain = r#"{"services":[],"schemaVersion":4}"#;
        assert!(matches!(
            twofas(plain, "pw"),
            Err(DecryptError::Malformed { .. })
        ));
    }

    fn proton_file(password: &str, plain_export: &str) -> String {
        let salt = [0x77u8; 16];
        let nonce = [0x88u8; 12];
        let params = argon2::Params::new(
            PROTON_ARGON2_MEMORY_KIB,
            PROTON_ARGON2_OPERATIONS,
            1,
            Some(32),
        )
        .unwrap();
        let mut derived = Zeroizing::new([0u8; 32]);
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(password.as_bytes(), &salt, derived.as_mut())
            .unwrap();

        let cipher = Aes256Gcm::new(&key_of(derived.as_ref()).unwrap());
        let ciphertext = cipher
            .encrypt(
                &nonce_of(&nonce).unwrap(),
                AeadPayload {
                    msg: plain_export.as_bytes(),
                    aad: PROTON_EXPORT_AAD,
                },
            )
            .unwrap();
        let mut content = nonce.to_vec();
        content.extend_from_slice(&ciphertext);
        format!(
            r#"{{"version":1,"salt":"{}","content":"{}"}}"#,
            to_base64(&salt),
            to_base64(&content)
        )
    }

    const PROTON_PLAIN: &str = r#"{"version":1,"entries":[
        {"id":"one","content":{"uri":"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example","entry_type":"Totp","name":"Example"},"note":"keep"},
        {"id":"two","content":{"uri":"steam://JBSWY3DPEHPK3PXP","entry_type":"Steam","name":"Steam account"}}
    ]}"#;

    #[test]
    fn the_right_password_opens_a_proton_authenticator_export() {
        let file = proton_file("correct horse", PROTON_PLAIN);
        let report = proton(&file, "correct horse").unwrap();

        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].as_otp().unwrap().note, "keep");
        assert!(report.entries[1].is_steam());
    }

    #[test]
    fn a_wrong_proton_password_is_refused() {
        let file = proton_file("correct horse", PROTON_PLAIN);
        assert_eq!(
            proton(&file, "wrong"),
            Err(DecryptError::WrongPasswordOrDamaged)
        );
    }

    #[test]
    fn an_official_ente_export_fixture_opens() {
        // This fixture is the low-cost Ente export used by Proton's importer
        // compatibility tests. Its password is `password`.
        let file = include_str!("fixtures/ente-encrypted-v1.json");
        let report = ente(file, "password").unwrap();

        // The fixture contains two valid dummy Base32 secrets and one invalid
        // dummy Steam secret. Successful authenticated decryption is proved by
        // the two parsed entries and the specific per-entry refusal.
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0].reason.contains("Base32"));
    }

    #[test]
    fn a_wrong_ente_password_is_refused() {
        let file = include_str!("fixtures/ente-encrypted-v1.json");
        assert_eq!(
            ente(file, "wrong"),
            Err(DecryptError::WrongPasswordOrDamaged)
        );
    }

    #[test]
    fn unreasonable_ente_argon2_costs_are_refused_before_derivation() {
        let file = include_str!("fixtures/ente-encrypted-v1.json")
            .replace("\"memLimit\": 10240", "\"memLimit\": 1073741824");
        let started = std::time::Instant::now();
        let result = ente(&file, "password");

        assert!(matches!(result, Err(DecryptError::Unreasonable { .. })));
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
    }
}

#[cfg(test)]
mod panic_tests {
    use super::*;

    /// A malformed file must produce a message, not a crash.
    ///
    /// `Key::from_slice` and `Nonce::from_slice` panic on a wrong length, and
    /// both lengths here come out of a file — so the earlier code would have
    /// taken the application down on input a user can be handed by anyone.
    /// Clippy flagged them as deprecated; the panic was the real problem
    /// underneath the deprecation.
    #[test]
    fn a_wrong_length_nonce_is_an_error_not_a_panic() {
        for length in [0usize, 1, 11, 13, 16, 32] {
            let bytes = vec![0u8; length];
            let result = nonce_of(&bytes);
            if length == 12 {
                assert!(result.is_ok());
            } else {
                assert!(
                    matches!(result, Err(DecryptError::Malformed { .. })),
                    "a {length}-byte nonce must be refused, not panic"
                );
            }
        }
    }

    #[test]
    fn a_wrong_length_key_is_an_error_not_a_panic() {
        for length in [0usize, 16, 31, 33, 64] {
            assert!(
                matches!(
                    key_of(&vec![0u8; length]),
                    Err(DecryptError::Malformed { .. })
                ),
                "a {length}-byte key must be refused, not panic"
            );
        }
        assert!(key_of(&[0u8; 32]).is_ok());
    }

    /// The whole file, end to end, on input designed to break it.
    #[test]
    fn malformed_files_never_panic() {
        for text in [
            r#"{"header":{"slots":[{"type":1,"key":"00","key_params":{"nonce":"00","tag":"00"},"salt":"00"}],"params":{"nonce":"00","tag":"00"}},"db":"AA"}"#,
            r#"{"header":{"slots":[{"type":1,"key":"zz","key_params":{"nonce":"","tag":""},"salt":""}],"params":{"nonce":"","tag":""}},"db":""}"#,
            r#"{"header":{"slots":[],"params":{}},"db":""}"#,
            r#"{"servicesEncrypted":"::","schemaVersion":4}"#,
            r#"{"servicesEncrypted":"!!!:!!!:!!!","schemaVersion":4}"#,
        ] {
            // Either answer is fine. Not returning at all is not.
            let _ = aegis(text, "pw");
            let _ = twofas(text, "pw");
            let _ = ente(text, "pw");
            let _ = proton(text, "pw");
        }
    }
}
