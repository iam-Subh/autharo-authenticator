//! Backup files this application writes and reads (PRD FR-26 to FR-28).
//!
//! # Why an app that cannot be left is a worse app
//!
//! Microsoft Authenticator cannot export its secrets — "by design for
//! security", which is why section 8.2.1 says to write a help page for it
//! rather than a parser. Users leaving it must retype every account by hand or
//! keep an application they no longer want.
//!
//! Being on the receiving end of that is a good reason not to do it. An
//! authenticator holds the keys to everything its user owns, and a product that
//! makes those hard to move is holding them hostage. So this writes a format
//! that is documented here, readable by anything that implements it, and
//! entirely offline.
//!
//! # The file describes its own encryption
//!
//! Section 12.1 rule 2 says not to rely on library defaults, and the same rule
//! applies to a file that has to be readable years later. The Argon2id
//! parameters are written into the header, so raising them for new backups
//! never orphans an old one.
//!
//! The base64 in the header and body is base64url without padding — the same
//! encoder the wire protocol uses, so there is one in this project rather than
//! two. Anything reading these files needs to know that, so it is written here.
//!
//! This is not theory: reading Aegis taught it. Their exports carry the scrypt
//! cost for exactly this reason, and a reader that assumed a value would fail on
//! every newer file — reporting a wrong password, on a correct one.
//!
//! # A plain export is a loaded weapon
//!
//! FR-27 requires one, because a user who cannot read their own data does not
//! really have it. It is still a file containing every secret in clear text, and
//! this module labels it as such in the file itself, so anything that opens it
//! later can say what it is holding.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::NONCE_LEN;
use crate::entry::Payload;
use crate::pin::{self, KdfParams, SALT_LEN};

use core::fmt;

/// Names the file for anything that opens it, including a text editor.
pub const FORMAT: &str = "authcore-backup";
/// Moves when the *file shape* changes, not when an entry gains a field.
pub const VERSION: u32 = 1;

#[derive(Debug)]
pub enum BackupError {
    /// Not one of ours.
    NotABackup,
    /// Encrypted, and no passphrase was supplied.
    NeedsPassphrase,
    /// The tag did not verify: a wrong passphrase, or a damaged file. AEAD
    /// cannot tell them apart and this does not pretend to.
    WrongPassphraseOrDamaged,
    /// Written by a newer version of this application.
    TooNew {
        version: u32,
    },
    Malformed {
        detail: String,
    },
    /// The vault holds nothing. Refused rather than written, because a backup
    /// file containing no accounts is indistinguishable from a working one
    /// until the day it is needed.
    Empty,
    Crypto {
        detail: String,
    },
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotABackup => f.write_str("This is not a backup file from this app."),
            Self::NeedsPassphrase => {
                f.write_str("This backup is encrypted. Enter the passphrase you set for it.")
            }
            Self::WrongPassphraseOrDamaged => f.write_str(
                "That passphrase did not open the backup. Check it and try again — \
                 if the passphrase is definitely right, the file may be damaged or \
                 incomplete.",
            ),
            Self::TooNew { version } => write!(
                f,
                "This backup was written by a newer version of the app (format {version}). \
                 Update the app and try again."
            ),
            Self::Malformed { detail } => write!(f, "This backup could not be read: {detail}"),
            Self::Empty => f.write_str(
                "There is nothing to back up yet. Add an account first — a backup \
                 with no accounts in it looks the same as a working one until you \
                 need it.",
            ),
            Self::Crypto { detail } => write!(f, "The backup could not be secured: {detail}"),
        }
    }
}

impl std::error::Error for BackupError {}

type Result<T> = core::result::Result<T, BackupError>;

/// The header every backup carries, encrypted or not.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u32,
    /// True when `data` is ciphertext. Present in both, so a reader never has
    /// to infer it from which fields exist — inferring is how 2FAS's protected
    /// backups get read as empty ones.
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfHeader>,
    /// Base64, present only when encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    /// The entries. An array when plain, a base64 string when encrypted.
    data: serde_json::Value,
}

/// The derivation, written down so a future change cannot orphan this file.
#[derive(Debug, Serialize, Deserialize)]
struct KdfHeader {
    algorithm: String,
    /// Memory in kibibytes, iterations, lanes — Argon2id's three costs.
    m: u32,
    t: u32,
    p: u32,
    salt: String,
}

/// What reading a backup produced.
#[derive(Debug)]
pub struct Backup {
    pub entries: Vec<Payload>,
    /// True when the file was encrypted. Worth surfacing: a user who thought
    /// they had made an encrypted backup and finds a plain one should be told.
    pub was_encrypted: bool,
}

/// A read-only check result. It contains no secret and changes no vault state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub entry_count: usize,
    pub folder_count: usize,
    pub was_encrypted: bool,
}

/// FR-27: every secret, in clear text, in a file.
///
/// Deliberately not pretty-printed into something that looks harmless. The
/// `encrypted: false` field is first-class so any reader — including a text
/// editor — can see what it is holding.
pub fn export_plain(entries: &[Payload]) -> Result<Zeroizing<String>> {
    if entries.is_empty() {
        return Err(BackupError::Empty);
    }

    let envelope = Envelope {
        format: FORMAT.to_string(),
        version: VERSION,
        encrypted: false,
        kdf: None,
        nonce: None,
        data: serde_json::to_value(entries).map_err(|error| BackupError::Malformed {
            detail: error.to_string(),
        })?,
    };

    // Zeroizing, because this string is every secret the user owns and it will
    // sit in memory until the caller has written it out.
    Ok(Zeroizing::new(
        serde_json::to_string_pretty(&envelope).map_err(|error| BackupError::Malformed {
            detail: error.to_string(),
        })?,
    ))
}

/// FR-26: the same contents, sealed with a passphrase the user chose.
///
/// Argon2id with the same costs as the account password slot (section 9.2.1),
/// and the parameters written into the file. XChaCha20-Poly1305 for the sealing,
/// matching section 9.3 — one construction in this project, not two.
pub fn export_encrypted(entries: &[Payload], passphrase: &str) -> Result<Zeroizing<String>> {
    if entries.is_empty() {
        return Err(BackupError::Empty);
    }
    if passphrase.is_empty() {
        return Err(BackupError::Malformed {
            detail: "a backup passphrase cannot be empty".to_string(),
        });
    }

    let plaintext =
        Zeroizing::new(
            serde_json::to_vec(entries).map_err(|error| BackupError::Malformed {
                detail: error.to_string(),
            })?,
        );

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|error| BackupError::Crypto {
        detail: format!("no secure random numbers are available: {error}"),
    })?;

    let params = KdfParams::default();
    let key = pin::derive_kek(passphrase, &salt, params).map_err(|error| BackupError::Crypto {
        detail: error.to_string(),
    })?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| BackupError::Crypto {
        detail: format!("no secure random numbers are available: {error}"),
    })?;

    let sealed = seal(&key, &nonce, &plaintext)?;

    let envelope = Envelope {
        format: FORMAT.to_string(),
        version: VERSION,
        encrypted: true,
        kdf: Some(KdfHeader {
            algorithm: "argon2id".to_string(),
            m: params.memory_kib,
            t: params.iterations,
            p: params.lanes,
            salt: base64(&salt),
        }),
        nonce: Some(base64(&nonce)),
        data: serde_json::Value::String(base64(&sealed)),
    };

    Ok(Zeroizing::new(
        serde_json::to_string_pretty(&envelope).map_err(|error| BackupError::Malformed {
            detail: error.to_string(),
        })?,
    ))
}

/// FR-28: reads either kind.
///
/// `passphrase` is ignored for a plain file. A plain file is *not* refused when
/// a passphrase is supplied — the user cannot be expected to remember which
/// kind they made, and refusing would be pedantry with a data-loss flavour.
pub fn read(text: &str, passphrase: Option<&str>) -> Result<Backup> {
    let envelope: Envelope = serde_json::from_str(text).map_err(|_| BackupError::NotABackup)?;

    if envelope.format != FORMAT {
        return Err(BackupError::NotABackup);
    }
    // Refused rather than attempted. A newer format may mean the same fields
    // with different rules, and guessing produces entries that look right.
    if envelope.version > VERSION {
        return Err(BackupError::TooNew {
            version: envelope.version,
        });
    }

    if !envelope.encrypted {
        let entries: Vec<Payload> =
            serde_json::from_value(envelope.data).map_err(|error| BackupError::Malformed {
                detail: error.to_string(),
            })?;
        return Ok(Backup {
            entries,
            was_encrypted: false,
        });
    }

    let Some(passphrase) = passphrase else {
        return Err(BackupError::NeedsPassphrase);
    };

    let kdf = envelope.kdf.ok_or(BackupError::Malformed {
        detail: "it is marked encrypted but says nothing about its key".to_string(),
    })?;
    if kdf.algorithm != "argon2id" {
        return Err(BackupError::Malformed {
            detail: format!("it uses {}, which this app cannot read", kdf.algorithm),
        });
    }

    let salt = unbase64(&kdf.salt).ok_or(BackupError::Malformed {
        detail: "its salt is not valid base64".to_string(),
    })?;
    let salt: [u8; SALT_LEN] = salt
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::Malformed {
            detail: "its salt is the wrong length".to_string(),
        })?;

    let nonce = envelope
        .nonce
        .as_deref()
        .and_then(unbase64)
        .ok_or(BackupError::Malformed {
            detail: "it has no usable nonce".to_string(),
        })?;

    let ciphertext = envelope
        .data
        .as_str()
        .and_then(unbase64)
        .ok_or(BackupError::Malformed {
            detail: "its contents are not valid base64".to_string(),
        })?;

    // The file's own parameters, never this version's defaults — the whole
    // reason they are written down.
    let params = KdfParams {
        memory_kib: kdf.m,
        iterations: kdf.t,
        lanes: kdf.p,
    };
    let key = pin::derive_kek(passphrase, &salt, params).map_err(|error| BackupError::Crypto {
        detail: error.to_string(),
    })?;

    let plaintext = open(&key, &nonce, &ciphertext)?;
    let entries: Vec<Payload> =
        serde_json::from_slice(&plaintext).map_err(|error| BackupError::Malformed {
            detail: error.to_string(),
        })?;

    Ok(Backup {
        entries,
        was_encrypted: true,
    })
}

/// Whether a file needs a passphrase, without attempting to read it.
///
/// Lets an interface ask for one before the user has waited through a
/// derivation, and lets it *not* ask for a plain file.
pub fn needs_passphrase(text: &str) -> Result<bool> {
    let envelope: Envelope = serde_json::from_str(text).map_err(|_| BackupError::NotABackup)?;
    if envelope.format != FORMAT {
        return Err(BackupError::NotABackup);
    }
    Ok(envelope.encrypted)
}

/// Opens and validates a backup without importing any record.
///
/// Reading proves the encrypted authentication tag, the passphrase, and the
/// JSON structure. Serializing each payload also applies the same size and
/// note limits that a restore applies before it writes a record.
pub fn verify(text: &str, passphrase: Option<&str>) -> Result<Verification> {
    let backup = read(text, passphrase)?;
    if backup.entries.is_empty() {
        return Err(BackupError::Empty);
    }

    let mut entry_count = 0usize;
    let mut folder_count = 0usize;
    for payload in &backup.entries {
        payload.to_json().map_err(|error| BackupError::Malformed {
            detail: error.to_string(),
        })?;
        match payload {
            Payload::Folder(_) => folder_count += 1,
            Payload::Totp(_) | Payload::Hotp(_) | Payload::Steam(_) => entry_count += 1,
        }
    }

    Ok(Verification {
        entry_count,
        folder_count,
        was_encrypted: backup.was_encrypted,
    })
}

// ---------------------------------------------------------------------------

fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| BackupError::Crypto {
        detail: "the key is the wrong length".to_string(),
    })?;
    cipher
        .encrypt(&XNonce::from(*nonce), plaintext)
        .map_err(|_| BackupError::Crypto {
            detail: "the backup could not be encrypted".to_string(),
        })
}

fn open(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| BackupError::Malformed {
        detail: "its nonce is the wrong length".to_string(),
    })?;

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| BackupError::Crypto {
        detail: "the key is the wrong length".to_string(),
    })?;

    cipher
        .decrypt(&XNonce::from(nonce), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| BackupError::WrongPassphraseOrDamaged)
}

fn base64(bytes: &[u8]) -> String {
    crate::transport::b64_encode(bytes)
}

fn unbase64(text: &str) -> Option<Vec<u8>> {
    crate::transport::b64_decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::OtpEntry;
    use crate::otp::Algorithm;
    use crate::secret::SecretString;

    fn entry(account: &str, counter: Option<u64>) -> Payload {
        let base = OtpEntry {
            v: 1,
            issuer: Some("Example".to_string()),
            account: account.to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP"),
            algorithm: Algorithm::Sha256,
            digits: 8,
            period: 60,
            counter,
            folder_id: None,
            icon: Some("example".to_string()),
            favourite: true,
            order: "a0m".to_string(),
            created_at: 1_700_000_000_000,
            note: "a note".to_string(),
            tags: vec!["work".to_string()],
            trashed_at: None,
            extra: Default::default(),
        };
        match counter {
            Some(_) => Payload::Hotp(base),
            None => Payload::Totp(base),
        }
    }

    #[test]
    fn a_plain_backup_round_trips_every_field() {
        // Everything, not just the secret. A backup that loses the counter
        // produces codes the issuer has already rejected; one that loses the
        // period or the digit count produces codes that are simply wrong. Both
        // restore silently and fail at the worst moment.
        let entries = vec![entry("alice", None), entry("bob", Some(42))];
        let text = export_plain(&entries).unwrap();
        let restored = read(&text, None).unwrap();

        assert!(!restored.was_encrypted);
        assert_eq!(restored.entries, entries);
    }

    #[test]
    fn an_encrypted_backup_round_trips() {
        let entries = vec![entry("alice", None)];
        let text = export_encrypted(&entries, "correct horse battery staple").unwrap();
        let restored = read(&text, Some("correct horse battery staple")).unwrap();

        assert!(restored.was_encrypted);
        assert_eq!(restored.entries, entries);
    }

    #[test]
    fn an_encrypted_backup_holds_no_readable_secret() {
        // The point of the whole exercise, asserted on the bytes rather than on
        // the fact that a function called "encrypt" was called.
        let entries = vec![entry("alice", None)];
        let text = export_encrypted(&entries, "pw").unwrap();

        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "the secret is in the file"
        );
        assert!(!text.contains("alice"), "the account name is in the file");
        assert!(!text.contains("Example"), "the issuer is in the file");
        assert!(!text.contains("a note"), "the note is in the file");
    }

    #[test]
    fn a_plain_backup_says_what_it_is() {
        // FR-27's file is every secret in clear text. Anything that opens it —
        // including a text editor — should be able to see that.
        let text = export_plain(&[entry("alice", None)]).unwrap();
        assert!(text.contains("\"encrypted\": false"));
        assert!(text.contains(FORMAT));
        assert!(
            text.contains("JBSWY3DPEHPK3PXP"),
            "a plain export that hid the secret would not be a plain export"
        );
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let text = export_encrypted(&[entry("alice", None)], "right").unwrap();
        assert!(matches!(
            read(&text, Some("wrong")),
            Err(BackupError::WrongPassphraseOrDamaged)
        ));
    }

    #[test]
    fn an_encrypted_backup_without_a_passphrase_asks_for_one() {
        // Rather than failing as unreadable, which would send the user looking
        // for a damaged file.
        let text = export_encrypted(&[entry("alice", None)], "pw").unwrap();
        assert!(matches!(
            read(&text, None),
            Err(BackupError::NeedsPassphrase)
        ));
        assert!(needs_passphrase(&text).unwrap());
    }

    #[test]
    fn a_plain_backup_opens_even_if_a_passphrase_is_offered() {
        // Users do not remember which kind they made. Refusing would be
        // pedantry with a data-loss flavour.
        let text = export_plain(&[entry("alice", None)]).unwrap();
        assert!(read(&text, Some("unnecessary")).is_ok());
        assert!(!needs_passphrase(&text).unwrap());
    }

    #[test]
    fn verification_opens_the_file_without_importing_it() {
        let text = export_encrypted(&[entry("alice", None), entry("bob", Some(4))], "pw").unwrap();

        let report = verify(&text, Some("pw")).unwrap();
        assert_eq!(report.entry_count, 2);
        assert_eq!(report.folder_count, 0);
        assert!(report.was_encrypted);
    }

    #[test]
    fn verification_rejects_a_wrong_passphrase() {
        let text = export_encrypted(&[entry("alice", None)], "right").unwrap();
        assert!(matches!(
            verify(&text, Some("wrong")),
            Err(BackupError::WrongPassphraseOrDamaged)
        ));
    }

    #[test]
    fn the_derivation_parameters_travel_with_the_file() {
        // Section 12.1 rule 2, in the export direction. Reading Aegis taught
        // this: their exports carry the scrypt cost so that raising it does not
        // orphan old files, and a reader that assumed a value fails on every
        // newer one — reporting a wrong password, on a correct password.
        let text = export_encrypted(&[entry("alice", None)], "pw").unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        let params = KdfParams::default();
        assert_eq!(value["kdf"]["algorithm"], "argon2id");
        assert_eq!(value["kdf"]["m"], params.memory_kib);
        assert_eq!(value["kdf"]["t"], params.iterations);
        assert_eq!(value["kdf"]["p"], params.lanes);
        assert!(value["kdf"]["salt"].as_str().is_some());
    }

    #[test]
    fn a_file_written_with_other_parameters_still_opens() {
        // The consequence of writing them down: a backup made when the costs
        // were lower must keep opening after they are raised.
        let entries = vec![entry("alice", None)];
        let text = export_encrypted(&entries, "pw").unwrap();

        // Rewrite the header to a *different* cost, as a future version would.
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let original = value["kdf"]["m"].as_u64().unwrap();
        assert!(original > 0);

        // Reading uses the file's value, so tampering with it must fail to
        // derive the same key — which proves the file's value is what is used,
        // not a constant.
        value["kdf"]["m"] = serde_json::json!(original * 2);
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(
            matches!(
                read(&tampered, Some("pw")),
                Err(BackupError::WrongPassphraseOrDamaged)
            ),
            "the header cost is not being used"
        );
    }

    #[test]
    fn an_empty_vault_refuses_to_produce_a_backup() {
        // A file with no accounts in it is indistinguishable from a working one
        // until the day it is needed.
        assert!(matches!(export_plain(&[]), Err(BackupError::Empty)));
        assert!(matches!(
            export_encrypted(&[], "pw"),
            Err(BackupError::Empty)
        ));
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        assert!(matches!(
            export_encrypted(&[entry("a", None)], ""),
            Err(BackupError::Malformed { .. })
        ));
    }

    #[test]
    fn a_newer_format_is_refused_rather_than_guessed_at() {
        let text = export_plain(&[entry("alice", None)]).unwrap();
        let bumped = text.replace("\"version\": 1", "\"version\": 99");
        assert!(matches!(
            read(&bumped, None),
            Err(BackupError::TooNew { version: 99 })
        ));
    }

    #[test]
    fn something_that_is_not_a_backup_says_so() {
        for text in [
            "",
            "{}",
            "not json",
            r#"{"format":"something-else","version":1,"encrypted":false,"data":[]}"#,
            r#"{"db":{"entries":[]}}"#,
        ] {
            assert!(
                matches!(
                    read(text, None),
                    Err(BackupError::NotABackup) | Err(BackupError::Malformed { .. })
                ),
                "{text:?} was accepted"
            );
        }
    }

    #[test]
    fn a_truncated_encrypted_backup_does_not_panic() {
        let text = export_encrypted(&[entry("alice", None)], "pw").unwrap();
        for cut in [10, 50, 100, text.len() / 2] {
            let truncated = &text[..cut.min(text.len())];
            let _ = read(truncated, Some("pw"));
        }
    }

    #[test]
    fn the_encrypted_flag_is_written_rather_than_inferred() {
        // 2FAS's protected backups are read as empty ones by readers that infer
        // encryption from which fields are present. An explicit flag removes
        // the inference, so this file cannot be misread the same way.
        let text = export_encrypted(&[entry("alice", None)], "pw").unwrap();
        assert!(text.contains("\"encrypted\": true"));
    }
}
