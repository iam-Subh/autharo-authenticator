//! `EntryPayload`, the plaintext inside a record (PRD section 12.2).
//!
//! This is the only thing the vault key ever encrypts. A folder is a record in
//! the same table with `"type": "folder"`, so folder names sync, encrypt, and
//! resolve conflicts through the same path as entries (FR-19).
//!
//! Unknown fields are captured in `extra` and written back out untouched, so a
//! version 1 client can round-trip a record written by a version 2 client
//! without dropping what it did not understand.

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::otp::{Algorithm, DEFAULT_DIGITS, DEFAULT_PERIOD, OtpKind};
use crate::otpauth::OtpAuthUri;
use crate::secret::SecretString;

/// The schema version this build writes.
pub const CURRENT_VERSION: u32 = 2;
/// Longest note the user interface accepts (section 12.2).
pub const MAX_NOTE_CHARS: usize = 512;
/// Largest payload before encryption (section 12.2). The server quota in
/// NFR-11 is 4 KiB per encrypted record; this leaves room for the AEAD tag and
/// the nonce, and it lets the client refuse with its own message first.
pub const MAX_PAYLOAD_BYTES: usize = 3 * 1024;

/// A payload that cannot be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    NoteTooLong { chars: usize },
    TooLarge { bytes: usize },
    Malformed { reason: String },
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoteTooLong { chars } => write!(
                f,
                "The note is {chars} characters. The limit is {MAX_NOTE_CHARS}."
            ),
            Self::TooLarge { bytes } => write!(
                f,
                "This entry is {bytes} bytes. The limit is {MAX_PAYLOAD_BYTES}."
            ),
            Self::Malformed { reason } => write!(f, "This entry could not be read: {reason}"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// One record's plaintext.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Payload {
    Totp(OtpEntry),
    Hotp(OtpEntry),
    /// A Steam Guard code (FR-06).
    ///
    /// Carries an `OtpEntry` like the others rather than a type of its own,
    /// because everything except the final encoding is shared — the same
    /// secret, the same thirty-second step, the same truncation. Its `digits`
    /// and `period` are fixed by the format and are not read when the code is
    /// produced; they are stored so that an entry round-trips through export
    /// and back unchanged.
    Steam(OtpEntry),
    Folder(Folder),
}

/// A TOTP or HOTP account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtpEntry {
    #[serde(default = "default_version")]
    pub v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub account: String,
    /// Canonical unpadded Base32, as produced by `base32::normalize`. Wrapped
    /// so that it is wiped on drop and redacted in `Debug` (section 9.4).
    pub secret: SecretString,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "default_digits")]
    pub digits: u8,
    #[serde(default = "default_period")]
    pub period: u32,
    /// An integer for HOTP, `null` for TOTP.
    #[serde(default)]
    pub counter: Option<u64>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    /// Fractional index for manual ordering (FR-22).
    #[serde(default)]
    pub order: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub note: String,
    /// User-defined labels. One entry can have more than one label.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Epoch milliseconds when the user moved this entry to trash.
    /// A live entry has no value.
    #[serde(default)]
    pub trashed_at: Option<i64>,
    /// Fields written by a newer client, preserved on write.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A folder (FR-19).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Folder {
    #[serde(default = "default_version")]
    pub v: u32,
    pub name: String,
    #[serde(default)]
    pub order: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_version() -> u32 {
    CURRENT_VERSION
}
fn default_digits() -> u8 {
    DEFAULT_DIGITS
}
fn default_period() -> u32 {
    DEFAULT_PERIOD
}

impl Payload {
    /// Serializes to the bytes that the vault key encrypts, after checking the
    /// size limits so the user sees a message from the client rather than a
    /// quota error from the server.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
        if let Payload::Totp(entry) | Payload::Hotp(entry) | Payload::Steam(entry) = self {
            let chars = entry.note.chars().count();
            if chars > MAX_NOTE_CHARS {
                return Err(PayloadError::NoteTooLong { chars });
            }
        }
        let bytes = serde_json::to_vec(self).map_err(|error| PayloadError::Malformed {
            reason: error.to_string(),
        })?;
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(PayloadError::TooLarge { bytes: bytes.len() });
        }
        Ok(Zeroizing::new(bytes))
    }

    /// Reads a payload produced by this or any other client.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PayloadError> {
        serde_json::from_slice(bytes).map_err(|error| PayloadError::Malformed {
            reason: error.to_string(),
        })
    }

    /// The `type` value this payload carries.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Totp(_) => "totp",
            Self::Hotp(_) => "hotp",
            Self::Steam(_) => "steam",
            Self::Folder(_) => "folder",
        }
    }

    /// The account inside, for every variant that holds one.
    pub fn as_otp(&self) -> Option<&OtpEntry> {
        match self {
            Self::Totp(entry) | Self::Hotp(entry) | Self::Steam(entry) => Some(entry),
            Self::Folder(_) => None,
        }
    }

    /// True for an entry whose code is produced by [`crate::otp::steam`].
    pub fn is_steam(&self) -> bool {
        matches!(self, Self::Steam(_))
    }
}

impl OtpEntry {
    /// Builds an entry from a scanned or imported URI (FR-10, FR-14, FR-15).
    pub fn from_uri(uri: &OtpAuthUri, created_at: i64) -> Payload {
        let entry = Self {
            v: CURRENT_VERSION,
            issuer: uri.issuer.clone(),
            account: uri.account.clone(),
            secret: uri.secret.clone(),
            algorithm: uri.algorithm,
            digits: uri.digits,
            period: uri.period,
            counter: uri.counter,
            folder_id: None,
            icon: None,
            favourite: false,
            order: String::new(),
            created_at,
            note: String::new(),
            tags: Vec::new(),
            trashed_at: None,
            extra: Map::new(),
        };
        match uri.kind {
            OtpKind::Totp => Payload::Totp(entry),
            OtpKind::Hotp => Payload::Hotp(entry),
            OtpKind::Steam => Payload::Steam(entry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Payload {
        let uri = OtpAuthUri::parse(
            "otpauth://totp/GitHub:rupsa%40example.com\
             ?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub",
        )
        .unwrap();
        OtpEntry::from_uri(&uri, 1_755_734_400_000)
    }

    #[test]
    fn round_trips_through_json() {
        let payload = sample();
        let bytes = payload.to_json().unwrap();
        assert_eq!(Payload::from_json(&bytes).unwrap(), payload);
    }

    /// Section 12.2 shows the exact field names. Other clients read these, so
    /// a rename is a breaking change and should fail this test.
    #[test]
    fn writes_the_documented_field_names() {
        let bytes = sample().to_json().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object["type"], "totp");
        assert_eq!(object["v"], CURRENT_VERSION);
        assert_eq!(object["issuer"], "GitHub");
        assert_eq!(object["account"], "rupsa@example.com");
        assert_eq!(object["algorithm"], "SHA1");
        assert_eq!(object["digits"], 6);
        assert_eq!(object["period"], 30);
        assert!(
            object["counter"].is_null(),
            "TOTP entries carry a null counter"
        );
        for field in [
            "folder_id",
            "icon",
            "favourite",
            "order",
            "created_at",
            "note",
            "tags",
            "trashed_at",
        ] {
            assert!(object.contains_key(field), "missing field {field}");
        }
    }

    #[test]
    fn an_hotp_entry_carries_its_counter() {
        let uri = OtpAuthUri::parse(
            "otpauth://hotp/Bank:acct?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=7",
        )
        .unwrap();
        let payload = OtpEntry::from_uri(&uri, 0);
        assert_eq!(payload.type_name(), "hotp");
        assert_eq!(payload.as_otp().unwrap().counter, Some(7));
    }

    /// The rule in section 12.2: a client must preserve fields it does not
    /// understand rather than dropping them on write.
    #[test]
    fn preserves_unknown_fields_written_by_a_newer_client() {
        let from_v2 = br#"{
            "v": 2,
            "type": "totp",
            "account": "acct",
            "secret": "MZXW6YQ",
            "tags": ["work", "finance"],
            "pinned_at": 1755734400000
        }"#;

        let payload = Payload::from_json(from_v2).unwrap();
        let entry = payload.as_otp().unwrap();
        assert_eq!(entry.v, 2);
        assert_eq!(entry.tags, ["work", "finance"]);

        let value: Value = serde_json::from_slice(&payload.to_json().unwrap()).unwrap();
        assert_eq!(value["tags"][1], "finance");
        assert_eq!(value["pinned_at"], 1_755_734_400_000i64);
    }

    #[test]
    fn an_old_entry_defaults_to_live_with_no_tags() {
        let old = br#"{
            "v": 1,
            "type": "totp",
            "account": "acct",
            "secret": "MZXW6YQ"
        }"#;

        let payload = Payload::from_json(old).unwrap();
        let entry = payload.as_otp().unwrap();
        assert!(entry.tags.is_empty());
        assert_eq!(entry.trashed_at, None);
    }

    #[test]
    fn trash_time_and_tags_round_trip_inside_the_encrypted_payload() {
        let Payload::Totp(mut entry) = sample() else {
            unreachable!()
        };
        entry.tags = vec!["work".to_string(), "finance".to_string()];
        entry.trashed_at = Some(1_755_734_400_000);

        let payload = Payload::Totp(entry);
        let reopened = Payload::from_json(&payload.to_json().unwrap()).unwrap();
        let reopened = reopened.as_otp().unwrap();
        assert_eq!(reopened.tags, ["work", "finance"]);
        assert_eq!(reopened.trashed_at, Some(1_755_734_400_000));
    }

    #[test]
    fn a_folder_is_a_payload_of_its_own() {
        let folder = Payload::Folder(Folder {
            v: CURRENT_VERSION,
            name: "Work".to_string(),
            order: "a0f".to_string(),
            created_at: 1_755_734_400_000,
            extra: Map::new(),
        });
        let bytes = folder.to_json().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["type"], "folder");
        assert_eq!(value["name"], "Work");
        assert_eq!(Payload::from_json(&bytes).unwrap(), folder);
    }

    #[test]
    fn rejects_a_note_over_the_limit() {
        let Payload::Totp(mut entry) = sample() else {
            unreachable!()
        };
        entry.note = "x".repeat(MAX_NOTE_CHARS + 1);
        assert_eq!(
            Payload::Totp(entry).to_json().unwrap_err(),
            PayloadError::NoteTooLong {
                chars: MAX_NOTE_CHARS + 1
            }
        );
    }

    #[test]
    fn rejects_a_payload_over_the_limit() {
        let Payload::Totp(mut entry) = sample() else {
            unreachable!()
        };
        entry.account = "x".repeat(MAX_PAYLOAD_BYTES);
        assert!(matches!(
            Payload::Totp(entry).to_json().unwrap_err(),
            PayloadError::TooLarge { .. }
        ));
    }

    #[test]
    fn reports_why_a_payload_is_unreadable() {
        assert!(matches!(
            Payload::from_json(b"not json").unwrap_err(),
            PayloadError::Malformed { .. }
        ));
    }
}
