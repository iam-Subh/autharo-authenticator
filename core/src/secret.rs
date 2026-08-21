//! `SecretString`, the wrapper every stored secret travels in (PRD section 9.4).
//!
//! Three rules from section 9.4 drive this type:
//!
//! - "Zero key material in memory after use." The inner buffer is wiped when
//!   the value drops.
//! - "Do not log secrets, codes, or key material at any log level." A derived
//!   `Debug` on any struct holding a secret would defeat that, because a panic
//!   message or a `tracing` field prints it. `Debug` here redacts instead.
//! - "Never write the vault key or the master key to disk in plaintext."
//!   Serialization is a deliberate impl below, not a derive.
//!
//! # Why the buffer is sized once
//!
//! Zeroizing clears the buffer a value currently owns. It cannot reach a copy
//! that `String` left behind when it grew: pushing past the capacity allocates
//! a larger block, copies the bytes across, and frees the old block without
//! clearing it. The secret then sits in freed heap until something else
//! happens to reuse that memory.
//!
//! So every constructor here allocates the exact length up front and writes
//! once. `assert_no_slack` in the tests pins that, because the failure is
//! invisible at runtime — the type still behaves correctly, it just leaves a
//! copy behind.
//!
//! What this still does not cover, and cannot: copies the allocator, the
//! operating system, or a deserializer made before the value reached this
//! type. Prefer [`SecretString::into_bytes`] where the Base32 text is not
//! needed afterwards, so the encoded form stops existing at the earliest point.

use core::fmt;
use core::ops::Deref;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::base32::{self, Base32Error};

/// A Base32 secret, wiped on drop and redacted in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

/// Hashed by content, so a secret can key a duplicate check (FR-16) without
/// the caller reaching for `expose`.
impl core::hash::Hash for SecretString {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl SecretString {
    /// Copies `value` into a buffer sized exactly to it.
    ///
    /// Going through `with_capacity` and a single `push_str` rather than
    /// `to_string` is not superstition: it guarantees one allocation and no
    /// growth, so there is exactly one buffer to wipe.
    pub fn new(value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        let mut buffer = String::with_capacity(value.len());
        buffer.push_str(value);
        Self(Zeroizing::new(buffer))
    }

    /// Takes ownership of a string that is already exactly sized.
    ///
    /// Used by `base32::normalize`, which builds its output with the symbol
    /// count known in advance. If the string carries spare capacity it is
    /// repacked instead, because that spare capacity means it grew.
    pub fn from_exact(value: Zeroizing<String>) -> Self {
        if value.capacity() == value.len() {
            return Self(value);
        }
        Self::new(value.as_str())
    }

    /// Decodes to key bytes, leaving the Base32 text in place.
    pub fn decode(&self) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
        base32::decode(self.0.as_str())
    }

    /// Decodes to key bytes and destroys the Base32 text.
    ///
    /// Prefer this wherever the text is not needed again — it is the only way
    /// to stop the encoded form existing alongside the decoded one. The string
    /// is wiped by `Zeroizing` as it goes out of scope at the end of this call.
    pub fn into_bytes(self) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
        base32::decode(self.0.as_str())
    }

    /// Reads the secret. Every call site for this is a place to check that the
    /// value does not escape into a log or a display string.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<Zeroizing<String>> for SecretString {
    fn from(value: Zeroizing<String>) -> Self {
        Self::from_exact(value)
    }
}

/// Redacted. Section 9.4 forbids a secret reaching any log level, and a
/// derived `Debug` on an enclosing struct would print it.
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<redacted, {} characters>)", self.0.len())
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Serializes as a plain string, because `EntryPayload.secret` in section 12.2
/// is a plain string. The protection is against memory disclosure, not against
/// the payload format.
impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;

        impl Visitor<'_> for SecretVisitor {
            type Value = SecretString;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Base32 secret")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SecretString::new(value))
            }

            // serde hands over a `String` it allocated, which may carry spare
            // capacity from its own parsing buffer. Repack it, then wipe the
            // one serde built rather than letting it drop uncleared.
            fn visit_string<E: de::Error>(self, mut value: String) -> Result<Self::Value, E> {
                let secret = SecretString::new(&value);
                value.zeroize();
                Ok(secret)
            }
        }

        deserializer.deserialize_str(SecretVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQ";

    /// A buffer with spare capacity is a buffer that grew, and a buffer that
    /// grew left its old contents in freed heap where zeroize cannot reach.
    fn assert_no_slack(secret: &SecretString) {
        assert_eq!(
            secret.0.capacity(),
            secret.0.len(),
            "the buffer carries spare capacity, so it was grown rather than              sized once; the pre-growth copy cannot be wiped"
        );
    }

    #[test]
    fn every_constructor_sizes_the_buffer_exactly() {
        assert_no_slack(&SecretString::new(SECRET));
        assert_no_slack(&SecretString::from(SECRET));
        assert_no_slack(&SecretString::from(SECRET.to_string()));

        // A buffer with spare capacity stands in for one that grew: the
        // capacity beyond the length is where the pre-growth copy would sit.
        // Sized explicitly rather than by pushing, because String's growth
        // policy can land on an exact fit by luck and make the test vacuous.
        let mut slack = String::with_capacity(SECRET.len() * 4);
        slack.push_str(SECRET);
        assert!(slack.capacity() > slack.len(), "precondition");
        assert_no_slack(&SecretString::from(Zeroizing::new(slack)));
    }

    #[test]
    fn an_exactly_sized_buffer_is_adopted_without_copying() {
        let mut exact = String::with_capacity(SECRET.len());
        exact.push_str(SECRET);
        let address = exact.as_ptr();

        let secret = SecretString::from_exact(Zeroizing::new(exact));

        assert_eq!(
            secret.expose().as_ptr(),
            address,
            "an already exact buffer should be moved, not reallocated"
        );
    }

    #[test]
    fn deserialization_produces_an_exact_buffer() {
        let secret: SecretString = serde_json::from_str(&format!("\"{SECRET}\"")).unwrap();
        assert_eq!(secret.expose(), SECRET);
        assert_no_slack(&secret);
    }

    #[test]
    fn decodes_to_key_bytes() {
        let secret = SecretString::new(SECRET);
        let expected: &[u8] = b"1234567890";

        assert_eq!(secret.decode().unwrap().as_slice(), expected);
        assert_eq!(
            secret.into_bytes().unwrap().as_slice(),
            expected,
            "into_bytes drops the Base32 text and returns the same key"
        );
    }

    /// Section 9.4: a secret must not reach any log level. `Debug` is the
    /// easiest way for one to get there, so it is redacted at the source.
    #[test]
    fn debug_output_hides_the_secret() {
        let secret = SecretString::new(SECRET);
        let rendered = format!("{secret:?}");

        assert!(!rendered.contains(SECRET), "Debug leaked the secret");
        assert!(rendered.contains("redacted"));
    }

    /// A struct that derives `Debug` must inherit the redaction, which is the
    /// case this type exists to cover.
    #[test]
    fn an_enclosing_struct_inherits_the_redaction() {
        #[derive(Debug)]
        struct Entry {
            account: String,
            secret: SecretString,
        }

        let entry = Entry {
            account: "rupsa@example.com".to_string(),
            secret: SecretString::new(SECRET),
        };
        let rendered = format!("{entry:?}");

        assert!(!rendered.contains(SECRET), "Debug leaked the secret");
        assert_eq!(entry.secret.expose(), SECRET);
        assert!(
            rendered.contains(&entry.account),
            "other fields still print"
        );
    }

    #[test]
    fn round_trips_as_a_plain_json_string() {
        let secret = SecretString::new(SECRET);
        let json = serde_json::to_string(&secret).unwrap();

        assert_eq!(json, format!("\"{SECRET}\""));
        assert_eq!(serde_json::from_str::<SecretString>(&json).unwrap(), secret);
    }

    #[test]
    fn reads_like_a_string_where_it_is_used() {
        let secret = SecretString::new(SECRET);
        assert_eq!(secret.expose(), SECRET);
        assert_eq!(&*secret, SECRET);
        assert_eq!(secret.len(), SECRET.len());
        assert!(!secret.is_empty());
    }

    #[test]
    fn zeroizing_clears_the_buffer() {
        let mut secret = SecretString::new(SECRET);
        secret.zeroize();
        assert!(secret.is_empty());
    }
}
