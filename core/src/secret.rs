//! `SecretString`, the wrapper every stored secret travels in (PRD section 9.4).
//!
//! Two rules from section 9.4 drive this type:
//!
//! - "Zero key material in memory after use." The inner buffer is wiped when
//!   the value drops.
//! - "Do not log secrets, codes, or key material at any log level." A derived
//!   `Debug` on any struct holding a secret would defeat that, because a panic
//!   message or a `tracing` field prints it. `Debug` here redacts instead.
//!
//! The limit is worth stating: zeroizing clears the buffer this value owns. It
//! cannot reach a copy that `String` left behind when it grew and reallocated,
//! nor a copy the allocator or the operating system made. It reduces the window
//! in which a secret sits in memory; it does not close it.

use core::fmt;
use core::ops::Deref;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

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
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
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
        Self(value)
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

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(SecretString::new(value))
            }
        }

        deserializer.deserialize_str(SecretVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQ";

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
