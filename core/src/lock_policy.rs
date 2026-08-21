//! When the application locks itself, and where that setting lives
//! (PRD FR-33, FR-33a, FR-34).
//!
//! # Why this is in the metadata file
//!
//! FR-33a: "Store the lock policy in the unencrypted `meta` file. The
//! application must read it before the vault opens. It holds a timeout value
//! only. A lock setting that resets at every start does nothing."
//!
//! The ordering constraint is the whole reason. The policy decides whether the
//! application may open the vault without asking, so it has to be readable
//! *before* the vault opens — which rules out storing it inside the vault.
//! `meta.db` is unencrypted for exactly this class of thing.
//!
//! Nothing here is secret. A timeout and a flag tell an attacker who already
//! has the file how long a window they might have had, which is not something
//! the file was hiding anyway.
//!
//! # What is stored, and one judgement call
//!
//! FR-33a says the policy "holds a timeout value only". This module stores the
//! FR-34 background flag alongside it, and that is a deliberate reading rather
//! than an oversight: the same requirement ends "a lock setting that resets at
//! every start does nothing", and FR-34's option is a lock setting. Leaving it
//! unpersisted would satisfy the sentence's letter and break its point. The
//! "only" is read as a limit on what kind of thing goes in — a timeout, not a
//! key, not a verifier.

use crate::store::{MetaStore, StoreError};

/// `meta` keys holding the lock policy.
const META_LOCK_TIMEOUT: &str = "lock.timeout_seconds";
const META_LOCK_ON_BACKGROUND: &str = "lock.on_background";

/// The sentinel for FR-33's "never". Stored rather than deleting the key, so
/// that "the user chose never" is distinguishable from "never set".
const NEVER: i64 = -1;

/// The default timeout for a device that has not been asked yet.
///
/// One minute, the middle of FR-33's list. A vault that never locks by default
/// would make the lock opt-in, and FR-31 treats it as the protection for a
/// stolen device.
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 60;

/// When to lock (FR-33, FR-34).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicy {
    /// Seconds in the background before the vault locks. `None` is FR-33's
    /// "never"; `Some(0)` is its "immediate".
    pub timeout_seconds: Option<u32>,
    /// FR-34: lock as soon as the application leaves the foreground.
    pub lock_on_background: bool,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            timeout_seconds: Some(DEFAULT_TIMEOUT_SECONDS),
            lock_on_background: false,
        }
    }
}

impl LockPolicy {
    /// Reads the stored policy, falling back to the default.
    ///
    /// A damaged or unreadable value falls back rather than failing: the
    /// consequence of the fallback is a vault that locks after a minute, and
    /// the consequence of an error here is an application that will not start.
    pub fn load(meta: &MetaStore) -> Result<Self, StoreError> {
        let default = Self::default();

        let timeout = match read_i64(meta, META_LOCK_TIMEOUT)? {
            None => default.timeout_seconds,
            Some(NEVER) => None,
            Some(seconds) if seconds >= 0 => Some(seconds.min(u32::MAX as i64) as u32),
            // A negative value that is not the sentinel is damage. The safer
            // reading is the shorter window, not "never".
            Some(_) => default.timeout_seconds,
        };

        Ok(Self {
            timeout_seconds: timeout,
            lock_on_background: read_i64(meta, META_LOCK_ON_BACKGROUND)?
                .map(|value| value != 0)
                .unwrap_or(default.lock_on_background),
        })
    }

    pub fn save(&self, meta: &MetaStore) -> Result<(), StoreError> {
        let timeout = match self.timeout_seconds {
            Some(seconds) => i64::from(seconds),
            None => NEVER,
        };
        meta.set(META_LOCK_TIMEOUT, timeout.to_string().as_bytes())?;
        meta.set(
            META_LOCK_ON_BACKGROUND,
            if self.lock_on_background { b"1" } else { b"0" },
        )?;
        Ok(())
    }
}

fn read_i64(meta: &MetaStore, key: &str) -> Result<Option<i64>, StoreError> {
    Ok(meta
        .get(key)?
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| text.trim().parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> MetaStore {
        MetaStore::open_in_memory().unwrap()
    }

    #[test]
    fn a_device_that_was_never_asked_gets_the_default() {
        let policy = LockPolicy::load(&meta()).unwrap();

        assert_eq!(policy.timeout_seconds, Some(DEFAULT_TIMEOUT_SECONDS));
        assert!(!policy.lock_on_background);
    }

    /// FR-33a's point: a setting that resets at every start does nothing.
    #[test]
    fn every_choice_survives_a_reload() {
        let meta = meta();

        for timeout in [Some(0), Some(15), Some(60), Some(300), Some(900), None] {
            for background in [true, false] {
                let policy = LockPolicy {
                    timeout_seconds: timeout,
                    lock_on_background: background,
                };
                policy.save(&meta).unwrap();

                assert_eq!(
                    LockPolicy::load(&meta).unwrap(),
                    policy,
                    "timeout {timeout:?} with background {background} did not survive"
                );
            }
        }
    }

    /// "Never" has to be distinguishable from "not set", or choosing it would
    /// silently give the user the default instead.
    #[test]
    fn never_is_not_confused_with_unset() {
        let meta = meta();
        LockPolicy {
            timeout_seconds: None,
            lock_on_background: false,
        }
        .save(&meta)
        .unwrap();

        assert_eq!(LockPolicy::load(&meta).unwrap().timeout_seconds, None);
        assert_ne!(
            LockPolicy::load(&meta).unwrap().timeout_seconds,
            Some(DEFAULT_TIMEOUT_SECONDS)
        );
    }

    /// Immediate is zero, not absent. Confusing the two would turn the
    /// strictest setting into the default.
    #[test]
    fn immediate_is_zero_and_survives() {
        let meta = meta();
        LockPolicy {
            timeout_seconds: Some(0),
            lock_on_background: false,
        }
        .save(&meta)
        .unwrap();

        assert_eq!(LockPolicy::load(&meta).unwrap().timeout_seconds, Some(0));
    }

    /// A damaged value must not become "never". Falling back to the default
    /// keeps the shorter window, which is the safer of the two failures.
    #[test]
    fn a_damaged_value_falls_back_rather_than_disabling_the_lock() {
        let meta = meta();

        for damaged in ["", "not a number", "-99", "   "] {
            meta.set(META_LOCK_TIMEOUT, damaged.as_bytes()).unwrap();
            assert_eq!(
                LockPolicy::load(&meta).unwrap().timeout_seconds,
                Some(DEFAULT_TIMEOUT_SECONDS),
                "{damaged:?} should fall back, not disable the lock"
            );
        }
    }

    /// The policy has to be readable with no vault open — that is the whole
    /// reason FR-33a puts it in the metadata file.
    #[test]
    fn the_policy_is_readable_without_a_vault() {
        let meta = meta();
        LockPolicy {
            timeout_seconds: Some(15),
            lock_on_background: true,
        }
        .save(&meta)
        .unwrap();

        // No Store, no vault key, no cipher: just the metadata file.
        let reloaded = LockPolicy::load(&meta).unwrap();
        assert_eq!(reloaded.timeout_seconds, Some(15));
        assert!(reloaded.lock_on_background);
    }
}
