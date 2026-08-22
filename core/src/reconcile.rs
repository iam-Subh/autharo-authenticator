//! The deferred HOTP counter rule (PRD section 10.4, steps 4 and 5).
//!
//! # Why this is a separate module
//!
//! Applying the rule needs the payloads, so it needs a key, so it needs
//! `Vault`. The sync cycle must not — OFF-09 has it running while locked, and
//! `crate::sync` is deliberately written so that a change needing a payload
//! there would not compile. Keeping the two apart preserves that.
//!
//! # What it fixes
//!
//! While locked, a conflict is settled by HLC alone. That can take the *newer*
//! HOTP counter rather than the *larger* one, and a counter behind the
//! issuer's produces codes the issuer has already rejected. The sync cycle
//! therefore keeps the discarded record, and this runs at unlock with both
//! payloads in hand.
//!
//! # When it runs
//!
//! Inside the unlock path, before the code list is usable (step 4). A lazy
//! reconcile would leave a window in which the user unlocks, taps an HOTP
//! entry, and gets a code from the wrong counter — which is exactly the
//! failure being avoided, arrived at a second way.
//!
//! `Store::reconcile_pending_for` backs that up: an entry with a record still
//! pending refuses to produce a code at all, so a caller that forgets to run
//! this gets an error rather than a wrong answer.

use core::fmt;

use crate::entry::{OtpEntry, Payload};
use crate::hlc::HlcClock;
use crate::store::StoreError;
use crate::vault::{Vault, VaultError};

/// What a reconcile pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Records examined.
    pub examined: usize,
    /// Entries whose counter was raised to the discarded record's.
    pub counters_raised: usize,
    /// Records that needed no change: the winner already held the larger
    /// counter, or the entry was not an HOTP entry.
    pub already_correct: usize,
    /// Records dropped because the entry no longer exists — deleted on another
    /// device between the conflict and the unlock.
    pub orphaned: usize,
}

#[derive(Debug)]
pub enum ReconcileError {
    Store(StoreError),
    Vault(VaultError),
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(inner) => write!(f, "{inner}"),
            Self::Vault(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

impl From<StoreError> for ReconcileError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<VaultError> for ReconcileError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}

type Result<T> = core::result::Result<T, ReconcileError>;

/// Applies section 10.4's counter rule to every pending record.
///
/// Call this from the unlock path, before anything can ask for a code.
///
/// A raised counter is written with a **fresh HLC**, so it propagates: the
/// device that held the smaller counter needs to learn the larger one, and a
/// write that kept the old timestamp would lose the next conflict and be
/// undone.
pub fn run<C: crate::vault::RecordCipher>(
    vault: &mut Vault<C>,
    clock: &mut HlcClock,
    now_ms: u64,
) -> Result<ReconcileReport> {
    let mut report = ReconcileReport::default();

    for pending in vault.store().reconcile_pending()? {
        report.examined += 1;

        let Ok(current) = vault.get(&pending.entry_id) else {
            // The entry is gone — deleted elsewhere while this was waiting.
            // Nothing to reconcile, and keeping the record would block a code
            // for an entry that no longer exists.
            vault.store().clear_reconcile(&pending.entry_id)?;
            report.orphaned += 1;
            continue;
        };

        let discarded = vault.open_record(&pending.entry_id, &pending.ciphertext, &pending.nonce);

        let raised = match (current.payload.as_otp(), discarded.as_ref().ok()) {
            (Some(winner), Some(loser_payload)) => {
                match (winner.counter, counter_of(loser_payload)) {
                    // Section 10.4: "Take the larger counter. Never take the
                    // newer value."
                    (Some(kept), Some(other)) if other > kept => Some(other),
                    _ => None,
                }
            }
            // A payload that will not open is not a reason to keep blocking
            // the entry. It cannot be compared, and the alternative is an
            // entry that never produces a code again.
            _ => None,
        };

        match raised {
            Some(counter) => {
                let mut payload = current.payload.clone();
                if let Payload::Hotp(entry) = &mut payload {
                    entry.counter = Some(counter);
                }
                // A fresh timestamp, so the larger counter wins the next
                // conflict and reaches the other devices.
                let _ = clock.tick(now_ms);
                vault.update(&pending.entry_id, &payload, now_ms as i64)?;
                report.counters_raised += 1;
            }
            None => report.already_correct += 1,
        }

        // Step 5: cleared only now. A crash before this point leaves the
        // record for the next unlock.
        vault.store().clear_reconcile(&pending.entry_id)?;
    }

    Ok(report)
}

fn counter_of(payload: &Payload) -> Option<u64> {
    match payload {
        Payload::Hotp(entry) => entry.counter,
        _ => None,
    }
}

/// True when this entry still has a record waiting (section 10.4 step 3).
pub fn is_blocked<C: crate::vault::RecordCipher>(
    vault: &Vault<C>,
    entry_id: &str,
) -> core::result::Result<bool, StoreError> {
    vault.store().reconcile_pending_for(entry_id)
}

/// The counter an [`OtpEntry`] holds, for callers outside this module.
pub fn entry_counter(entry: &OtpEntry) -> Option<u64> {
    entry.counter
}
