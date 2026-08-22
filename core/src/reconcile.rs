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
//!
//! # The corrected timestamp comes from the records, not a clock
//!
//! Section 10.4 step 7. The correction only has to beat the records it
//! corrects, so its timestamp is the largest of theirs with the counter
//! increased by one, carrying this device's identifier.
//!
//! Reading a clock here would be wrong in both directions, and neither failure
//! announces itself. A clock behind the records makes the correction *lose* to
//! the record it corrects, so the counter reverts after every unlock. A clock
//! ahead makes it win every later conflict on that entry until real time
//! catches up — and section 10.2's drift bound cannot help, because that bound
//! applies to incoming values and this one is local.

use std::collections::BTreeMap;

use core::fmt;

use crate::entry::{OtpEntry, Payload};
use crate::hlc::{Hlc, advance};
use crate::store::StoreError;
use crate::vault::{Vault, VaultError};

/// What a reconcile pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Entries examined. An entry with several candidates counts once.
    pub examined: usize,
    /// Discarded candidates read.
    pub candidates: usize,
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

/// Applies section 10.4's counter rule to every pending candidate.
///
/// Call this from the unlock path, before anything can ask for a code. It
/// reads no clock: see the module documentation for why that matters.
pub fn run<C: crate::vault::RecordCipher>(vault: &mut Vault<C>) -> Result<ReconcileReport> {
    let mut report = ReconcileReport::default();
    let device = vault.store().device_id()?;

    // Grouped, because step 4 keeps every candidate and an entry may hold
    // several. Taking the largest counter across all of them is the whole
    // point: with three candidates, comparing only one can return a value
    // that is neither the largest nor obviously wrong.
    let mut by_entry: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for candidate in vault.store().reconcile_pending()? {
        report.candidates += 1;
        by_entry
            .entry(candidate.entry_id.clone())
            .or_default()
            .push(candidate);
    }

    for (entry_id, candidates) in by_entry {
        report.examined += 1;

        let Ok(current) = vault.get(&entry_id) else {
            // Section 10.4 step 8: the entry was deleted elsewhere while this
            // was waiting. Delete is absolute, and a kept candidate would
            // block an entry that no longer exists.
            vault.store().clear_reconcile(&entry_id)?;
            report.orphaned += 1;
            continue;
        };

        let mut largest_counter = current.payload.as_otp().and_then(|entry| entry.counter);
        let mut newest_hlc = current.hlc;
        let mut is_hotp = matches!(current.payload, Payload::Hotp(_));

        for candidate in &candidates {
            // A candidate whose timestamp is unknown — carried over from
            // schema version 2 — still contributes its counter. Only the
            // timestamp is missing.
            if let Some(hlc) = candidate.hlc
                && hlc > newest_hlc
            {
                newest_hlc = hlc;
            }

            let Ok(payload) = vault.open_record(&entry_id, &candidate.ciphertext, &candidate.nonce)
            else {
                // A candidate that will not open cannot be compared. Skipping
                // it is better than blocking the entry forever; the others
                // still count.
                continue;
            };

            if matches!(payload, Payload::Hotp(_)) {
                is_hotp = true;
            }
            if let Some(counter) = counter_of(&payload)
                && largest_counter.is_none_or(|kept| counter > kept)
            {
                largest_counter = Some(counter);
            }
        }

        let current_counter = current.payload.as_otp().and_then(|entry| entry.counter);
        let needs_raise = is_hotp
            && match (current_counter, largest_counter) {
                (Some(kept), Some(largest)) => largest > kept,
                (None, Some(_)) => false,
                _ => false,
            };

        if needs_raise && let Some(counter) = largest_counter {
            let mut payload = current.payload.clone();
            if let Payload::Hotp(entry) = &mut payload {
                entry.counter = Some(counter);
            }
            vault.write_with_hlc(
                &entry_id,
                &payload,
                corrected_hlc(newest_hlc, device),
                Some(current.hlc),
            )?;
            report.counters_raised += 1;
        } else {
            report.already_correct += 1;
        }

        // Step 9: cleared only now. A crash before this point leaves every
        // candidate for the next unlock.
        vault.store().clear_reconcile(&entry_id)?;
    }

    Ok(report)
}

/// Section 10.4 step 7: the largest candidate timestamp, its counter increased
/// by one, and this device's identifier.
///
/// Just enough to beat the records being corrected, and nothing more. The
/// counter roll into the next millisecond is handled by `advance`.
fn corrected_hlc(largest: Hlc, device: u64) -> Hlc {
    advance(largest.wall_ms, largest.counter, device)
}

fn counter_of(payload: &Payload) -> Option<u64> {
    match payload {
        Payload::Hotp(entry) => entry.counter,
        _ => None,
    }
}

/// True when this entry still has a candidate waiting (section 10.4 step 5).
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
