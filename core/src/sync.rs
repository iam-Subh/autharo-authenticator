//! The sync cycle (PRD sections 10.3, 10.4, 10.6, OFF-09).
//!
//! # It runs while the vault is locked
//!
//! OFF-09, and it shapes everything here: "Push sends ciphertext that already
//! exists, pull stores ciphertext, and conflict resolution reads only the HLC,
//! which is plaintext metadata. No vault key is needed. A sync engine that
//! waits for an unlock leaves a device stale all day."
//!
//! So this module works on [`Store`] and never on `Vault`. There is no cipher
//! here and no way to obtain one, which is a property worth keeping: a future
//! change that needed to read a payload during sync would not compile.
//!
//! # The one rule that cannot run while locked
//!
//! Section 10.4's HOTP rule — "take the larger counter" — needs the counter,
//! and the counter is inside the ciphertext. That cannot be read while locked,
//! and pretending otherwise would silently take the newer counter instead of
//! the larger one, which produces codes the issuer has already rejected.
//!
//! The resolution follows section 10.4's five steps. The part that is easy to
//! get wrong is step 2: the reconcile record must keep the **discarded
//! ciphertext**, not just the entry identifier. The winning record replaces
//! the loser in the entry table, so an identifier alone would leave the other
//! counter existing nowhere, and the reconcile step at unlock would have
//! nothing to compare — silently keeping whatever the HLC chose, which is the
//! outcome the rule exists to prevent.
//!
//! Both directions are recorded. When the remote wins, the local record is the
//! discarded one; when the local wins, the remote is. The counter rule takes
//! the larger value regardless of which HLC was higher, so the losing side is
//! worth keeping either way.
//!
//! Applying it needs a key, so it lives in [`crate::reconcile`] rather than
//! here. This module stays free of `Vault`.

use core::fmt;
use std::collections::BTreeSet;

use crate::hlc::{DriftOutcome, Hlc, HlcClock, clamp_drift};
use crate::store::{Record, Store, StoreError};

/// A record as it travels to and from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRecord {
    pub entry_id: String,
    /// `None` for a tombstone.
    pub ciphertext: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub hlc: Hlc,
    pub deleted: bool,
    /// Set by the server on the way out; ignored on the way in.
    pub server_seq: i64,
}

/// One record being pushed, with the revision the device last saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRecord {
    pub entry_id: String,
    pub ciphertext: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub hlc: Hlc,
    pub deleted: bool,
    pub base_hlc: Option<Hlc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResponse {
    pub records: Vec<WireRecord>,
    pub cursor: i64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushResponse {
    pub accepted: Vec<String>,
    /// What the server holds for each rejected entry, so the client can
    /// resolve without a second round trip (section 10.3 step 6).
    pub conflicts: Vec<WireRecord>,
}

/// Why a cycle stopped.
#[derive(Debug)]
pub enum SyncError {
    /// Section 10.4: the cursor is at or below the prune watermark, so this
    /// device may have missed a delete that has since been pruned. Only a full
    /// re-sync is correct.
    CursorTooOld,
    /// The session is over. Retrying with the same token loops forever — the
    /// caller has to sign in again.
    ///
    /// Its own variant for the same reason [`Self::CursorTooOld`] has one: the
    /// action it calls for is different from a retry, and a client that cannot
    /// tell them apart does the wrong one indefinitely.
    Unauthorized,
    /// The network, or the server. Retried with backoff by the caller (OFF-06).
    Transport {
        detail: String,
    },
    Store(StoreError),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CursorTooOld => f.write_str(
                "This device is too far behind to catch up incrementally and \
                 needs a full re-sync.",
            ),
            Self::Unauthorized => {
                f.write_str("This device has been signed out. Sign in again to keep syncing.")
            }
            Self::Transport { detail } => {
                write!(f, "The sync server could not be reached: {detail}")
            }
            Self::Store(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<StoreError> for SyncError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

type Result<T> = core::result::Result<T, SyncError>;

/// How the cycle reaches the server.
///
/// A trait so the property harness can drive the same engine over an in-memory
/// server with partitions and dropped responses. A harness that exercised a
/// second, similar engine would prove something about the harness.
pub trait SyncTransport {
    fn pull(&mut self, since: i64, limit: i64, mode: PullMode) -> Result<PullResponse>;
    fn push(&mut self, records: &[PushRecord]) -> Result<PushResponse>;
}

/// Why the client is asking for changes.
///
/// # Why the server has to be told
///
/// Section 10.6's watermark check exists to tell a *lagging* client that it may
/// have missed a delete which has since been pruned. It compares the cursor the
/// client saved against the watermark.
///
/// A full re-sync walks up from zero, so every cursor after the first page is
/// below the watermark by construction — not because the client is behind, but
/// because it is halfway through reading everything. Applying the check to those
/// refuses page two of every re-sync on any vault larger than one page, and the
/// re-sync then cannot complete: it fails before it stores a cursor, so the next
/// attempt starts from the same place and fails identically. The device never
/// syncs again, and nothing says so.
///
/// A missed delete cannot matter to a re-sync in any case. It is rebuilding from
/// nothing, and drops whatever the server does not have.
///
/// The property harness found this at forty thousand operations, once the vault
/// crossed five hundred records — one more than a page. Below that, a re-sync is
/// a single request from zero, never trips the check, and works.
///
/// A parameter rather than a second method, so that no transport can be written
/// that forgets to distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullMode {
    /// Resuming from the cursor this device saved. The watermark check applies.
    Incremental,
    /// Rebuilding local state from nothing (section 10.6). The watermark check
    /// does not apply, and must not.
    FullResync,
}

/// What one cycle did. Returned rather than logged, so a test can assert on it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CycleReport {
    pub pulled: usize,
    /// Records the local database took from the server.
    pub applied: usize,
    /// Records the server sent that lost to a local write.
    pub rejected: usize,
    pub pushed: usize,
    pub conflicts: usize,
    /// Incoming timestamps clamped by section 10.2's drift bound.
    pub clamped: usize,
    pub cursor: i64,
}

/// The maximum records per pull, matching the server's own limit.
const PULL_LIMIT: i64 = 500;

/// Runs one cycle of section 10.3.
///
/// The order is the one in the specification: pull, apply, store the cursor,
/// then drain the outbox. Pulling first means a push that conflicts has
/// already seen the server's version, so most conflicts resolve without the
/// retry in step 6.
pub fn run_cycle<T: SyncTransport>(
    store: &mut Store,
    clock: &mut HlcClock,
    transport: &mut T,
    now_ms: u64,
) -> Result<CycleReport> {
    let mut report = CycleReport::default();

    // Steps 1 to 3: pull, apply, store the cursor.
    let mut cursor = store.cursor()?;
    loop {
        let response = transport.pull(cursor, PULL_LIMIT, PullMode::Incremental)?;
        report.pulled += response.records.len();

        for incoming in &response.records {
            match apply_remote(store, clock, incoming, now_ms)? {
                Applied::Took { clamped } => {
                    report.applied += 1;
                    if clamped {
                        report.clamped += 1;
                    }
                }
                Applied::Kept => report.rejected += 1,
            }
        }

        cursor = response.cursor;
        store.set_cursor(cursor)?;
        report.cursor = cursor;

        if !response.has_more {
            break;
        }
    }

    // Steps 4 to 7: drain the outbox.
    let outbox = store.outbox()?;
    if !outbox.is_empty() {
        let mut batch = Vec::with_capacity(outbox.len());
        for item in &outbox {
            let Some(record) = store.get(&item.entry_id)? else {
                continue; // Removed by a full re-sync between read and push.
            };
            batch.push(PushRecord {
                entry_id: record.id.clone(),
                ciphertext: none_if_empty(&record.ciphertext),
                nonce: none_if_empty(&record.nonce),
                hlc: record.hlc,
                deleted: record.deleted,
                base_hlc: item.base_hlc,
            });
        }

        if !batch.is_empty() {
            // A push that never reached the server counts against every record
            // it carried (OFF-06). The count is what makes a record that keeps
            // failing distinguishable from a device that is merely offline:
            // the second clears on the next success, the first does not, and
            // only the first is a defect.
            //
            // Recorded before the error propagates, because `?` on the line
            // below leaves the cycle immediately.
            let response = match transport.push(&batch) {
                Ok(response) => response,
                Err(error) => {
                    for item in &batch {
                        store.outbox_record_attempt(&item.entry_id, now_ms as i64)?;
                    }
                    return Err(error);
                }
            };
            report.pushed += response.accepted.len();
            report.conflicts += response.conflicts.len();

            // Step 6: resolve what the server rejected, then retry once. The
            // retry is deliberately not a loop — a conflict that survives one
            // resolution is a disagreement the next cycle should look at with
            // fresh state rather than something to spin on.
            let mut retry = Vec::new();
            for conflict in &response.conflicts {
                if let Applied::Kept = apply_remote(store, clock, conflict, now_ms)?
                    && let Some(record) = store.get(&conflict.entry_id)?
                {
                    retry.push(PushRecord {
                        entry_id: record.id.clone(),
                        ciphertext: none_if_empty(&record.ciphertext),
                        nonce: none_if_empty(&record.nonce),
                        hlc: record.hlc,
                        deleted: record.deleted,
                        base_hlc: Some(conflict.hlc),
                    });
                }
            }

            let mut accepted = response.accepted;
            if !retry.is_empty() {
                let second = transport.push(&retry)?;
                report.pushed += second.accepted.len();
                accepted.extend(second.accepted);
            }

            store.outbox_clear(&accepted)?;
        }
    }

    Ok(report)
}

/// What happened to one incoming record.
enum Applied {
    /// The remote record won and was written.
    Took { clamped: bool },
    /// The local record won and was kept.
    Kept,
}

/// Section 10.4's rules, using only the HLC.
///
/// The delete rule and the HLC comparison both work on plaintext metadata, so
/// they run while locked. The HOTP counter rule cannot — see the module
/// documentation — so an entry resolved here is recorded for reconciliation.
fn apply_remote(
    store: &mut Store,
    clock: &mut HlcClock,
    incoming: &WireRecord,
    now_ms: u64,
) -> Result<Applied> {
    // Section 10.2: bound the forward drift before the value is used for
    // anything, including the comparison below. A remote clock an hour ahead
    // must not win on the strength of being wrong.
    let (hlc, drift) = clamp_drift(incoming.hlc, now_ms);
    let clamped = matches!(drift, DriftOutcome::Clamped { .. });

    // Fold the remote time into the local clock so this device's next write
    // sorts after what it has seen.
    clock.observe(hlc, now_ms);

    let local = store.get(&incoming.entry_id)?;

    let take = match &local {
        None => true,
        Some(current) => {
            if current.deleted != incoming.deleted {
                // Section 10.4: "The delete wins." Regardless of HLC — a
                // resurrection is worse than a lost edit, because the user
                // asked for the entry to be gone from every device.
                incoming.deleted
            } else {
                // Higher HLC wins; the device identifier inside it breaks a
                // tie, which is why `Hlc` orders on all three parts.
                hlc > current.hlc
            }
        }
    };

    // An incoming record carrying the timestamp the local one already has is
    // not a rival version of the entry: it *is* the local version, coming back.
    // That happens on every ordinary cycle, because a push does not move the
    // cursor, so the next pull returns what this device just sent.
    //
    // Recording it as a discarded candidate would be quietly destructive. A
    // pending candidate stops the entry producing a code (section 10.4 step 5),
    // so every HOTP entry this device had pushed would refuse to produce one
    // until the next unlock — and on a device that is never locked, refuse
    // permanently. Nothing about it would look wrong: the records agree, the
    // counters agree, and the codes simply stop.
    let same_version = local
        .as_ref()
        .is_some_and(|current| current.hlc == hlc && current.deleted == incoming.deleted);

    if !take {
        // The local record won. The remote is discarded — and may hold the
        // larger counter, which the HLC comparison above cannot see.
        if let Some(ciphertext) = &incoming.ciphertext
            && !incoming.deleted
            && !same_version
        {
            store.record_reconcile(
                &incoming.entry_id,
                ciphertext,
                incoming.nonce.as_deref().unwrap_or(&[]),
                // The clamped value, not the raw one: a candidate keeps the
                // timestamp it would have been stored under.
                hlc,
                now_ms as i64,
            )?;
        }
        return Ok(Applied::Kept);
    }

    // The remote record won, so the local one is about to be overwritten.
    // Keep it before that happens: after `apply_remote` it is gone.
    if let Some(current) = &local
        && !current.deleted
        && !incoming.deleted
        && !current.ciphertext.is_empty()
    {
        store.record_reconcile(
            &incoming.entry_id,
            &current.ciphertext,
            &current.nonce,
            current.hlc,
            now_ms as i64,
        )?;
    }

    store.apply_remote(&Record {
        id: incoming.entry_id.clone(),
        ciphertext: incoming.ciphertext.clone().unwrap_or_default(),
        nonce: incoming.nonce.clone().unwrap_or_default(),
        hlc,
        deleted: incoming.deleted,
        server_seq: Some(incoming.server_seq),
        updated_at: now_ms as i64,
    })?;

    Ok(Applied::Took { clamped })
}

/// Section 10.6: rebuild the local state from the server after the cursor has
/// become unusable.
///
/// Used after [`SyncError::CursorTooOld`] and on a device joining an existing
/// vault.
///
/// # Why this is not a wholesale replacement
///
/// It was one, and it lost data. A cursor goes stale because the device has
/// been away, and a device that has been away is exactly the one with local
/// changes still waiting in the outbox. Replacing every record with the
/// server's threw those away — and for a delete that meant the tombstone
/// vanished and the server's live copy came back, which section 10.4 forbids
/// outright: "the delete wins". Nothing announced it. The entry the user
/// deleted was simply there again the next time they looked.
///
/// So the server's records go through the same rules a normal cycle uses,
/// including the reconcile bookkeeping, and a local record is dropped only if
/// the server does not have it *and* this device is not waiting to push it.
///
/// The user-facing **Wipe and re-download** is the wholesale one, and calls
/// [`Store::replace_all`] directly. There the user has asked for the server's
/// copy and nothing else.
pub fn full_resync<T: SyncTransport>(
    store: &mut Store,
    clock: &mut HlcClock,
    transport: &mut T,
    now_ms: u64,
) -> Result<usize> {
    let mut all = Vec::new();
    let mut cursor = 0;

    loop {
        let response = transport.pull(cursor, PULL_LIMIT, PullMode::FullResync)?;
        cursor = response.cursor;
        let has_more = response.has_more;
        all.extend(response.records);

        if !has_more {
            break;
        }
    }

    let held_by_server: BTreeSet<&str> = all.iter().map(|r| r.entry_id.as_str()).collect();
    let pending: BTreeSet<String> = store
        .outbox()?
        .into_iter()
        .map(|item| item.entry_id)
        .collect();

    // Anything the server has never heard of that this device is not about to
    // tell it about is a leftover of the gap in the cursor, and goes.
    let stale: Vec<String> = store
        .list(true)?
        .into_iter()
        .filter(|record| {
            !held_by_server.contains(record.id.as_str()) && !pending.contains(&record.id)
        })
        .map(|record| record.id)
        .collect();
    store.forget_entries(&stale)?;

    let count = all.len();
    for incoming in &all {
        apply_remote(store, clock, incoming, now_ms)?;
    }
    store.set_cursor(cursor)?;
    Ok(count)
}

/// Entries whose conflict was decided by HLC alone and still need section
/// 10.4's counter rule applied. See [`crate::reconcile`] for applying them.
///
/// One name per entry, however many candidates it holds. A single cycle can
/// record two for the same entry — once when the pulled record is compared,
/// and again when the push comes back as a conflict and is compared a second
/// time — and both are kept, because either could hold the larger counter.
/// The caller wants to know which entries are waiting, not how many
/// comparisons happened.
pub fn needs_counter_reconcile(store: &Store) -> core::result::Result<Vec<String>, StoreError> {
    let mut names: Vec<String> = store
        .reconcile_pending()?
        .into_iter()
        .map(|record| record.entry_id)
        .collect();
    names.dedup();
    Ok(names)
}

fn none_if_empty(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}
