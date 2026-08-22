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
//! The resolution is explicit rather than implicit. Every entry whose conflict
//! was decided by HLC alone is recorded in [`Store`]'s reconcile list, and
//! [`needs_counter_reconcile`] reports it. When the vault is next unlocked the
//! caller walks that list and applies the counter rule with the payloads in
//! hand. Deferred, not skipped, and visible in the type.

use core::fmt;

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
    fn pull(&mut self, since: i64, limit: i64) -> Result<PullResponse>;
    fn push(&mut self, records: &[PushRecord]) -> Result<PushResponse>;
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
        let response = transport.pull(cursor, PULL_LIMIT)?;
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
            let response = transport.push(&batch)?;
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

    if !take {
        return Ok(Applied::Kept);
    }

    let had_conflict = local.is_some();

    store.apply_remote(&Record {
        id: incoming.entry_id.clone(),
        ciphertext: incoming.ciphertext.clone().unwrap_or_default(),
        nonce: incoming.nonce.clone().unwrap_or_default(),
        hlc,
        deleted: incoming.deleted,
        server_seq: Some(incoming.server_seq),
        updated_at: now_ms as i64,
    })?;

    // A conflict decided by HLC alone may have picked the newer HOTP counter
    // rather than the larger one. Recorded now, applied when unlocked.
    if had_conflict && !incoming.deleted {
        store.mark_for_counter_reconcile(&incoming.entry_id)?;
    }

    Ok(Applied::Took { clamped })
}

/// Section 10.6: replace every local record with the server's.
///
/// Used after [`SyncError::CursorTooOld`], on a new device, and when the user
/// asks. The replacement is one transaction, so a failure part way leaves the
/// previous state rather than half of each.
pub fn full_resync<T: SyncTransport>(store: &mut Store, transport: &mut T) -> Result<usize> {
    let mut all = Vec::new();
    let mut cursor = 0;

    loop {
        let response = transport.pull(cursor, PULL_LIMIT)?;
        cursor = response.cursor;
        let has_more = response.has_more;

        all.extend(response.records.into_iter().map(|incoming| Record {
            id: incoming.entry_id,
            ciphertext: incoming.ciphertext.unwrap_or_default(),
            nonce: incoming.nonce.unwrap_or_default(),
            hlc: incoming.hlc,
            deleted: incoming.deleted,
            server_seq: Some(incoming.server_seq),
            updated_at: 0,
        }));

        if !has_more {
            break;
        }
    }

    let count = all.len();
    store.replace_all(&all, cursor)?;
    Ok(count)
}

/// Entries whose conflict was decided by HLC alone and may need section
/// 10.4's HOTP counter rule applied once the vault is open.
pub fn needs_counter_reconcile(store: &Store) -> core::result::Result<Vec<String>, StoreError> {
    store.counter_reconcile_list()
}

fn none_if_empty(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}
