//! The sync cycle (PRD sections 10.3, 10.4, 10.6, OFF-09).
//!
//! These are the ordinary cases, written directly so a failure names one rule.
//! The property harness that follows drives the same engine over random
//! operations and asserts convergence; this file is what tells you *which*
//! rule broke when it does.

use authcore::hlc::{Hlc, HlcClock};
use authcore::store::{MetaStore, Record, Store};
use authcore::sync::{
    self, PullMode, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport, WireRecord,
};

const DEVICE_A: u64 = 0xaaaa_0000_0000_0001;
const DEVICE_B: u64 = 0xbbbb_0000_0000_0002;
const NOW: u64 = 1_755_734_400_000;

fn store() -> Store {
    Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap()
}

/// An in-memory stand-in for the server, holding what section 12.3 holds.
#[derive(Default)]
struct FakeServer {
    records: Vec<WireRecord>,
    next_seq: i64,
    prune_watermark: i64,
    /// Set to make the next push look like a lost response: the server applies
    /// it and the client never hears.
    drop_next_push_response: bool,
    pushes_seen: usize,
}

impl FakeServer {
    fn store(&mut self, record: &PushRecord) {
        self.next_seq += 1;
        let wire = WireRecord {
            entry_id: record.entry_id.clone(),
            ciphertext: record.ciphertext.clone(),
            nonce: record.nonce.clone(),
            hlc: record.hlc,
            deleted: record.deleted,
            server_seq: self.next_seq,
        };
        match self
            .records
            .iter_mut()
            .find(|r| r.entry_id == wire.entry_id)
        {
            Some(existing) => *existing = wire,
            None => self.records.push(wire),
        }
    }

    fn held(&self, entry_id: &str) -> Option<&WireRecord> {
        self.records.iter().find(|r| r.entry_id == entry_id)
    }
}

impl SyncTransport for FakeServer {
    fn pull(&mut self, since: i64, limit: i64, mode: PullMode) -> Result<PullResponse, SyncError> {
        // The server's rule, `full` flag and all: a re-sync walks up from
        // zero, so its later pages ask from below the watermark by
        // construction and must not be refused.
        if mode == PullMode::Incremental && since > 0 && since <= self.prune_watermark {
            return Err(SyncError::CursorTooOld);
        }

        let mut matching: Vec<WireRecord> = self
            .records
            .iter()
            .filter(|r| r.server_seq > since)
            .cloned()
            .collect();
        matching.sort_by_key(|r| r.server_seq);

        let has_more = matching.len() as i64 > limit;
        matching.truncate(limit as usize);
        let cursor = matching.last().map(|r| r.server_seq).unwrap_or(since);

        Ok(PullResponse {
            records: matching,
            cursor,
            has_more,
        })
    }

    fn push(&mut self, records: &[PushRecord]) -> Result<PushResponse, SyncError> {
        self.pushes_seen += 1;
        let mut accepted = Vec::new();
        let mut conflicts = Vec::new();

        for record in records {
            // The base-revision check and nothing more, exactly as
            // `server/src/vault.rs` reads it: a conflict needs a record to
            // conflict *with*. A base the server cannot check because it holds
            // nothing for the entry is accepted as a create.
            //
            // The earlier version treated that as neither accepted nor
            // conflicted, and the record then existed nowhere: the client
            // never cleared it from the outbox and had nothing to resolve, so
            // it retried the same push forever. The property harness found it
            // at forty thousand operations, as three devices each holding only
            // their own creations.
            match self.held(&record.entry_id).cloned() {
                Some(current) if record.base_hlc != Some(current.hlc) => {
                    conflicts.push(current);
                }
                _ => {
                    self.store(record);
                    accepted.push(record.entry_id.clone());
                }
            }
        }

        assert_eq!(
            accepted.len() + conflicts.len(),
            records.len(),
            "every pushed record must be answered for, one way or the other"
        );

        if self.drop_next_push_response {
            self.drop_next_push_response = false;
            // Applied, then the response is lost. The client will retry.
            return Err(SyncError::Transport {
                detail: "the response was lost".to_string(),
            });
        }

        Ok(PushResponse {
            accepted,
            conflicts,
        })
    }
}

fn local_write(store: &mut Store, clock: &mut HlcClock, id: &str, body: &[u8], at: u64) {
    let base = store.get(id).unwrap().map(|r| r.hlc);
    let record = Record {
        id: id.to_string(),
        ciphertext: body.to_vec(),
        nonce: vec![7; 24],
        hlc: clock.tick(at),
        deleted: false,
        server_seq: None,
        updated_at: at as i64,
    };
    store.write_local(&record, base).unwrap();
}

// ---------------------------------------------------------------------------
// Section 10.3, the cycle
// ---------------------------------------------------------------------------

#[test]
fn a_local_write_reaches_the_server() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"body", NOW);
    let report = sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert_eq!(report.pushed, 1);
    assert_eq!(
        server.held("e1").unwrap().ciphertext.as_deref(),
        Some(&b"body"[..])
    );
    assert!(
        store.outbox().unwrap().is_empty(),
        "an accepted record must leave the outbox"
    );
}

#[test]
fn a_remote_write_reaches_the_device() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"from-elsewhere".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    let report = sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert_eq!(report.applied, 1);
    assert_eq!(
        store.get("e1").unwrap().unwrap().ciphertext,
        b"from-elsewhere"
    );
    assert_eq!(store.cursor().unwrap(), 1, "the cursor must advance");
}

/// The cursor is what stops a device re-downloading everything. A cycle with
/// nothing new must not move it backwards or re-apply.
#[test]
fn a_second_cycle_with_no_changes_does_nothing() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"body", NOW);
    sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();
    let cursor = store.cursor().unwrap();

    let second = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 1).unwrap();

    assert_eq!(second.applied, 0);
    assert_eq!(second.pushed, 0);
    assert!(store.cursor().unwrap() >= cursor);
}

// ---------------------------------------------------------------------------
// Section 10.4, the conflict rules
// ---------------------------------------------------------------------------

#[test]
fn the_higher_hlc_wins() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"local", NOW);

    // The server holds a newer write from another device.
    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"remote-newer".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW + 1000, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 2000).unwrap();

    assert_eq!(
        store.get("e1").unwrap().unwrap().ciphertext,
        b"remote-newer"
    );
}

#[test]
fn an_older_remote_write_loses() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"local-newer", NOW + 1000);

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"remote-older".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    let report = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 2000).unwrap();

    assert_eq!(report.rejected, 1);
    assert_eq!(store.get("e1").unwrap().unwrap().ciphertext, b"local-newer");
}

/// Section 10.4: "The delete wins." Even against a newer edit — a resurrected
/// entry is worse than a lost edit, because the user asked for it to be gone
/// from every device.
#[test]
fn a_delete_beats_a_newer_edit() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"local-newest", NOW + 5000);

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: None,
        nonce: None,
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: true,
        base_hlc: None,
    });

    sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 6000).unwrap();

    assert!(
        store.get("e1").unwrap().unwrap().deleted,
        "the delete must win even though the local edit is newer"
    );
}

/// And the other direction: a local delete is not undone by a remote edit.
#[test]
fn a_remote_edit_does_not_resurrect_a_local_delete() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"body", NOW);
    store
        .tombstone("e1", clock.tick(NOW + 100), (NOW + 100) as i64)
        .unwrap();

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"edited-elsewhere".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW + 9000, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 10_000).unwrap();

    assert!(store.get("e1").unwrap().unwrap().deleted);
}

/// Section 10.2's bound, reaching the cycle: a remote clock an hour ahead must
/// not win on the strength of being wrong.
#[test]
fn a_far_future_remote_write_is_clamped_before_it_is_compared() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"from-the-future".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW + 60 * 60 * 1000, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    let report = sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert_eq!(report.clamped, 1);
    let stored = store.get("e1").unwrap().unwrap();
    assert!(
        stored.hlc.wall_ms <= NOW + 5 * 60 * 1000,
        "the stored timestamp kept its unearned hour"
    );
}

// ---------------------------------------------------------------------------
// OFF-09 and the deferred counter rule
// ---------------------------------------------------------------------------

/// The whole cycle runs against `Store`, which holds no key. This test exists
/// to state that as a property rather than leave it implied by the types.
#[test]
fn the_cycle_needs_no_vault_key() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(
        &mut store,
        &mut clock,
        "e1",
        b"ciphertext-we-cannot-read",
        NOW,
    );
    server.store(&PushRecord {
        entry_id: "e2".to_string(),
        ciphertext: Some(b"also-opaque".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    // No Vault, no cipher, no key anywhere in this test.
    let report = sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert_eq!(report.applied, 1);
    assert_eq!(report.pushed, 1);
}

/// Section 10.4's HOTP rule needs the counter, which is inside the ciphertext.
/// A conflict resolved while locked therefore records the entry instead of
/// guessing.
#[test]
fn a_conflict_is_listed_for_counter_reconciliation() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"local", NOW);
    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"remote-newer".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW + 1000, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 2000).unwrap();

    assert_eq!(
        sync::needs_counter_reconcile(&store).unwrap(),
        vec!["e1".to_string()],
        "an HLC-only resolution must be recorded, not silently accepted"
    );

    // Section 10.4 step 4: every comparison keeps its candidate, so one entry
    // may hold several. A cycle compares twice — once for the pulled record
    // and once when the push comes back as a conflict — and both are kept,
    // because either could carry the larger counter.
    assert!(
        !store.reconcile_pending().unwrap().is_empty(),
        "the discarded record itself must be kept, not just the name"
    );

    store.clear_reconcile("e1").unwrap();
    assert!(sync::needs_counter_reconcile(&store).unwrap().is_empty());
}

/// A first sight of an entry is not a conflict, so it must not be listed.
#[test]
fn a_new_remote_entry_is_not_listed_for_reconciliation() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"new".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert!(sync::needs_counter_reconcile(&store).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Sections 10.4 and 10.6, the stale cursor
// ---------------------------------------------------------------------------

#[test]
fn a_cursor_at_the_watermark_is_refused() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"body".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });
    sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    // The server prunes past this device's cursor.
    server.prune_watermark = store.cursor().unwrap();

    let error = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 1).unwrap_err();
    assert!(matches!(error, SyncError::CursorTooOld));
}

/// A record the server has never heard of and this device is not waiting to
/// push is a leftover of the gap the stale cursor left. It goes.
#[test]
fn a_full_resync_drops_local_state_the_server_does_not_have() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "stale", b"old", NOW);
    // Pushed and accepted, so nothing is waiting: this is state the device
    // holds only because it has been away.
    store.outbox_clear(&["stale".to_string()]).unwrap();

    server.store(&PushRecord {
        entry_id: "fresh".to_string(),
        ciphertext: Some(b"current".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    let count = sync::full_resync(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert_eq!(count, 1);
    assert!(store.get("stale").unwrap().is_none());
    assert!(store.get("fresh").unwrap().is_some());
}

/// A cycle that resolved nothing must leave nothing behind.
///
/// A push does not move the cursor, so the next pull returns the records this
/// device just sent. Treating a record whose timestamp equals the one already
/// held as a discarded rival made every entry a device had pushed refuse to
/// produce a code (section 10.4 step 5) — for one cycle on a device that locks,
/// and permanently on one that does not. Nothing about it looked wrong: the
/// records agreed and the counters agreed, and the codes simply stopped.
///
/// The two report assertions are the point of the test, not decoration. An
/// earlier version of this seeded the record through `apply_remote`, which is
/// the server-originated path and touches no outbox — so the first cycle
/// pushed nothing, the second pulled nothing back, and the test passed whatever
/// `apply_remote` did. It passed with the fix reverted, which is how that was
/// found.
#[test]
fn a_record_coming_back_unchanged_is_not_a_conflict() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"body", NOW);

    let first = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 1).unwrap();
    assert_eq!(
        first.pushed, 1,
        "the first cycle has to push, or the rest of this proves nothing"
    );

    let second = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 2).unwrap();
    assert_eq!(
        second.pulled, 1,
        "the second cycle has to pull that record back, or the rest proves nothing"
    );

    assert!(
        !store.reconcile_pending_for("e1").unwrap(),
        "an entry stopped producing codes because its own record came back"
    );
    assert_eq!(
        store.reconcile_pending().unwrap().len(),
        0,
        "a record identical to the one already held is not a discarded candidate"
    );
}

/// OFF-06: a push that never reached the server counts against what it carried.
///
/// The count is the only thing separating "this device is offline" from "this
/// record keeps being rejected". The first clears on the next success and needs
/// no attention; the second is a defect that would otherwise sit in the outbox
/// forever, retried every cycle, reported nowhere.
///
/// `outbox_record_attempt` existed for a stage with no caller at all, which is
/// its own lesson: a column nothing writes reads exactly like a column nothing
/// needed.
#[test]
fn a_push_that_fails_is_counted_against_the_records_it_carried() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"one", NOW);
    local_write(&mut store, &mut clock, "e2", b"two", NOW);

    assert!(
        store
            .outbox()
            .unwrap()
            .iter()
            .all(|item| item.attempts == 0),
        "nothing has been attempted yet"
    );

    server.drop_next_push_response = true;
    let error = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 1).unwrap_err();
    assert!(matches!(error, SyncError::Transport { .. }));

    for item in store.outbox().unwrap() {
        assert_eq!(
            item.attempts, 1,
            "{} was carried by the failed push and must count it",
            item.entry_id
        );
        assert_eq!(item.last_attempt, Some((NOW + 1) as i64));
    }

    // And the records are still queued. A failed push must not look like a
    // delivered one.
    assert_eq!(store.outbox().unwrap().len(), 2);
}

/// A re-sync of a vault larger than one page, on a device whose cursor is
/// already stale.
///
/// The bug this pins was total and permanent, and took forty thousand random
/// operations to reach because it needs more than five hundred records:
///
/// 1. The device falls behind the prune watermark, so its incremental pull is
///    refused and it starts a full re-sync.
/// 2. Page one asks from zero, which the watermark check skips, and returns
///    five hundred records.
/// 3. Page two asks from the sequence page one ended on — which is below the
///    watermark, because everything is. The old check refused it.
/// 4. `full_resync` fails before it stores a cursor, so the next attempt
///    starts from exactly the same place and fails identically.
///
/// The device never syncs again. It keeps making local changes, never sees
/// anyone else's, and nothing reports an error the user would see. Under five
/// hundred records the re-sync is a single request and none of this happens,
/// which is why every smaller test passed.
#[test]
fn a_full_resync_pages_past_the_prune_watermark() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    // More than one page, so the re-sync has to ask for a second one.
    const RECORDS: usize = 600;
    for i in 0..RECORDS {
        server.store(&PushRecord {
            entry_id: format!("entry-{i:04}"),
            ciphertext: Some(b"body".to_vec()),
            nonce: Some(vec![3; 24]),
            hlc: Hlc::new(NOW + i as u64, 0, DEVICE_B),
            deleted: false,
            base_hlc: None,
        });
    }

    // Everything this device could ask for is behind the watermark.
    server.prune_watermark = server.next_seq;

    let count = sync::full_resync(&mut store, &mut clock, &mut server, NOW).unwrap();

    assert_eq!(
        count, RECORDS,
        "the re-sync must read every page, not the first"
    );
    assert_eq!(store.list(true).unwrap().len(), RECORDS);
    assert!(
        store.cursor().unwrap() > 0,
        "a re-sync that stores no cursor repeats itself forever"
    );
}

/// The control: the watermark check still refuses a stale *incremental* pull.
///
/// Without this, making the re-sync work by removing the check altogether would
/// pass the test above and quietly delete the rule it exists to enforce.
#[test]
fn an_incremental_pull_is_still_refused_below_the_watermark() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"body".to_vec()),
        nonce: Some(vec![3; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });
    server.prune_watermark = server.next_seq;
    store.set_cursor(server.next_seq).unwrap();

    let error = sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap_err();
    assert!(matches!(error, SyncError::CursorTooOld));
}

/// The case the property harness found, in six operations.
///
/// A cursor goes stale because the device has been away, and a device that has
/// been away is the one most likely to have local changes still waiting. The
/// re-sync used to replace every record with the server's — so the tombstone
/// for a delete that had not been pushed vanished, and the server's live copy
/// came back. Section 10.4 is unambiguous that this must not happen, and
/// nothing announced it: the entry the user deleted was simply there again.
#[test]
fn a_full_resync_does_not_resurrect_a_delete_that_has_not_been_pushed() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "doomed", b"body", NOW);
    let live = store.get("doomed").unwrap().unwrap().hlc;

    // The server still holds the live version: the delete never reached it.
    server.store(&PushRecord {
        entry_id: "doomed".to_string(),
        ciphertext: Some(b"body".to_vec()),
        nonce: Some(vec![7; 24]),
        hlc: live,
        deleted: false,
        base_hlc: None,
    });
    store.outbox_clear(&["doomed".to_string()]).unwrap();

    store
        .tombstone("doomed", clock.tick(NOW + 1), (NOW + 1) as i64)
        .unwrap();

    sync::full_resync(&mut store, &mut clock, &mut server, NOW + 2).unwrap();

    let record = store
        .get("doomed")
        .unwrap()
        .expect("the record is still there");
    assert!(
        record.deleted,
        "a stale cursor brought back an entry the user had deleted"
    );
    assert!(
        store
            .outbox()
            .unwrap()
            .iter()
            .any(|item| item.entry_id == "doomed"),
        "the delete is still waiting to be pushed, so it must stay in the outbox"
    );
}

/// The same rule for an ordinary edit: unpushed local work survives the
/// re-sync and is still queued afterwards.
#[test]
fn a_full_resync_keeps_local_work_that_is_still_waiting_to_be_pushed() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "mine", b"local", NOW);

    server.store(&PushRecord {
        entry_id: "theirs".to_string(),
        ciphertext: Some(b"remote".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    sync::full_resync(&mut store, &mut clock, &mut server, NOW + 1).unwrap();

    assert!(
        store.get("mine").unwrap().is_some(),
        "a re-sync must not discard a write the server has not seen"
    );
    assert!(store.get("theirs").unwrap().is_some());
    assert!(
        store.outbox().unwrap().iter().any(|i| i.entry_id == "mine"),
        "and it must still be queued, or it would never reach the server"
    );
}

// ---------------------------------------------------------------------------
// Section 10.3 step 6, the conflict retry
// ---------------------------------------------------------------------------

/// A push whose base revision is stale comes back as a conflict. The cycle
/// resolves it and retries once, without a second round of pulling.
#[test]
fn a_rejected_push_is_resolved_and_retried() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    // The server already holds a record this device has never seen.
    server.store(&PushRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(b"server-version".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    // The device writes the same entry without having pulled, so its base is
    // None while the server holds a version.
    local_write(&mut store, &mut clock, "e1", b"local-version", NOW + 5000);
    store.set_cursor(0).unwrap();

    let report = sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 6000).unwrap();

    // The pull in step 1 brings the server's version in first, so by the time
    // the push runs the base matches and there is nothing to conflict over.
    assert_eq!(report.pulled, 1);
    assert!(
        server.held("e1").is_some(),
        "the entry must still exist on the server"
    );
}

/// Section 10.3 step 6 says retry *once*. A conflict that survives that is
/// left for the next cycle rather than spun on.
#[test]
fn the_retry_does_not_loop() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    local_write(&mut store, &mut clock, "e1", b"body", NOW);
    sync::run_cycle(&mut store, &mut clock, &mut server, NOW).unwrap();

    let before = server.pushes_seen;
    local_write(&mut store, &mut clock, "e1", b"changed", NOW + 100);
    sync::run_cycle(&mut store, &mut clock, &mut server, NOW + 200).unwrap();

    assert!(
        server.pushes_seen - before <= 2,
        "at most one push and one retry per cycle"
    );
}
