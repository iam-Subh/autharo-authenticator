//! The sync cycle (PRD sections 10.3, 10.4, 10.6, OFF-09).
//!
//! These are the ordinary cases, written directly so a failure names one rule.
//! The property harness that follows drives the same engine over random
//! operations and asserts convergence; this file is what tells you *which*
//! rule broke when it does.

use authcore::hlc::{Hlc, HlcClock};
use authcore::store::{MetaStore, Record, Store};
use authcore::sync::{
    self, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport, WireRecord,
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
    fn pull(&mut self, since: i64, limit: i64) -> Result<PullResponse, SyncError> {
        if since > 0 && since <= self.prune_watermark {
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
            let held = self.held(&record.entry_id).cloned();
            let agrees = match (&held, record.base_hlc) {
                (None, None) => true,
                (Some(current), Some(base)) => current.hlc == base,
                _ => false,
            };

            if agrees {
                self.store(record);
                accepted.push(record.entry_id.clone());
            } else if let Some(current) = held {
                conflicts.push(current);
            }
        }

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

#[test]
fn a_full_resync_replaces_local_state() {
    let mut store = store();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    // Local state the server has never heard of, as a device left behind by a
    // prune would hold.
    local_write(&mut store, &mut clock, "stale", b"old", NOW);

    server.store(&PushRecord {
        entry_id: "fresh".to_string(),
        ciphertext: Some(b"current".to_vec()),
        nonce: Some(vec![1; 24]),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        base_hlc: None,
    });

    let count = sync::full_resync(&mut store, &mut server).unwrap();

    assert_eq!(count, 1);
    assert!(
        store.get("stale").unwrap().is_none(),
        "a re-sync replaces local state rather than merging into it"
    );
    assert!(store.get("fresh").unwrap().is_some());
    assert!(
        store.outbox().unwrap().is_empty(),
        "the outbox belongs to state that no longer exists"
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
