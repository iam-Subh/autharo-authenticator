//! The deferred HOTP counter rule (PRD section 10.4, steps 1 to 5).
//!
//! The failure being prevented is specific and quiet. A locked device settles
//! a conflict by HLC, which can keep the *newer* counter rather than the
//! *larger* one. A counter behind the issuer's produces codes the issuer has
//! already rejected — and nothing announces it. The user just finds that their
//! codes stopped working.

use authcore::crypto::{VaultKey, XChaChaCipher};
use authcore::entry::{OtpEntry, Payload};
use authcore::hlc::{Hlc, HlcClock};
use authcore::otp::Algorithm;
use authcore::reconcile;
use authcore::secret::SecretString;
use authcore::store::{MetaStore, Record, Store};
use authcore::sync::{
    self, PullMode, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport, WireRecord,
};
use authcore::vault::Vault;

const DEVICE_A: u64 = 0xaaaa_0000_0000_0001;
const DEVICE_B: u64 = 0xbbbb_0000_0000_0002;
const NOW: u64 = 1_755_734_400_000;
const SECRET: &str = "GEZDGNBVGY3TQOJQ";

fn key() -> VaultKey {
    VaultKey::from_slice(&[0x2Au8; 32]).unwrap()
}

fn vault() -> Vault<XChaChaCipher> {
    Vault::open(
        Store::open_in_memory(MetaStore::open_in_memory().unwrap()).unwrap(),
        XChaChaCipher::new(&key()),
    )
    .unwrap()
}

fn hotp(counter: u64) -> Payload {
    Payload::Hotp(OtpEntry {
        v: 1,
        issuer: Some("Bank".to_string()),
        account: "rupsa".to_string(),
        secret: SecretString::new(SECRET),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        counter: Some(counter),
        folder_id: None,
        icon: None,
        favourite: false,
        order: String::new(),
        created_at: NOW as i64,
        note: String::new(),
        tags: Vec::new(),
        trashed_at: None,
        extra: Default::default(),
    })
}

/// Seals a payload the way another device holding the same vault key would
/// have, so it can be handed to the sync cycle as an incoming record.
fn sealed_elsewhere(entry_id: &str, payload: &Payload) -> (Vec<u8>, Vec<u8>) {
    vault().seal_record(entry_id, payload).unwrap()
}

/// Stores a payload under a chosen identifier, with a chosen timestamp.
///
/// `Vault::add` generates an identifier; these tests need a known one on both
/// sides of a conflict, and need to set the HLC to arrange which side wins.
fn put(vault: &mut Vault<XChaChaCipher>, id: &str, payload: &Payload, hlc: Hlc) {
    let (ciphertext, nonce) = vault.seal_record(id, payload).unwrap();
    vault
        .store_mut()
        .apply_remote(&Record {
            id: id.to_string(),
            ciphertext,
            nonce,
            hlc,
            deleted: false,
            server_seq: None,
            updated_at: NOW as i64,
        })
        .unwrap();
}

#[derive(Default)]
struct FakeServer {
    records: Vec<WireRecord>,
    next_seq: i64,
}

impl FakeServer {
    fn hold(&mut self, record: WireRecord) {
        self.next_seq += 1;
        let mut record = record;
        record.server_seq = self.next_seq;
        self.records.push(record);
    }
}

impl SyncTransport for FakeServer {
    fn pull(
        &mut self,
        since: i64,
        _limit: i64,
        _mode: PullMode,
    ) -> Result<PullResponse, SyncError> {
        let records: Vec<WireRecord> = self
            .records
            .iter()
            .filter(|r| r.server_seq > since)
            .cloned()
            .collect();
        let cursor = records.last().map(|r| r.server_seq).unwrap_or(since);
        Ok(PullResponse {
            records,
            cursor,
            has_more: false,
        })
    }

    fn push(&mut self, _records: &[PushRecord]) -> Result<PushResponse, SyncError> {
        Ok(PushResponse {
            accepted: Vec::new(),
            conflicts: Vec::new(),
        })
    }
}

/// The whole point, in one test.
///
/// The device holds counter 9 with a NEWER timestamp. The other device holds
/// counter 42 with an OLDER one. HLC alone keeps 9 — which is behind the
/// issuer and produces rejected codes. The reconcile must recover 42.
#[test]
fn the_larger_counter_wins_even_though_the_smaller_one_was_newer() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(9),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(42));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });

    // The locked cycle. It keeps the local record on HLC, and records the
    // discarded remote one.
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(9),
        "before reconcile the HLC winner is in place, counter and all"
    );
    assert!(
        reconcile::is_blocked(&vault, "e1").unwrap(),
        "step 3: the entry must not produce a code while this is pending"
    );

    // The unlock path.
    let report = reconcile::run(&mut vault).unwrap();

    assert_eq!(report.counters_raised, 1);
    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(42),
        "the larger counter must survive, whichever HLC was higher"
    );
    assert!(!reconcile::is_blocked(&vault, "e1").unwrap());
}

/// The same conflict, on a device that is *unlocked* when it syncs.
///
/// Found by the property harness. Section 10.4 defers the counter rule because
/// the cycle may have no key — but a cycle on an unlocked device has one, and
/// deferring there was quietly destructive. The candidate waited for an unlock
/// that was never going to come, because the device was already unlocked, and
/// step 5 refuses to produce a code for an entry with a candidate outstanding.
/// So an ordinary sync stopped the entry working for as long as the app stayed
/// open, with the records and the counters agreeing the whole time.
#[test]
fn a_conflict_resolved_while_unlocked_is_reconciled_by_the_same_cycle() {
    let mut vault = vault();
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(9),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(42));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });

    // Through the vault, which is what an unlocked device does.
    let outcome = vault.sync(&mut server, NOW + 20_000).unwrap();

    assert_eq!(outcome.reconcile.counters_raised, 1);
    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(42),
        "the larger counter, without waiting for a lock the user may never use"
    );
    assert!(
        !reconcile::is_blocked(&vault, "e1").unwrap(),
        "and the entry produces codes again immediately"
    );
}

/// The other direction: the remote wins on HLC and the *local* record holds
/// the larger counter. Recording only one side would miss this.
#[test]
fn the_local_counter_is_recovered_when_the_remote_wins_on_hlc() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(&mut vault, "e1", &hotp(99), Hlc::new(NOW, 0, DEVICE_A));

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(3));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        // Newer, so the remote wins the HLC comparison.
        hlc: Hlc::new(NOW + 60_000, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });

    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 70_000).unwrap();
    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(3),
        "the HLC winner is in place"
    );

    reconcile::run(&mut vault).unwrap();

    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(99),
        "the discarded local counter was larger and must be recovered"
    );
}

/// The record must outlive a crash between writing it and applying it
/// (step 5). Modelled by reopening the vault over the same metadata file
/// without running the reconcile.
#[test]
fn a_pending_record_survives_a_crash_and_applies_on_the_next_unlock() {
    let meta = MetaStore::open_in_memory().unwrap();
    let mut vault = Vault::open(
        Store::open_in_memory(meta).unwrap(),
        XChaChaCipher::new(&key()),
    )
    .unwrap();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(5),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(77));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });

    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    // The crash: the process ends here, with the record written and the
    // reconcile never run.
    let store = vault.into_store();
    assert_eq!(
        store.reconcile_pending().unwrap().len(),
        1,
        "the record must be on disk, not only in memory"
    );

    // Next unlock, over the same storage.
    let mut reopened = Vault::open(store, XChaChaCipher::new(&key())).unwrap();
    assert!(
        reconcile::is_blocked(&reopened, "e1").unwrap(),
        "still blocked after the crash"
    );

    let report = reconcile::run(&mut reopened).unwrap();

    assert_eq!(report.counters_raised, 1);
    assert_eq!(
        reopened
            .get("e1")
            .unwrap()
            .payload
            .as_otp()
            .unwrap()
            .counter,
        Some(77)
    );
}

/// A raised counter has to reach the other devices, or the device that held
/// the smaller value keeps it and the two disagree forever.
#[test]
fn a_raised_counter_is_queued_to_propagate() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(2),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(50));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    let hlc_before = vault.store().get("e1").unwrap().unwrap().hlc;
    reconcile::run(&mut vault).unwrap();

    let after = vault.store().get("e1").unwrap().unwrap();
    assert!(
        after.hlc > hlc_before,
        "a fresh timestamp, or the correction loses the next conflict"
    );
    assert!(
        !vault.store().outbox().unwrap().is_empty(),
        "the correction must be queued for the other devices"
    );
}

/// A conflict where the winner already holds the larger counter needs no
/// change, and must not churn the record or its timestamp.
#[test]
fn nothing_changes_when_the_winner_already_has_the_larger_counter() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(100),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(7));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    let before = vault.store().get("e1").unwrap().unwrap().hlc;
    let report = reconcile::run(&mut vault).unwrap();

    assert_eq!(report.counters_raised, 0);
    assert_eq!(report.already_correct, 1);
    assert_eq!(vault.store().get("e1").unwrap().unwrap().hlc, before);
    assert!(!reconcile::is_blocked(&vault, "e1").unwrap());
}

/// A TOTP conflict produces a record too — the locked cycle cannot tell the
/// types apart — and it must clear without changing anything.
#[test]
fn a_totp_conflict_clears_without_a_change() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    let totp = Payload::Totp(OtpEntry {
        v: 1,
        issuer: Some("GitHub".to_string()),
        account: "rupsa".to_string(),
        secret: SecretString::new(SECRET),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        counter: None,
        folder_id: None,
        icon: None,
        favourite: false,
        order: String::new(),
        created_at: NOW as i64,
        note: String::new(),
        tags: Vec::new(),
        trashed_at: None,
        extra: Default::default(),
    });

    put(&mut vault, "e1", &totp, Hlc::new(NOW + 10_000, 0, DEVICE_A));

    let (ciphertext, nonce) = sealed_elsewhere("e1", &totp);
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    let report = reconcile::run(&mut vault).unwrap();

    assert_eq!(report.counters_raised, 0);
    assert!(
        !reconcile::is_blocked(&vault, "e1").unwrap(),
        "a TOTP entry must not stay blocked"
    );
}

/// An entry deleted elsewhere while a record was waiting must not stay
/// blocked forever.
#[test]
fn a_record_for_a_deleted_entry_is_dropped() {
    let mut vault = vault();

    put(&mut vault, "e1", &hotp(1), Hlc::new(NOW, 0, DEVICE_A));
    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(9));
    vault
        .store()
        .record_reconcile(
            "e1",
            &ciphertext,
            &nonce,
            Hlc::new(NOW, 0, DEVICE_B),
            NOW as i64,
        )
        .unwrap();

    vault.delete("e1", (NOW + 100) as i64).unwrap();

    let report = reconcile::run(&mut vault).unwrap();

    assert_eq!(report.orphaned, 1);
    assert!(vault.store().reconcile_pending().unwrap().is_empty());
}

/// Section 10.4 step 2, stated directly: the record holds the discarded
/// ciphertext, not merely the identifier. Without it there is nothing to
/// compare and the reconcile would bless whatever the HLC chose.
#[test]
fn the_record_holds_the_discarded_ciphertext() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(4),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(31));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext.clone()),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    let pending = vault.store().reconcile_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(
        pending[0].hlc.is_some(),
        "step 7 needs the discarded timestamp"
    );
    assert_eq!(
        pending[0].ciphertext, ciphertext,
        "the discarded ciphertext must be kept verbatim"
    );
    assert_eq!(pending[0].nonce.len(), 24);

    // And it opens, which is the property the reconcile depends on.
    let opened = vault
        .open_record("e1", &pending[0].ciphertext, &pending[0].nonce)
        .unwrap();
    assert_eq!(opened.as_otp().unwrap().counter, Some(31));
}

// ---------------------------------------------------------------------------
// Section 10.4 step 4: every candidate is kept
// ---------------------------------------------------------------------------

/// Three conflicts before one unlock. Keeping only the first candidate loses
/// the third exactly as overwriting would, and the reconcile then returns a
/// counter that is neither the largest nor obviously wrong.
#[test]
fn every_candidate_is_kept_and_the_largest_counter_wins() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(1),
        Hlc::new(NOW + 50_000, 0, DEVICE_A),
    );

    // Three remote records, each older than the local one so the local keeps
    // winning on HLC and each remote is discarded in turn. The largest counter
    // arrives last.
    for (offset, counter) in [(0u64, 10u64), (1_000, 500), (2_000, 77)] {
        let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(counter));
        server.hold(WireRecord {
            entry_id: "e1".to_string(),
            ciphertext: Some(ciphertext),
            nonce: Some(nonce),
            hlc: Hlc::new(NOW + offset, 0, DEVICE_B),
            deleted: false,
            server_seq: 0,
        });
        sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 60_000).unwrap();
    }

    let pending = vault.store().reconcile_pending().unwrap();
    assert_eq!(
        pending.len(),
        3,
        "each conflict must add a candidate, not replace the last"
    );

    let report = reconcile::run(&mut vault).unwrap();

    assert_eq!(report.candidates, 3);
    assert_eq!(report.examined, 1, "one entry, three candidates");
    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(500),
        "the largest of every candidate, not the first or the last"
    );
}

// ---------------------------------------------------------------------------
// Section 10.4 step 7: the corrected timestamp comes from the records
// ---------------------------------------------------------------------------

/// The correction must beat every record it corrects, and must not reach
/// further than that.
#[test]
fn the_corrected_timestamp_is_derived_from_the_candidates() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    let local_hlc = Hlc::new(NOW + 10_000, 0, DEVICE_A);
    put(&mut vault, "e1", &hotp(2), local_hlc);

    let remote_hlc = Hlc::new(NOW + 5_000, 3, DEVICE_B);
    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(90));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: remote_hlc,
        deleted: false,
        server_seq: 0,
    });
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    reconcile::run(&mut vault).unwrap();

    let corrected = vault.store().get("e1").unwrap().unwrap().hlc;
    let device = vault.store().device_id().unwrap();

    assert!(corrected > local_hlc, "must beat the record it corrects");
    assert!(
        corrected > remote_hlc,
        "and the candidate it took the counter from"
    );
    assert_eq!(
        corrected.device, device,
        "the correcting device owns the timestamp"
    );

    // Derived from the largest participating timestamp, not from a clock: the
    // wall-clock component is that record's, with the counter stepped once.
    assert_eq!(corrected.wall_ms, local_hlc.wall_ms);
    assert_eq!(corrected.counter, local_hlc.counter + 1);
}

/// The failure a clock read would cause, in the direction that is hardest to
/// notice: a device whose clock is behind writes a correction that loses to
/// the record it corrects, so the counter reverts at every unlock.
///
/// The derivation cannot do this, because it never looks at a clock. Asserted
/// by running the whole reconcile with wall-clock values far behind the
/// records and checking the correction still wins.
#[test]
fn a_device_with_a_slow_clock_still_writes_a_winning_correction() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    // The records are far in the future relative to any clock this device has.
    let local_hlc = Hlc::new(NOW + 900_000, 0, DEVICE_A);
    put(&mut vault, "e1", &hotp(4), local_hlc);

    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(60));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW + 800_000, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });
    // The cycle runs with a "now" long before those timestamps.
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW).unwrap();

    reconcile::run(&mut vault).unwrap();

    let corrected = vault.store().get("e1").unwrap().unwrap().hlc;
    assert!(
        corrected > local_hlc,
        "a correction written from a slow clock would lose and revert"
    );
    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(60)
    );
}

/// Running twice must not move the timestamp again. The second pass has no
/// candidates, so there is nothing to correct.
#[test]
fn a_second_reconcile_changes_nothing() {
    let mut vault = vault();
    let mut clock = HlcClock::new(DEVICE_A);
    let mut server = FakeServer::default();

    put(
        &mut vault,
        "e1",
        &hotp(3),
        Hlc::new(NOW + 10_000, 0, DEVICE_A),
    );
    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(40));
    server.hold(WireRecord {
        entry_id: "e1".to_string(),
        ciphertext: Some(ciphertext),
        nonce: Some(nonce),
        hlc: Hlc::new(NOW, 0, DEVICE_B),
        deleted: false,
        server_seq: 0,
    });
    sync::run_cycle(vault.store_mut(), &mut clock, &mut server, NOW + 20_000).unwrap();

    reconcile::run(&mut vault).unwrap();
    let after_first = vault.store().get("e1").unwrap().unwrap().hlc;

    let second = reconcile::run(&mut vault).unwrap();

    assert_eq!(second.examined, 0);
    assert_eq!(vault.store().get("e1").unwrap().unwrap().hlc, after_first);
}
