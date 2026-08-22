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
    self, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport, WireRecord,
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
    fn pull(&mut self, since: i64, _limit: i64) -> Result<PullResponse, SyncError> {
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
    let report = reconcile::run(&mut vault, &mut clock, NOW + 30_000).unwrap();

    assert_eq!(report.counters_raised, 1);
    assert_eq!(
        vault.get("e1").unwrap().payload.as_otp().unwrap().counter,
        Some(42),
        "the larger counter must survive, whichever HLC was higher"
    );
    assert!(!reconcile::is_blocked(&vault, "e1").unwrap());
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

    reconcile::run(&mut vault, &mut clock, NOW + 80_000).unwrap();

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

    let report = reconcile::run(&mut reopened, &mut clock, NOW + 40_000).unwrap();

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
    reconcile::run(&mut vault, &mut clock, NOW + 30_000).unwrap();

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
    let report = reconcile::run(&mut vault, &mut clock, NOW + 30_000).unwrap();

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

    let report = reconcile::run(&mut vault, &mut clock, NOW + 30_000).unwrap();

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
    let mut clock = HlcClock::new(DEVICE_A);

    put(&mut vault, "e1", &hotp(1), Hlc::new(NOW, 0, DEVICE_A));
    let (ciphertext, nonce) = sealed_elsewhere("e1", &hotp(9));
    vault
        .store()
        .record_reconcile("e1", &ciphertext, &nonce, NOW as i64)
        .unwrap();

    vault.delete("e1", (NOW + 100) as i64).unwrap();

    let report = reconcile::run(&mut vault, &mut clock, NOW + 200).unwrap();

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
