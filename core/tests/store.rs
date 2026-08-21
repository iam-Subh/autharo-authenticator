//! Tests for the local database (PRD section 12.1, OFF-02, section 10.6).
//!
//! The store handles opaque ciphertext, so these tests use byte strings in
//! place of encrypted payloads. Stage S3 supplies the real encryption; nothing
//! in this layer changes when it does.

use authcore::hlc::{Hlc, HlcClock};
use authcore::store::{Record, Store, new_entry_id};

const DEVICE: u64 = 0xa91b_7f0e_44d2_c318;

fn record(id: &str, hlc: Hlc, body: &[u8]) -> Record {
    Record {
        id: id.to_string(),
        ciphertext: body.to_vec(),
        nonce: vec![7u8; 24],
        hlc,
        deleted: false,
        server_seq: None,
        updated_at: 1_755_734_400_000,
    }
}

#[test]
fn a_new_database_is_empty_and_usable() {
    let store = Store::open_in_memory().unwrap();
    assert!(store.list(true).unwrap().is_empty());
    assert_eq!(store.cursor().unwrap(), 0);
    assert_eq!(store.time_offset_seconds().unwrap(), 0);
}

#[test]
fn a_written_record_reads_back_unchanged() {
    let mut store = Store::open_in_memory().unwrap();
    let id = new_entry_id();
    let written = record(&id, Hlc::new(1000, 0, DEVICE), b"ciphertext");

    store.write_local(&written, None).unwrap();

    assert_eq!(store.get(&id).unwrap().unwrap(), written);
    assert_eq!(store.list(false).unwrap(), vec![written]);
    assert!(store.get("no-such-entry").unwrap().is_none());
}

/// OFF-02: a local change lands in the database and the outbox together.
#[test]
fn a_local_write_queues_for_the_server() {
    let mut store = Store::open_in_memory().unwrap();
    let id = new_entry_id();
    let base = Hlc::new(500, 0, DEVICE);

    store
        .write_local(&record(&id, Hlc::new(1000, 0, DEVICE), b"v2"), Some(base))
        .unwrap();

    let outbox = store.outbox().unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].entry_id, id);
    assert_eq!(outbox[0].base_hlc, Some(base));
    assert_eq!(outbox[0].attempts, 0);
}

/// A record that arrives from the server is already on the server, so pushing
/// it back would be a wasted round trip.
#[test]
fn a_remote_write_does_not_queue() {
    let mut store = Store::open_in_memory().unwrap();
    let id = new_entry_id();
    let mut incoming = record(&id, Hlc::new(1000, 0, DEVICE), b"from server");
    incoming.server_seq = Some(42);

    store.apply_remote(&incoming).unwrap();

    assert_eq!(store.get(&id).unwrap().unwrap().server_seq, Some(42));
    assert!(store.outbox().unwrap().is_empty());
}

#[test]
fn a_failed_push_counts_up_for_the_backoff() {
    let mut store = Store::open_in_memory().unwrap();
    let id = new_entry_id();
    store
        .write_local(&record(&id, Hlc::new(1000, 0, DEVICE), b"x"), None)
        .unwrap();

    store.outbox_record_attempt(&id, 1_755_734_405_000).unwrap();
    store.outbox_record_attempt(&id, 1_755_734_410_000).unwrap();

    let outbox = store.outbox().unwrap();
    assert_eq!(outbox[0].attempts, 2);
    assert_eq!(outbox[0].last_attempt, Some(1_755_734_410_000));

    store.outbox_clear(&[id]).unwrap();
    assert!(store.outbox().unwrap().is_empty());
}

/// Section 10.4: a delete leaves a tombstone so it can reach other devices,
/// and the ciphertext goes away with the entry.
#[test]
fn a_delete_leaves_a_tombstone_with_no_ciphertext() {
    let mut store = Store::open_in_memory().unwrap();
    let id = new_entry_id();
    store
        .write_local(&record(&id, Hlc::new(1000, 0, DEVICE), b"secret"), None)
        .unwrap();

    let deleted = store
        .tombstone(&id, Hlc::new(2000, 0, DEVICE), 1_755_734_500_000)
        .unwrap();
    assert!(deleted);

    let tombstone = store.get(&id).unwrap().unwrap();
    assert!(tombstone.deleted);
    assert!(tombstone.ciphertext.is_empty());
    assert!(tombstone.nonce.is_empty());

    assert!(
        store.list(false).unwrap().is_empty(),
        "hidden from the list"
    );
    assert_eq!(store.list(true).unwrap().len(), 1, "kept for the sync");
    assert_eq!(
        store.outbox().unwrap().len(),
        1,
        "the delete must be pushed"
    );

    assert!(
        !store
            .tombstone("no-such-entry", Hlc::new(3000, 0, DEVICE), 0)
            .unwrap()
    );
}

/// The list is ordered by HLC, which is the sortable string from section 10.2.
#[test]
fn the_list_comes_back_newest_first() {
    let mut store = Store::open_in_memory().unwrap();
    let mut clock = HlcClock::new(DEVICE);
    let mut ids = Vec::new();
    for index in 0..3 {
        let id = new_entry_id();
        let hlc = clock.tick(1000 + index);
        store.write_local(&record(&id, hlc, b"x"), None).unwrap();
        ids.push(id);
    }

    let listed: Vec<String> = store
        .list(false)
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    ids.reverse();
    assert_eq!(listed, ids);
}

/// Section 10.6: a full re-sync replaces the table in one transaction, but a
/// local change that never reached the server must not be lost.
#[test]
fn a_full_resync_replaces_every_record() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .write_local(&record("old", Hlc::new(1000, 0, DEVICE), b"stale"), None)
        .unwrap();

    let fresh = vec![
        record("a", Hlc::new(3000, 0, DEVICE), b"a"),
        record("b", Hlc::new(3001, 0, DEVICE), b"b"),
    ];
    store.replace_all(&fresh, 99).unwrap();

    assert!(store.get("old").unwrap().is_none());
    assert_eq!(store.list(false).unwrap().len(), 2);
    assert_eq!(store.cursor().unwrap(), 99);
    assert!(
        store.outbox().unwrap().is_empty(),
        "the replaced records are already on the server"
    );
}

#[test]
fn the_cursor_and_the_time_offset_survive_a_reopen() {
    let path = std::env::temp_dir().join(format!("authcore-{}.db", new_entry_id()));
    let path = path.to_str().unwrap();

    let device;
    {
        let store = Store::open(path).unwrap();
        store.set_cursor(1234).unwrap();
        store.set_time_offset_seconds(-45).unwrap();
        device = store.device_id().unwrap();
    }
    {
        let store = Store::open(path).unwrap();
        assert_eq!(store.cursor().unwrap(), 1234);
        assert_eq!(store.time_offset_seconds().unwrap(), -45);
        assert_eq!(
            store.device_id().unwrap(),
            device,
            "the device identifier never changes"
        );
    }
    std::fs::remove_file(path).ok();
}

#[test]
fn the_device_identifier_is_stable_and_not_zero() {
    let store = Store::open_in_memory().unwrap();
    let first = store.device_id().unwrap();
    assert_ne!(first, 0);
    assert_eq!(store.device_id().unwrap(), first);

    let other = Store::open_in_memory().unwrap();
    assert_ne!(
        other.device_id().unwrap(),
        first,
        "two installs must not share an identifier"
    );
}

#[test]
fn meta_holds_arbitrary_bytes() {
    let store = Store::open_in_memory().unwrap();
    assert!(store.meta_get("wrapped_vault_key").unwrap().is_none());

    store
        .meta_set("wrapped_vault_key", &[0u8, 255, 128])
        .unwrap();
    assert_eq!(
        store.meta_get("wrapped_vault_key").unwrap().unwrap(),
        vec![0u8, 255, 128]
    );

    store.meta_set("wrapped_vault_key", b"replaced").unwrap();
    assert_eq!(
        store.meta_get("wrapped_vault_key").unwrap().unwrap(),
        b"replaced".to_vec()
    );
}

/// Reopening an existing file must not wipe it or fail on the schema.
#[test]
fn reopening_keeps_the_records() {
    let path = std::env::temp_dir().join(format!("authcore-{}.db", new_entry_id()));
    let path = path.to_str().unwrap();

    {
        let mut store = Store::open(path).unwrap();
        store
            .write_local(&record("kept", Hlc::new(1000, 0, DEVICE), b"body"), None)
            .unwrap();
    }
    {
        let store = Store::open(path).unwrap();
        assert_eq!(store.get("kept").unwrap().unwrap().ciphertext, b"body");
    }
    std::fs::remove_file(path).ok();
}
