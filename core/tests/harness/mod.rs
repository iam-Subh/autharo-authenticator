//! The stage S5 exit criterion: three devices converge under random
//! operations, partitions, locks, and prunes (PRD sections 10.3, 10.4, 10.6).
//!
//! # The failure this file is designed against
//!
//! A property test that passes because it never reached the interesting case.
//! A thousand random operations that happened to produce no conflict, no stale
//! cursor and no reconcile prove nothing — and the run still reports success,
//! which is worse than no test, because it looks like coverage.
//!
//! Three things guard against that, and the first had to exist before the
//! others were worth writing:
//!
//! 1. **A coverage floor.** Every event that makes a run meaningful is
//!    counted, and the run *fails* naming the event that never happened. See
//!    [`Coverage::check`]. Without it, the oracle and the invariants can both
//!    report success on a run that never produced a conflict.
//! 2. **An oracle.** The convergence invariants prove the devices agree; they
//!    do not prove the devices are right. Three devices can converge on a
//!    state that has lost an entry, and every one of those invariants would
//!    still pass. [`Model`] is kept outside the implementation and says what
//!    the answer should be: every add minus every delete, and the largest
//!    counter any device ever wrote.
//! 3. **A printed seed and trace.** A seed alone means replaying the run to
//!    find out what it did, so the operations are printed with it — shrunk
//!    first, to something short enough to read.
//!
//! # Every random source comes from the seed
//!
//! Including the record nonces and the device identifiers. A run that reached
//! for the operating system's randomness anywhere would not reproduce from its
//! printed seed, which is the whole point of printing one. [`SeededCipher`]
//! therefore draws nonces from the same generator as the operations — and
//! keeps them, so that nonce uniqueness stays assertable over the whole run.
//! The real cipher's use of `getrandom` is tested in `crypto.rs`, where it
//! belongs. The device identifier matters for the same reason and one more:
//! it breaks HLC ties, so a random one would change which device wins.
//!
//! # Two rules the generated operations obey
//!
//! Both are properties of the real client, not conveniences:
//!
//! - A device writes a counter derived from *its own* current value. HOTP
//!   counters never go backwards on the device holding them; a client that
//!   wrote a smaller counter than it already had would be broken, and is not
//!   something sync is meant to survive. This is what makes "the largest
//!   counter anyone wrote" a sound oracle.
//! - An entry with a reconcile record outstanding produces no code (section
//!   10.4 step 5), so no user could have advanced its counter either.
//!
//! # Running it
//!
//! ```text
//! cargo test --test convergence
//! CONVERGENCE_OPS=100000 cargo test --test convergence -- --ignored --nocapture
//! ```

#![allow(dead_code)] // Two binaries include this; neither uses all of it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::rc::Rc;

use authcore::crypto::NONCE_LEN;
use authcore::entry::{OtpEntry, Payload};
use authcore::hlc::{Hlc, HlcClock};
use authcore::otp::Algorithm;
use authcore::reconcile;
use authcore::secret::SecretString;
use authcore::store::{MetaStore, Store};
use authcore::sync::{
    self, PullMode, PullResponse, PushRecord, PushResponse, SyncError, SyncTransport,
};
use authcore::vault::{CipherError, CipherResult, RecordCipher, Sealed, SyncFailure, Vault};

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Operations per run in the ordinary suite.
const DEFAULT_OPS: usize = 1000;
const DEVICE_COUNT: usize = 3;
/// How many identifiers are in play at once. Small on purpose: a conflict
/// needs two devices to touch the same entry, and a wide identifier space
/// would make that rare enough that the coverage floor would fail every run.
const ENTRY_WINDOW: usize = 8;
/// How many operations the window advances by one identifier.
///
/// The window has to move, or a long run stops doing anything. A delete is
/// absolute and an identifier is never reused, so with a fixed set of eight the
/// run deleted all eight within a few hundred operations and every operation
/// after that was a no-op. The hundred-thousand-operation run passed with
/// seventeen conflicts — fewer than the thousand-operation one — and the
/// coverage floor called it a pass, because every count had cleared zero. It
/// takes a floor that scales, and a generator that keeps finding work.
const ENTRY_LIFETIME: usize = 40;
const SECRET: &str = "GEZDGNBVGY3TQOJQ";
/// How many rounds of unlock-and-sync the run allows before it gives up.
///
/// Generous, and asserted rather than exhausted quietly: a run that stops
/// short of quiescence has not tested convergence, and would report whatever
/// the half-finished state happened to look like.
const MAX_QUIESCENCE_ROUNDS: usize = 200;
// ---------------------------------------------------------------------------
// A seeded generator
// ---------------------------------------------------------------------------

/// xorshift64*. Small, deterministic, and good enough to drive a state
/// machine. Nothing it produces protects anything — see [`SeededCipher`] for
/// why the record nonces come from here anyway.
#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state stays zero forever.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&word[..len]);
        }
    }
}

// ---------------------------------------------------------------------------
// A cipher whose nonces come from the seed
// ---------------------------------------------------------------------------

/// The nonce generator for one device, shared by every cipher it builds.
///
/// A device throws its `Vault` away when it locks and builds a new one when it
/// unlocks. A cipher that restarted the generator from the seed would emit the
/// same nonces again — a nonce repeat under one key, manufactured by the
/// harness rather than found by it. The state therefore lives in the device
/// and outlives the vault.
#[derive(Clone)]
struct NonceSource {
    rng: Rc<RefCell<Rng>>,
    emitted: Rc<RefCell<Vec<[u8; NONCE_LEN]>>>,
}

impl NonceSource {
    fn new(seed: u64) -> Self {
        Self {
            rng: Rc::new(RefCell::new(Rng::new(seed))),
            emitted: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn next(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.borrow_mut().fill(&mut nonce);
        self.emitted.borrow_mut().push(nonce);
        nonce
    }

    fn emitted(&self) -> Vec<[u8; NONCE_LEN]> {
        self.emitted.borrow().clone()
    }
}

/// The real record construction — XChaCha20-Poly1305 with the entry identifier
/// and record version as associated data (section 9.3) — with the nonce drawn
/// from the seed instead of from `getrandom`.
///
/// The associated data is byte for byte what `crypto::XChaChaCipher` binds, so
/// a record sealed here is a record the real cipher would produce; only where
/// the nonce came from differs.
struct SeededCipher {
    key: [u8; 32],
    nonces: NonceSource,
}

impl SeededCipher {
    fn new(key: [u8; 32], nonces: NonceSource) -> Self {
        Self { key, nonces }
    }

    fn associated_data(entry_id: &str, record_version: u32) -> Vec<u8> {
        let id = entry_id.as_bytes();
        let mut aad = Vec::with_capacity(4 + id.len() + 4);
        aad.extend_from_slice(&(id.len() as u32).to_be_bytes());
        aad.extend_from_slice(id);
        aad.extend_from_slice(&record_version.to_be_bytes());
        aad
    }

    fn cipher(&self) -> CipherResult<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| CipherError::Unavailable {
            reason: "the record key is the wrong length".to_string(),
        })
    }
}

impl RecordCipher for SeededCipher {
    fn seal(&self, entry_id: &str, record_version: u32, plaintext: &[u8]) -> CipherResult<Sealed> {
        let nonce = self.nonces.next();
        let ciphertext = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: plaintext,
                    aad: &Self::associated_data(entry_id, record_version),
                },
            )
            .map_err(|_| CipherError::Unavailable {
                reason: "the record could not be encrypted".to_string(),
            })?;

        Ok(Sealed {
            ciphertext,
            nonce: nonce.to_vec(),
        })
    }

    fn open(
        &self,
        entry_id: &str,
        record_version: u32,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> CipherResult<Zeroizing<Vec<u8>>> {
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CipherError::NotAuthentic)?;
        let plaintext = self
            .cipher()?
            .decrypt(
                &XNonce::from(nonce),
                AeadPayload {
                    msg: ciphertext,
                    aad: &Self::associated_data(entry_id, record_version),
                },
            )
            .map_err(|_| CipherError::NotAuthentic)?;
        Ok(Zeroizing::new(plaintext))
    }
}

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// What the devices *should* hold, tracked outside the implementation.
///
/// The convergence invariants prove the devices agree with each other, which
/// is not the same as being right: three devices can converge on a state that
/// has lost an entry, and agreement would still hold. This is the independent
/// answer to check them against.
#[derive(Default)]
struct Model {
    /// Every entry ever added, on any device.
    added: BTreeSet<String>,
    /// Every entry ever deleted. Section 10.4 makes a delete absolute, so an
    /// identifier here must not come back however the writes interleave.
    deleted: BTreeSet<String>,
    /// The largest counter any device ever wrote for an entry. Sound because
    /// the generated operations never write a counter below the one the
    /// writing device already held — see the module documentation.
    max_counter: BTreeMap<String, u64>,
}

impl Model {
    fn add(&mut self, id: &str, counter: u64) {
        self.added.insert(id.to_string());
        self.note_counter(id, counter);
    }

    fn delete(&mut self, id: &str) {
        self.deleted.insert(id.to_string());
    }

    fn note_counter(&mut self, id: &str, counter: u64) {
        let slot = self.max_counter.entry(id.to_string()).or_insert(0);
        *slot = (*slot).max(counter);
    }

    /// Every add minus every delete.
    fn expected_live(&self) -> BTreeSet<String> {
        self.added.difference(&self.deleted).cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// The coverage floor
// ---------------------------------------------------------------------------

/// Counts of the events that make a run meaningful.
///
/// The run fails if a required one is zero. That is the whole point: a passing
/// run that never produced a conflict has exercised the happy path and
/// reported it as though it had exercised the rules.
#[derive(Default, Debug)]
struct Coverage {
    conflicts_resolved: usize,
    three_way_conflicts: usize,
    reconcile_records_written: usize,
    reconcile_records_applied: usize,
    counters_raised: usize,
    stale_cursors: usize,
    full_resyncs: usize,
    pushes_replayed: usize,
    locked_cycles: usize,
    /// Records taken from the server, and records the server accepted. Not
    /// part of the floor — they are how the run knows whether anything is
    /// still moving. See the quiescence loop.
    records_applied: usize,
    records_pushed: usize,
    prunes: usize,
    deletes: usize,
    resurrections_attempted: usize,
    partitions: usize,
}

impl Coverage {
    /// Fails naming the event that did not happen often enough.
    ///
    /// # Why each event has its own rate
    ///
    /// A floor of "more than zero" passes a run that stopped doing anything
    /// after its first few hundred operations, which is exactly what the
    /// hundred-thousand-operation run did before the identifier window started
    /// moving: seventeen conflicts, fewer than the thousand-operation run, and
    /// a clean pass. So the bar has to rise with the operation count.
    ///
    /// But one rate for everything is wrong in the other direction. A conflict
    /// happens about once in fifty operations and a stale cursor about once in
    /// seventeen hundred, so a rate that suits the first fails every run on the
    /// second — which trains everyone to lower it, and a floor that gets
    /// lowered whenever it complains has stopped being a floor.
    ///
    /// The numbers below are roughly a quarter of what a healthy run produces,
    /// measured rather than guessed. They are for catching a run that went
    /// quiet, not for pinning the distribution.
    fn check(&self, ops: usize, can_prune: bool, can_replay: bool) -> Result<(), String> {
        // (what, how many happened, one expected per this many operations)
        let required: [(&str, usize, usize); 10] = [
            (
                "a conflict the server rejected",
                self.conflicts_resolved,
                200,
            ),
            ("a three-way conflict", self.three_way_conflicts, 600),
            (
                "a reconcile record written",
                self.reconcile_records_written,
                200,
            ),
            (
                "a reconcile record applied",
                self.reconcile_records_applied,
                200,
            ),
            (
                "a counter raised by the reconcile",
                self.counters_raised,
                1_000,
            ),
            ("a stale cursor, the 410 path", self.stale_cursors, 4_000),
            ("a full re-sync", self.full_resyncs, 4_000),
            ("a push replayed", self.pushes_replayed, 1_000),
            ("a cycle run while locked", self.locked_cycles, 100),
            ("a delete", self.deletes, 500),
        ];

        for (what, count, rate) in required {
            if !can_replay && what.contains("push replayed") {
                continue;
            }
            if !can_prune && (what.contains("stale cursor") || what.contains("full re-sync")) {
                // Nothing in this backend can move the server's watermark, so
                // neither can happen. Declared through `Backend::can_prune`
                // rather than left silently at zero — those rules are covered
                // against the in-memory server, which can.
                continue;
            }

            let floor = (ops / rate).max(1);
            if count < floor {
                let reached = if count == 0 {
                    "never exercised".to_string()
                } else {
                    format!("exercised {count} times, against a floor of {floor},")
                };
                return Err(format!(
                    "the run {reached} {what}, so {ops} operations proved \
                     little about it.\ncoverage: {self:#?}"
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// What the devices sync against
// ---------------------------------------------------------------------------

/// The server the run drives, whichever one it is.
///
/// Two implement it: an in-memory model in `convergence.rs`, and a real HTTP
/// client against a running server in `convergence_http.rs`. The point of the
/// trait is that everything above it — the operations, the devices, the model,
/// the invariants — is one piece of code rather than two copies that drift.
/// Two harnesses asserting slightly different things would be worse than one.
pub trait Backend {
    /// One device's connection, for one cycle.
    fn open(&mut self, partitioned: bool) -> Box<dyn Observed + '_>;

    /// The server prunes, invalidating cursors behind the watermark. False
    /// where the backend has no way to do it.
    fn prune(&mut self) -> bool;

    /// What this backend holds for one entry, for a failure message.
    ///
    /// A divergence says which entries disagree and nothing about why. Whether
    /// the server has the record at all is the difference between "one device
    /// never pushed it" and "one device never pulled it", which are different
    /// bugs with different fixes — and guessing between them from the entry
    /// list alone is how two rounds of this went to the wrong hypothesis.
    fn describe(&self, entry_id: &str) -> String {
        let _ = entry_id;
        "the backend does not say".to_string()
    }

    /// A one-line summary of the backend's own state.
    fn summary(&self) -> String {
        String::new()
    }

    /// Whether [`Self::replay_push`] can ever succeed.
    ///
    /// Same contract as [`Self::can_prune`]: a backend that cannot produce an
    /// event says so, and the floor names the gap rather than lowering itself
    /// to a zero it cannot tell from a regression.
    fn can_replay_pushes(&self) -> bool {
        true
    }

    /// Whether [`Self::prune`] can ever succeed.
    ///
    /// Not the same as it having failed this time. The floor demands a stale
    /// cursor and a full re-sync from a backend that can produce them, and
    /// says so in the failure when it cannot — a floor quietly lowered is a
    /// floor that stops catching anything.
    fn can_prune(&self) -> bool {
        true
    }

    /// How many *operations* the shrinker may replay on this backend.
    ///
    /// Operations, not replays: shrinking replays the whole candidate each
    /// time, so a replay costs what the candidate is long, and a budget in
    /// replays means something different at a thousand operations than at a
    /// hundred thousand.
    ///
    /// In memory an operation is microseconds; over HTTP it is a round trip
    /// and every replay signs up a fresh account, so that backend sets its own
    /// far lower. A smaller budget gives a longer trace, which is the right
    /// trade when the alternative is no trace at all.
    fn shrink_budget(&self) -> usize {
        20_000_000
    }

    /// Re-send a push the server already applied, exactly as it was sent, as
    /// though its response had been lost. False if there was nothing
    /// meaningful to replay.
    fn replay_push(&mut self, which: usize) -> bool;
}

/// A transport that also reports what the server said.
///
/// The cycle absorbs this: `run_cycle` resolves conflicts internally and
/// returns counts, but the coverage floor needs to know *which* entries
/// conflicted, to tell one three-way conflict from two two-way ones.
pub trait Observed: SyncTransport {
    /// Entries the server reported as conflicts during this cycle.
    fn conflicted(&self) -> &[String];
    /// Whether the server refused the cursor as too old.
    fn stale(&self) -> bool;
}

impl SyncTransport for Box<dyn Observed + '_> {
    fn pull(&mut self, since: i64, limit: i64, mode: PullMode) -> Result<PullResponse, SyncError> {
        (**self).pull(since, limit, mode)
    }

    fn push(&mut self, records: &[PushRecord]) -> Result<PushResponse, SyncError> {
        (**self).push(records)
    }
}

// ---------------------------------------------------------------------------
// A device
// ---------------------------------------------------------------------------

/// A device is either unlocked, holding a [`Vault`], or locked, holding only
/// its [`Store`].
///
/// That is FR-31 and OFF-09 together: locking releases the vault key, and the
/// sync cycle keeps running without one. Modelling it as one field or the
/// other makes it structural — a locked device here has no way to reach a
/// payload, because it has no vault to reach it with.
struct Device {
    id: usize,
    store: Option<Store>,
    vault: Option<Vault<SeededCipher>>,
    /// Kept for the locked cycles, which have no vault to borrow one from.
    clock: HlcClock,
    key: [u8; 32],
    nonces: NonceSource,
    locked: bool,
    partitioned: bool,
    /// This device's wall clock, driven by the run rather than by the host.
    now_ms: u64,
}

impl Device {
    fn new(id: usize, key: [u8; 32], seed: u64, device_id: u64, now_ms: u64) -> Self {
        let meta = MetaStore::open_in_memory().unwrap();
        // Written before anything reads it, so the identifier comes from the
        // seed rather than from a v4 UUID.
        meta.set("device_id", &device_id.to_be_bytes()).unwrap();

        let store = Store::open_in_memory(meta).unwrap();
        let nonces = NonceSource::new(seed);
        let vault = Vault::open(store, SeededCipher::new(key, nonces.clone())).unwrap();
        let clock = vault.clock();

        Self {
            id,
            store: None,
            vault: Some(vault),
            clock,
            key,
            nonces,
            locked: false,
            partitioned: false,
            now_ms,
        }
    }

    fn lock(&mut self) {
        if let Some(vault) = self.vault.take() {
            // The clock has to survive the vault: the locked cycle keeps
            // issuing from it, and reopening resumes from the stored records.
            self.clock = vault.clock();
            self.store = Some(vault.into_store());
        }
        self.locked = true;
    }

    /// Reopening runs the reconcile before anything can ask for a code
    /// (section 10.4 step 6).
    fn unlock(&mut self, coverage: &mut Coverage) {
        if let Some(store) = self.store.take() {
            let mut vault =
                Vault::open(store, SeededCipher::new(self.key, self.nonces.clone())).unwrap();

            let report = reconcile::run(&mut vault).unwrap();
            coverage.reconcile_records_applied += report.candidates;
            coverage.counters_raised += report.counters_raised;

            self.clock = vault.clock();
            self.vault = Some(vault);
        }
        self.locked = false;
    }

    fn store_ref(&self) -> &Store {
        match (&self.vault, &self.store) {
            (Some(vault), _) => vault.store(),
            (None, Some(store)) => store,
            _ => unreachable!("a device holds one or the other, always"),
        }
    }

    /// A timestamp from this device's own clock.
    ///
    /// Taken from the vault's clock when there is one. The cycle folds every
    /// timestamp it has seen into that clock, and a stale copy would issue a
    /// write below a record the write is meant to supersede.
    fn tick(&mut self) -> Hlc {
        match &self.vault {
            Some(vault) => vault.clock().tick(self.now_ms),
            None => self.clock.tick(self.now_ms),
        }
    }

    /// This device's counter for an entry, or `None` if it does not hold one,
    /// cannot read it, or is locked.
    fn counter_of(&self, id: &str) -> Option<u64> {
        let vault = self.vault.as_ref()?;
        let entry = vault.get(id).ok()?;
        entry.payload.as_otp().and_then(|otp| otp.counter)
    }

    /// Every entry this device holds, tombstones included, with its timestamp.
    fn timestamps(&self) -> BTreeMap<String, Hlc> {
        self.store_ref().timestamps().unwrap().into_iter().collect()
    }

    fn live(&self) -> BTreeSet<String> {
        self.store_ref()
            .list(false)
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect()
    }

    /// Whether this entry is queued for the server, and under what base.
    fn queued(&self, id: &str) -> Option<Option<Hlc>> {
        self.store_ref()
            .outbox()
            .unwrap()
            .into_iter()
            .find(|item| item.entry_id == id)
            .map(|item| item.base_hlc)
    }

    fn pending_reconcile(&self) -> usize {
        self.store_ref().reconcile_pending_count().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// Create an entry this device holds no record of. A device that has
    /// never seen an entry another device has deleted still tries, which is
    /// the case delete-wins exists for.
    Add {
        device: usize,
        entry: usize,
    },
    /// Advance the counter past the one this device currently holds.
    Bump {
        device: usize,
        entry: usize,
    },
    Delete {
        device: usize,
        entry: usize,
    },
    Sync {
        device: usize,
    },
    Lock {
        device: usize,
    },
    Unlock {
        device: usize,
    },
    Partition {
        device: usize,
    },
    Heal {
        device: usize,
    },
    /// The server prunes, invalidating every cursor behind the watermark.
    Prune,
    /// A push whose response was lost, sent again exactly as it was.
    ReplayPush {
        which: usize,
    },
    /// This device's wall clock moves forward.
    Tick {
        device: usize,
        ms: u64,
    },
}

fn generate(rng: &mut Rng, count: usize) -> Vec<Op> {
    let mut ops = Vec::with_capacity(count);
    for index in 0..count {
        let device = rng.below(DEVICE_COUNT);
        let entry = index / ENTRY_LIFETIME + rng.below(ENTRY_WINDOW);
        // Weighted so that the rare events still appear often enough over a
        // thousand operations to clear the coverage floor. If they stop doing
        // so, the floor is what says which one stopped.
        // Partitions open more often than they heal, on purpose. With the
        // weights the other way round a partition lasted two or three
        // operations, the devices never diverged far, and the counter rule in
        // section 10.4 had nothing to correct: a thousand operations applied
        // forty-six reconcile records and raised no counter at all. The floor
        // caught it, which is what the floor is for.
        ops.push(match rng.below(100) {
            0..=11 => Op::Add { device, entry },
            12..=39 => Op::Bump { device, entry },
            40..=45 => Op::Delete { device, entry },
            46..=71 => Op::Sync { device },
            72..=77 => Op::Lock { device },
            78..=83 => Op::Unlock { device },
            84..=88 => Op::Partition { device },
            89..=91 => Op::Heal { device },
            92..=93 => Op::Prune,
            94..=96 => Op::ReplayPush {
                which: rng.next_u64() as usize,
            },
            // Kept under the five-minute bound in section 10.2 deliberately. A
            // clamped timestamp is stored clamped, so two devices that
            // disagreed about whether to clamp would store different
            // timestamps for one record and no amount of syncing would fix it.
            // That rule has its own tests in `sync.rs`; this file is about
            // convergence, and the two questions should fail separately.
            _ => Op::Tick {
                device,
                ms: 1 + rng.next_u64() % 4_000,
            },
        });
    }
    ops
}

/// Entry identifiers are UUIDs, because the server parses them as UUIDs.
///
/// Derived from the index rather than generated, so a run reproduces from its
/// seed — `store::new_entry_id` reaches for the operating system. The shape is
/// a valid version 4 UUID: version nibble 4, variant bits 10.
fn entry_id(entry: usize) -> String {
    format!("00000000-0000-4000-8000-{entry:012x}")
}

fn hotp(entry: usize, counter: u64, created_at: u64) -> Payload {
    Payload::Hotp(OtpEntry {
        v: 1,
        issuer: Some(format!("Issuer {entry}")),
        account: format!("account{entry}"),
        secret: SecretString::new(SECRET),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        counter: Some(counter),
        folder_id: None,
        icon: None,
        favourite: false,
        order: String::new(),
        created_at: created_at as i64,
        note: String::new(),
        tags: Vec::new(),
        trashed_at: None,
        extra: Default::default(),
    })
}
// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// A broken invariant.
///
/// `kind` exists for the shrinker. Removing operations until "something still
/// fails" finds the shortest run that fails *for any reason*, which is not the
/// same bug as the one being reported: the first version of this harness shrank
/// a lost counter down to a single `Add` that tripped an unrelated invariant.
/// The shrinker keeps only candidates that fail the same way.
struct Failure {
    kind: &'static str,
    detail: String,
}

impl Failure {
    fn new(kind: &'static str, detail: String) -> Option<Self> {
        Some(Self { kind, detail })
    }
}

struct Outcome {
    coverage: Coverage,
    failure: Option<Failure>,
}

/// Rules that can only be checked while the run is happening.
///
/// Most invariants are about the state at quiescence, and `check` reads that
/// state directly. Full re-sync safety is not: it is about what one operation
/// *removed*, which is invisible by the time the run ends because the next
/// cycle pushes whatever survived. So it is watched at the moment, and the
/// first violation becomes the run's failure.
#[derive(Default)]
struct Watched {
    violations: Vec<(&'static str, String)>,
}

fn run<B: Backend>(seed: u64, ops: &[Op], backend: &mut B) -> Outcome {
    let mut rng = Rng::new(seed ^ 0x9E37_79B9_7F4A_7C15);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    let base_now = 1_755_734_400_000u64;
    let mut devices: Vec<Device> = (0..DEVICE_COUNT)
        .map(|i| {
            Device::new(
                i,
                key,
                seed.wrapping_add(i as u64 * 7919),
                0xD000_0000_0000_0001u64.wrapping_add(i as u64),
                base_now,
            )
        })
        .collect();

    let mut model = Model::default();
    let mut coverage = Coverage::default();
    let mut watched = Watched::default();

    for op in ops {
        match op {
            Op::Tick { device, ms } => devices[*device].now_ms += ms,

            Op::Add { device, entry } => {
                let id = entry_id(*entry);
                let device = &mut devices[*device];
                if device.locked {
                    continue; // No key, no payload.
                }
                if device.store_ref().get(&id).unwrap().is_some() {
                    // Only an entry this device holds no record of at all. An
                    // add is not an overwrite, and it is not an undelete
                    // either: identifiers are version 4 UUIDs minted at the
                    // moment of the add, so a new entry cannot land on one
                    // this device already has — live or tombstoned. `add`
                    // generates the identifier and `update` refuses a deleted
                    // entry, so the client has no path to it.
                    continue;
                }
                if model.deleted.contains(&id) {
                    // But a device that never saw the entry adding it while
                    // another device deletes it *is* reachable, and is the
                    // case delete-wins exists for. Left in, and counted.
                    coverage.resurrections_attempted += 1;
                }

                let hlc = device.tick();
                let payload = hotp(*entry, 0, device.now_ms);
                if device
                    .vault
                    .as_mut()
                    .unwrap()
                    .write_with_hlc(&id, &payload, hlc, None)
                    .is_ok()
                {
                    model.add(&id, 0);
                }
            }

            Op::Bump { device, entry } => {
                let id = entry_id(*entry);
                let device = &mut devices[*device];
                if device.locked {
                    continue;
                }
                let Some(record) = device.store_ref().get(&id).unwrap() else {
                    continue;
                };
                if record.deleted {
                    continue;
                }
                if device.store_ref().reconcile_pending_for(&id).unwrap() {
                    // Section 10.4 step 5: this entry produces no code, so no
                    // user could have advanced its counter.
                    continue;
                }
                // Derived from this device's own value. A counter that went
                // backwards would be a broken client, and would make the
                // oracle unsound.
                let Some(counter) = device.counter_of(&id) else {
                    continue;
                };
                let next = counter + 1;

                let hlc = device.tick();
                let payload = hotp(*entry, next, device.now_ms);
                if device
                    .vault
                    .as_mut()
                    .unwrap()
                    .write_with_hlc(&id, &payload, hlc, Some(record.hlc))
                    .is_ok()
                {
                    model.note_counter(&id, next);
                }
            }

            Op::Delete { device, entry } => {
                let id = entry_id(*entry);
                let device = &mut devices[*device];
                if device.locked {
                    continue;
                }
                let Some(record) = device.store_ref().get(&id).unwrap() else {
                    continue;
                };
                if record.deleted {
                    continue;
                }
                let now = device.now_ms as i64;
                if device.vault.as_mut().unwrap().delete(&id, now).is_ok() {
                    model.delete(&id);
                    coverage.deletes += 1;
                }
            }

            Op::Sync { device } => {
                cycle(*device, &mut devices, backend, &mut coverage, &mut watched)
            }

            Op::Lock { device } => devices[*device].lock(),
            Op::Unlock { device } => devices[*device].unlock(&mut coverage),

            Op::Partition { device } => {
                if !devices[*device].partitioned {
                    devices[*device].partitioned = true;
                    coverage.partitions += 1;
                }
            }
            Op::Heal { device } => devices[*device].partitioned = false,

            Op::Prune => {
                // Section 10.6: everything below the watermark is gone, and a
                // cursor pointing there gets a 410.
                if backend.prune() {
                    coverage.prunes += 1;
                }
            }

            Op::ReplayPush { which } => {
                // The client sent this, the server applied it, and the
                // response was lost. The client sends it again, byte for byte
                // — the same timestamp, the same base. Applying it twice must
                // leave the same state as applying it once.
                if backend.replay_push(*which) {
                    coverage.pushes_replayed += 1;
                }
            }
        }
    }

    // ---- quiescence ----
    //
    // Every partition heals, then the devices unlock and sync until nothing
    // moves. Unlock first, because that is where the reconcile runs and the
    // correction it writes has to be pushed by the cycle that follows.
    for device in devices.iter_mut() {
        device.partitioned = false;
    }
    // Until nothing moves.
    //
    // "Nothing moves" has to mean records, not conflicts. The first version of
    // this loop stopped when a round produced no conflict and no counter
    // raise — which a round spends entirely draining a backlog does not, so
    // with thousands of records in flight it declared quiescence after three
    // rounds and the invariants then compared devices that were still catching
    // up. At a thousand operations that was never visible; at a hundred
    // thousand, device 1 was short several hundred entries. The exit condition
    // was a proxy that had stopped tracking the thing.
    let mut settled = false;
    for _ in 0..MAX_QUIESCENCE_ROUNDS {
        let before = (
            coverage.records_applied,
            coverage.records_pushed,
            coverage.counters_raised,
            coverage.conflicts_resolved,
        );
        for index in 0..DEVICE_COUNT {
            devices[index].unlock(&mut coverage);
            cycle(index, &mut devices, backend, &mut coverage, &mut watched);
        }
        let after = (
            coverage.records_applied,
            coverage.records_pushed,
            coverage.counters_raised,
            coverage.conflicts_resolved,
        );
        if after == before {
            settled = true;
            break;
        }
    }
    assert!(
        settled,
        "the devices were still exchanging records after {MAX_QUIESCENCE_ROUNDS} rounds, \
         so whatever the invariants below said would have been about a state still in motion"
    );

    // Settled: clear whatever the last round recorded, then one quiet cycle
    // each. Invariant 6 below is about what that quiet cycle leaves behind.
    for device in devices.iter_mut() {
        device.unlock(&mut coverage);
    }
    for index in 0..DEVICE_COUNT {
        cycle(index, &mut devices, backend, &mut coverage, &mut watched);
    }

    // A rule broken during the run outranks the end state: the end state is
    // what the broken rule produced.
    let failure = match watched.violations.first() {
        Some((kind, detail)) => Failure::new(kind, detail.clone()),
        None => check(&devices, &model, backend),
    };
    Outcome { coverage, failure }
}

/// One sync cycle for one device, whatever state it is in.
///
/// A locked device calls [`sync::run_cycle`] directly with the clock it kept;
/// an unlocked one goes through [`Vault::sync`], so that the cycle and the
/// local writes share one clock.
fn cycle<B: Backend>(
    index: usize,
    devices: &mut [Device],
    backend: &mut B,
    coverage: &mut Coverage,
    watched: &mut Watched,
) {
    let before_pending = devices[index].pending_reconcile();

    // The versions this device is about to offer the server.
    //
    // Only these can come back as conflicts, and only this device's records
    // change during its own cycle — the other two are untouched, so their
    // versions can be read afterwards. Snapshotting every entry on every
    // device before every cycle was O(operations x entries), which was free
    // while there were eight identifiers and quadratic once the window
    // started moving: the fifty-thousand-operation run stopped finishing.
    let offered: BTreeMap<String, Hlc> = {
        let store = devices[index].store_ref();
        store
            .outbox()
            .unwrap()
            .into_iter()
            .filter_map(|item| {
                store
                    .get(&item.entry_id)
                    .unwrap()
                    .map(|record| (item.entry_id, record.hlc))
            })
            .collect()
    };

    let partitioned = devices[index].partitioned;
    let now = devices[index].now_ms;
    if devices[index].locked {
        coverage.locked_cycles += 1;
    }

    // An unlocked cycle reconciles at the end of itself; a locked one cannot,
    // and leaves its candidates for the next unlock.
    let (result, reconciled, moved, conflicted, stale) = {
        let mut link = backend.open(partitioned);
        let device = &mut devices[index];
        let mut reconciled = (0usize, 0usize);
        let mut moved = (0usize, 0usize);
        let result = match &mut device.vault {
            Some(vault) => match vault.sync(&mut link, now) {
                Ok(outcome) => {
                    reconciled = (
                        outcome.reconcile.candidates,
                        outcome.reconcile.counters_raised,
                    );
                    moved = (outcome.cycle.applied, outcome.cycle.pushed);
                    Ok(())
                }
                Err(SyncFailure::Cycle(error)) => Err(error),
                Err(SyncFailure::Reconcile(error)) => {
                    panic!("the reconcile failed during a cycle: {error}")
                }
            },
            None => {
                let store = device.store.as_mut().unwrap();
                sync::run_cycle(store, &mut device.clock, &mut link, now).map(|report| {
                    moved = (report.applied, report.pushed);
                })
            }
        };
        (
            result,
            reconciled,
            moved,
            link.conflicted().to_vec(),
            link.stale(),
        )
    };

    coverage.conflicts_resolved += conflicted.len();
    coverage.records_applied += moved.0;
    coverage.records_pushed += moved.1;
    coverage.reconcile_records_applied += reconciled.0;
    coverage.counters_raised += reconciled.1;
    if stale {
        coverage.stale_cursors += 1;
    }

    // A three-way conflict is not "two candidates recorded in one cycle". It
    // is one entry that all three devices held at a different version at the
    // moment the conflict was reported — the case two devices cannot reach.
    for id in &conflicted {
        let mut versions: BTreeSet<Hlc> = BTreeSet::new();
        if let Some(offered) = offered.get(id) {
            versions.insert(*offered);
        }
        for (other, device) in devices.iter().enumerate() {
            if other == index {
                continue; // Its version is the one it offered, above.
            }
            if let Some(record) = device.store_ref().get(id).unwrap() {
                versions.insert(record.hlc);
            }
        }
        if versions.len() >= DEVICE_COUNT {
            coverage.three_way_conflicts += 1;
        }
    }

    let after_pending = devices[index].pending_reconcile();
    // On a locked device the candidates stay, so the difference counts them.
    // On an unlocked one the reconcile at the end of the cycle has already
    // cleared them, and what it applied is the count that matters.
    coverage.reconcile_records_written +=
        after_pending.saturating_sub(before_pending) + reconciled.0;

    if let Err(SyncError::CursorTooOld) = result {
        // PRD section 17, full re-sync safety: "A full re-sync drops nothing
        // from the outbox."
        //
        // A stale cursor means the device has been away, and a device that has
        // been away is the one most likely to hold unpushed changes. Applying
        // the server's records wholesale removes an unpushed tombstone and
        // resurrects a deleted entry — which is what the earlier
        // `replace_all` did, and what six generated operations reproduced.
        //
        // Checked here rather than at quiescence because by then the evidence
        // is gone: the next cycle pushes whatever survived, and a record that
        // was dropped looks exactly like one that was never made.
        let queued_before: BTreeSet<String> = devices[index]
            .store_ref()
            .outbox()
            .unwrap()
            .into_iter()
            .map(|item| item.entry_id)
            .collect();

        // Section 10.6: start again from nothing.
        let mut link = backend.open(partitioned);
        let device = &mut devices[index];
        let resynced = match &mut device.vault {
            Some(vault) => match vault.full_resync(&mut link, now) {
                Ok(outcome) => {
                    coverage.records_applied += outcome.applied;
                    coverage.reconcile_records_applied += outcome.reconcile.candidates;
                    coverage.counters_raised += outcome.reconcile.counters_raised;
                    true
                }
                Err(SyncFailure::Cycle(_)) => false,
                Err(SyncFailure::Reconcile(error)) => {
                    panic!("the reconcile failed during a re-sync: {error}")
                }
            },
            None => {
                let store = device.store.as_mut().unwrap();
                match sync::full_resync(store, &mut device.clock, &mut link, now) {
                    Ok(applied) => {
                        coverage.records_applied += applied;
                        true
                    }
                    Err(_) => false,
                }
            }
        };
        if resynced {
            let queued_after: BTreeSet<String> = devices[index]
                .store_ref()
                .outbox()
                .unwrap()
                .into_iter()
                .map(|item| item.entry_id)
                .collect();

            let lost: Vec<&String> = queued_before.difference(&queued_after).collect();
            if !lost.is_empty() {
                watched.violations.push((
                    "full re-sync safety",
                    format!(
                        "device {} had {lost:?} waiting to be pushed, and a full \
                         re-sync dropped them. Whatever those writes were, the \
                         server never heard of them and never will.",
                        devices[index].id
                    ),
                ));
            }

            coverage.full_resyncs += 1;
        }
    }
}
// ---------------------------------------------------------------------------
// The invariants
// ---------------------------------------------------------------------------

fn check<B: Backend>(devices: &[Device], model: &Model, backend: &B) -> Option<Failure> {
    for device in devices {
        if device.locked {
            return Failure::new("locked", format!("device {} never unlocked", device.id));
        }
    }

    let live: Vec<BTreeSet<String>> = devices.iter().map(Device::live).collect();
    let stamps: Vec<BTreeMap<String, Hlc>> = devices.iter().map(Device::timestamps).collect();

    // 1. Identical entry sets.
    for i in 1..devices.len() {
        if live[i] != live[0] {
            let missing: Vec<&String> = live[0].difference(&live[i]).collect();
            let extra: Vec<&String> = live[i].difference(&live[0]).collect();

            // A handful, explained, rather than hundreds listed. The list says
            // which entries disagree; these say why.
            let mut detail = String::new();
            for id in missing.iter().take(3).chain(extra.iter().take(3)) {
                detail.push_str(&format!("\n  {id}\n    server: {}", backend.describe(id)));
                for device in devices {
                    let held = device
                        .store_ref()
                        .get(id)
                        .unwrap()
                        .map(|record| {
                            format!(
                                "{} {}",
                                record.hlc,
                                if record.deleted { "deleted" } else { "live" }
                            )
                        })
                        .unwrap_or_else(|| "absent".to_string());
                    let queued = match device.queued(id) {
                        Some(Some(base)) => format!(", queued with base {base}"),
                        Some(None) => ", queued as a create".to_string(),
                        None => String::new(),
                    };
                    detail.push_str(&format!(
                        "\n    device {}: {held}{queued}, cursor {}",
                        device.id,
                        device.store_ref().cursor().unwrap()
                    ));
                }
            }

            return Failure::new(
                "entry sets",
                format!(
                    "device 0 and device {i} hold different entries: device {i} is \
                     missing {} and has {} that device 0 does not.\n{}{detail}",
                    missing.len(),
                    extra.len(),
                    backend.summary(),
                ),
            );
        }
    }

    // 2. Identical timestamp for every entry, tombstones included. Agreeing on
    //    the set but not on the version means the next write picks a different
    //    winner on each device, and the disagreement comes back later.
    for i in 1..devices.len() {
        if stamps[i] != stamps[0] {
            let differing: Vec<String> = stamps[0]
                .keys()
                .chain(stamps[i].keys())
                .filter(|id| stamps[0].get(*id) != stamps[i].get(*id))
                .cloned()
                .collect();
            return Failure::new(
                "timestamps",
                format!("device 0 and device {i} disagree on the timestamp of {differing:?}"),
            );
        }
    }

    // 3. No entry resurrected after a delete.
    for id in &model.deleted {
        if live[0].contains(id) {
            return Failure::new(
                "resurrection",
                format!("{id} was deleted and is live again. The delete must win."),
            );
        }
    }

    // 4. Every counter equals the largest any device reached.
    for (id, expected) in &model.max_counter {
        if !live[0].contains(id) {
            continue;
        }
        for device in devices {
            match device.counter_of(id) {
                Some(actual) if actual == *expected => {}
                Some(actual) => {
                    return Failure::new(
                        "counter",
                        format!(
                            "device {} holds counter {actual} for {id}, but {expected} \
                             was written on some device and never withdrawn",
                            device.id
                        ),
                    );
                }
                None => {
                    return Failure::new(
                        "unreadable",
                        format!("device {} cannot read {id}", device.id),
                    );
                }
            }
        }
    }

    // 5. The oracle. Everything above proves the devices agree; this is the
    //    only check that proves they are right.
    let expected = model.expected_live();
    if live[0] != expected {
        let missing: Vec<&String> = expected.difference(&live[0]).collect();
        let extra: Vec<&String> = live[0].difference(&expected).collect();
        return Failure::new(
            "oracle",
            format!(
                "the devices agree with each other but not with the model: \
                 {missing:?} were added and never deleted but are gone, and \
                 {extra:?} are present but should not be"
            ),
        );
    }

    // 6. Sync liveness (PRD section 17): after quiescence with every device
    //    unlocked, no entry holds a pending reconcile record.
    //
    //    A deferral must end when a key is available. Section 10.4 step 5
    //    refuses to produce a code for an entry with a candidate outstanding,
    //    so an entry that never clears reads to the user as a broken account
    //    rather than as a sync defect — which is why this is an invariant and
    //    not a diagnostic.
    //
    //    Every device unlocked immediately before its last cycle, so its
    //    candidates were applied and cleared, and that cycle wrote nothing.
    //    Anything pending now was recorded for a record the device already
    //    held — and a record identical to the one you hold is not a conflict.
    //    Without this check such a cycle looks healthy: the counters still
    //    agree, while every HOTP entry it touched quietly refuses to produce a
    //    code until the next unlock.
    for device in devices {
        let pending = device.store_ref().reconcile_pending().unwrap();
        if !pending.is_empty() {
            let held = device.timestamps();
            let detail: Vec<String> = pending
                .iter()
                .map(|candidate| {
                    let current = held.get(&candidate.entry_id);
                    match (candidate.hlc, current) {
                        (Some(theirs), Some(ours)) if theirs == *ours => {
                            format!(
                                "{} at {theirs}, the version already held",
                                candidate.entry_id
                            )
                        }
                        (Some(theirs), Some(ours)) => {
                            format!("{} at {theirs}, against {ours} held", candidate.entry_id)
                        }
                        (Some(theirs), None) => {
                            format!("{} at {theirs}, entry not held", candidate.entry_id)
                        }
                        (None, _) => format!("{}, timestamp unknown", candidate.entry_id),
                    }
                })
                .collect();
            return Failure::new(
                "sync liveness",
                format!(
                    "device {} has {} reconcile records outstanding after a cycle \
                     that wrote nothing and followed an unlock that cleared them: {detail:#?}",
                    device.id,
                    pending.len(),
                ),
            );
        }
    }

    // 7. No nonce was ever used twice under the one vault key. A repeat breaks
    //    XChaCha20-Poly1305 outright, and nothing announces it. Asserted over
    //    every write in the run rather than in a test of its own.
    let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
    let mut total = 0usize;
    for device in devices {
        for nonce in device.nonces.emitted() {
            total += 1;
            if !seen.insert(nonce) {
                return Failure::new(
                    "nonce reuse",
                    format!(
                        "device {} emitted a nonce already used under the same vault key",
                        device.id
                    ),
                );
            }
        }
    }
    debug_assert!(total > 0 || model.added.is_empty());

    None
}

// ---------------------------------------------------------------------------
// Shrinking
// ---------------------------------------------------------------------------

/// Finds a short operation list that fails the same way.
///
/// A thousand-operation trace names the bug and explains nothing. This removes
/// operations while the failure survives, so what gets printed is close to the
/// smallest thing that reproduces it.
fn shrink<B: Backend>(seed: u64, kind: &str, ops: &[Op], fresh: &dyn Fn() -> B) -> (Vec<Op>, bool) {
    // The budget is operations replayed, not replays.
    //
    // It was a replay count, and that is the wrong unit: a replay of a
    // thousand operations is instant and a replay of a hundred thousand is
    // minutes, so one number cannot serve both. A hundred-thousand-operation
    // failure spent ten minutes shrinking without printing anything, which is
    // exactly the run that most needs a short trace and least tolerates
    // waiting for one.
    //
    // Counting the operations actually replayed makes the bound mean the same
    // thing at every size, and makes the cheap phase — the prefix search,
    // which halves the length each probe — affordable everywhere while the
    // expensive one stops when it has had its share.
    let budget = std::cell::Cell::new(fresh().shrink_budget());
    let fails_the_same_way = |candidate: &[Op]| {
        budget.set(budget.get().saturating_sub(candidate.len().max(1)));
        run(seed, candidate, &mut fresh())
            .failure
            .is_some_and(|failure| failure.kind == kind)
    };
    let mut best = ops.to_vec();

    // The shortest failing prefix first: the cheapest large reduction.
    let mut low = 0;
    let mut high = best.len();
    while low < high {
        let mid = low + (high - low) / 2;
        if fails_the_same_way(&best[..mid]) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    if low < best.len() && fails_the_same_way(&best[..low]) {
        best.truncate(low);
    }

    // Then delta debugging: cut chunks, halving the chunk size each time the
    // list survives a whole pass. Removing operations one at a time is O(n^2)
    // replays, which is fine for the thousand-operation suite and hopeless for
    // the hundred-thousand-operation one — the run that most needs a readable
    // trace is the run that would never produce one.
    let mut chunk = (best.len() / 2).max(1);
    while chunk >= 1 {
        let mut start = 0;
        while start < best.len() {
            if budget.get() == 0 {
                return (best, true);
            }
            let end = (start + chunk).min(best.len());
            let mut candidate = Vec::with_capacity(best.len() - (end - start));
            candidate.extend_from_slice(&best[..start]);
            candidate.extend_from_slice(&best[end..]);

            if !candidate.is_empty() && fails_the_same_way(&candidate) {
                best = candidate;
                // `start` stays put: the chunk that follows has moved into it.
            } else {
                start = end;
            }
        }
        if chunk == 1 {
            break;
        }
        chunk /= 2;
    }
    (best, false)
}
// ---------------------------------------------------------------------------
// Driving one run
// ---------------------------------------------------------------------------

pub fn operation_count() -> usize {
    std::env::var("CONVERGENCE_OPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_OPS)
}

pub fn go<B: Backend>(seed: u64, count: usize, fresh: &dyn Fn() -> B) {
    let mut rng = Rng::new(seed);
    let ops = generate(&mut rng, count);
    let mut backend = fresh();
    let can_prune = backend.can_prune();
    let can_replay = backend.can_replay_pushes();
    let outcome = run(seed, &ops, &mut backend);

    if let Some(failure) = outcome.failure {
        // Printed before shrinking, not after. Shrinking a long run replays it
        // thousands of times, and waiting all of that to find out even *what*
        // broke is the difference between a harness you use and one you turn
        // off.
        println!(
            "seed {seed:#x}, {count} operations: {} — {}
shrinking...",
            failure.kind, failure.detail
        );
        let (minimal, truncated) = shrink(seed, failure.kind, &ops, fresh);
        let trace = minimal
            .iter()
            .enumerate()
            .map(|(i, op)| format!("  {i:>4}: {op:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        // The detail from the *shrunk* run, not the original: they fail the
        // same way, but the short one names the entry you can actually follow
        // through the trace printed below it.
        let detail = run(seed, &minimal, &mut fresh())
            .failure
            .map(|shrunk| shrunk.detail)
            .unwrap_or(failure.detail);
        panic!(
            "\nseed: {seed:#x}\noperations: {count}\n\
             broken invariant: {}\n{detail}\n\
             shrunk from {} operations to {}{}:\n{trace}\n",
            failure.kind,
            ops.len(),
            minimal.len(),
            if truncated {
                ", which is as far as the budget reached — this is not minimal"
            } else {
                ", still failing the same way"
            },
        );
    }

    // The coverage floor. A run that converged without ever conflicting has
    // not tested convergence.
    if let Err(gap) = outcome.coverage.check(count, can_prune, can_replay) {
        panic!("\nseed: {seed:#x}\n{gap}\n");
    }

    // Captured unless the run asked for --nocapture, and worth having then:
    // the floor says only that each count cleared zero, and the numbers say
    // whether one of them is clearing it on a single lucky event.
    println!("seed {seed:#x}, {count} operations: {:?}", outcome.coverage);
}
