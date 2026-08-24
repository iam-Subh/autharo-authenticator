//! The vault: payloads in, records out (PRD sections 9.3, 12.1, 12.2).
//!
//! [`Store`] deals only in ciphertext and [`Payload`] is only plaintext. This
//! module is the single place the two meet, so stage S3 changes the cipher here
//! and nothing above this layer moves.
//!
//! The only implementation is [`crate::crypto::XChaChaCipher`]. Stage S2
//! shipped a `NullCipher` behind a non-default feature so that plaintext
//! storage could not happen by accident; stage S3 deleted it, which broke
//! every crate that had opted in and forced each onto the real cipher. That
//! was the point of putting it behind a feature rather than a default.

use core::fmt;

use zeroize::Zeroizing;

use crate::entry::{Payload, PayloadError};
use crate::hlc::{Hlc, HlcClock};
use crate::store::{Record, Store, StoreError, new_entry_id};

/// One sealed record, ready for the `entry` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Why a seal or an open failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// The ciphertext did not authenticate. Either the key is wrong or the
    /// record was altered, and section 9.3 requires that both are refused.
    NotAuthentic,
    /// The cipher could not run at all.
    Unavailable { reason: String },
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthentic => write!(
                f,
                "This entry could not be decrypted. It was changed, or it belongs to a \
                 different vault."
            ),
            Self::Unavailable { reason } => {
                write!(f, "The vault could not be opened: {reason}")
            }
        }
    }
}

impl std::error::Error for CipherError {}

/// Named separately from the module's `Result` alias, which carries
/// [`VaultError`]. A cipher fails for its own reasons.
pub type CipherResult<T> = core::result::Result<T, CipherError>;

/// Encrypts and decrypts one record.
///
/// `entry_id` and `record_version` are the associated data required by section
/// 9.3: binding them stops an attacker moving a valid ciphertext onto a
/// different entry. They are arguments rather than something the implementation
/// digs out of the payload, so the binding cannot be forgotten.
pub trait RecordCipher {
    fn seal(&self, entry_id: &str, record_version: u32, plaintext: &[u8]) -> CipherResult<Sealed>;

    fn open(
        &self,
        entry_id: &str,
        record_version: u32,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> CipherResult<Zeroizing<Vec<u8>>>;
}

/// Anything that stops a vault operation.
#[derive(Debug)]
pub enum VaultError {
    Store(StoreError),
    Payload(PayloadError),
    Cipher(CipherError),
    /// The entry is not in this vault.
    NotFound {
        id: String,
    },
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(inner) => write!(f, "{inner}"),
            Self::Payload(inner) => write!(f, "{inner}"),
            Self::Cipher(inner) => write!(f, "{inner}"),
            Self::NotFound { id } => write!(f, "No entry with the identifier {id} is stored."),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<PayloadError> for VaultError {
    fn from(value: PayloadError) -> Self {
        Self::Payload(value)
    }
}
impl From<CipherError> for VaultError {
    fn from(value: CipherError) -> Self {
        Self::Cipher(value)
    }
}

type Result<T> = core::result::Result<T, VaultError>;

/// What one call to [`Vault::sync`] did.
///
/// Two reports rather than one merged count, because they answer different
/// questions: the cycle says what moved between this device and the server,
/// and the reconcile says what section 10.4's counter rule had to correct
/// afterwards. A caller watching for trouble wants the second on its own.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub cycle: crate::sync::CycleReport,
    pub reconcile: crate::reconcile::ReconcileReport,
}

/// What one call to [`Vault::full_resync`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResyncOutcome {
    /// Records taken from the server.
    pub applied: usize,
    pub reconcile: crate::reconcile::ReconcileReport,
}

/// Why a [`Vault::sync`] stopped.
///
/// The two halves stay distinguishable: a cycle failure is usually the network
/// and worth retrying, while a reconcile failure is local and is not.
#[derive(Debug)]
pub enum SyncFailure {
    Cycle(crate::sync::SyncError),
    Reconcile(crate::reconcile::ReconcileError),
}

impl fmt::Display for SyncFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cycle(inner) => write!(f, "{inner}"),
            Self::Reconcile(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for SyncFailure {}

impl From<crate::sync::SyncError> for SyncFailure {
    fn from(value: crate::sync::SyncError) -> Self {
        Self::Cycle(value)
    }
}

impl From<crate::reconcile::ReconcileError> for SyncFailure {
    fn from(value: crate::reconcile::ReconcileError) -> Self {
        Self::Reconcile(value)
    }
}

/// One entry, decrypted.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultEntry {
    pub id: String,
    pub payload: Payload,
    pub hlc: Hlc,
}

/// The record version written into the associated data. It moves when the
/// wire shape of a record changes, not when `EntryPayload` gains a field.
pub const RECORD_VERSION: u32 = 1;

/// The local vault.
pub struct Vault<C: RecordCipher> {
    store: Store,
    cipher: C,
    clock: HlcClock,
}

impl<C: RecordCipher> Vault<C> {
    /// Opens a vault over an existing store.
    ///
    /// The HLC clock resumes from the highest timestamp already written, so a
    /// restart cannot issue a timestamp below one this device already used.
    pub fn open(store: Store, cipher: C) -> Result<Self> {
        let device = store.device_id()?;
        let highest = store.list(true)?.into_iter().map(|record| record.hlc).max();

        let clock = match highest {
            Some(last) => HlcClock::resume(device, last),
            None => HlcClock::new(device),
        };
        Ok(Self {
            store,
            cipher,
            clock,
        })
    }

    /// Every live entry, decrypted, newest first.
    ///
    /// A record that fails to open is skipped rather than failing the whole
    /// list. One damaged row must not hide every other code the user needs.
    /// The count of skipped rows comes back so the caller can surface it.
    pub fn list(&self) -> Result<(Vec<VaultEntry>, usize)> {
        let mut entries = Vec::new();
        let mut unreadable = 0usize;

        for record in self.store.list(false)? {
            let opened = self.cipher.open(
                &record.id,
                RECORD_VERSION,
                &record.ciphertext,
                &record.nonce,
            );
            let Ok(plaintext) = opened else {
                unreadable += 1;
                continue;
            };
            match Payload::from_json(&plaintext) {
                Ok(payload) => entries.push(VaultEntry {
                    id: record.id,
                    payload,
                    hlc: record.hlc,
                }),
                Err(_) => unreadable += 1,
            }
        }
        Ok((entries, unreadable))
    }

    /// Reads one entry.
    pub fn get(&self, id: &str) -> Result<VaultEntry> {
        let record = self
            .store
            .get(id)?
            .filter(|record| !record.deleted)
            .ok_or_else(|| VaultError::NotFound { id: id.to_string() })?;

        let plaintext = self.cipher.open(
            &record.id,
            RECORD_VERSION,
            &record.ciphertext,
            &record.nonce,
        )?;
        Ok(VaultEntry {
            id: record.id,
            payload: Payload::from_json(&plaintext)?,
            hlc: record.hlc,
        })
    }

    /// Adds a new entry and returns its identifier.
    pub fn add(&mut self, payload: &Payload, now_ms: i64) -> Result<String> {
        let id = new_entry_id();
        self.write(&id, payload, now_ms, None)?;
        Ok(id)
    }

    /// Runs one sync cycle against this vault's store, and then the reconcile
    /// the cycle may have left work for (PRD sections 10.3, 10.4, OFF-09).
    ///
    /// # Why the cycle uses this vault's clock
    ///
    /// Because it has to be the same one. The cycle folds every timestamp it
    /// sees into the clock, so that a later local write sorts after what this
    /// device has already observed. A cycle run against a *separate* clock
    /// would leave the vault's clock behind, and the next local edit could
    /// then be issued below a remote record it is meant to supersede — losing
    /// a conflict it should win, silently.
    ///
    /// A locked device has no `Vault`, so it calls [`crate::sync::run_cycle`]
    /// directly with a clock resumed from its stored records. Reopening the
    /// vault resumes from the highest stored timestamp, so the two paths meet.
    ///
    /// # Why the reconcile runs here and not only at unlock
    ///
    /// Section 10.4 defers the counter rule because the cycle may have no key.
    /// This one does. A conflict settled during a cycle on an *unlocked* device
    /// leaves a candidate that only the unlock path applies — and a device that
    /// is already unlocked has no unlock coming. Until one does, section 10.4
    /// step 5 refuses to produce a code for that entry, so an ordinary sync
    /// would quietly stop an entry working for as long as the app stayed open.
    ///
    /// Applying it here closes that: the deferral lasts exactly as long as the
    /// absence of a key, which is what it was for.
    ///
    /// Note the direction: `Vault` calls into `sync` and `reconcile`, never the
    /// reverse. That is what keeps `sync` free of any way to read a payload.
    pub fn sync<T: crate::sync::SyncTransport>(
        &mut self,
        transport: &mut T,
        now_ms: u64,
    ) -> core::result::Result<SyncOutcome, SyncFailure> {
        let cycle = crate::sync::run_cycle(&mut self.store, &mut self.clock, transport, now_ms)?;
        let reconcile = crate::reconcile::run(self)?;
        Ok(SyncOutcome { cycle, reconcile })
    }

    /// Section 10.6's full re-sync, against this vault's store and clock.
    ///
    /// Here for the same two reasons as [`Self::sync`]: the re-sync folds every
    /// timestamp it takes from the server into the clock, and it can leave
    /// reconcile records that this device has the key to apply now.
    pub fn full_resync<T: crate::sync::SyncTransport>(
        &mut self,
        transport: &mut T,
        now_ms: u64,
    ) -> core::result::Result<ResyncOutcome, SyncFailure> {
        let applied =
            crate::sync::full_resync(&mut self.store, &mut self.clock, transport, now_ms)?;
        let reconcile = crate::reconcile::run(self)?;
        Ok(ResyncOutcome { applied, reconcile })
    }

    /// The clock this vault issues timestamps from, for a caller that has to
    /// hand the same one to a locked cycle after this vault is dropped.
    pub fn clock(&self) -> HlcClock {
        self.clock.clone()
    }

    /// Writes a payload under a timestamp the caller chose.
    ///
    /// Used only by [`crate::reconcile`], which derives the corrected
    /// timestamp from the conflicting records rather than from a clock
    /// (section 10.4 step 7). Every other write goes through the vault's own
    /// clock; this exists because a clock read there would walk around the
    /// drift bound in section 10.2, which applies to incoming values only.
    ///
    /// The supplied timestamp is folded into the vault's clock, so later local
    /// writes still sort after it.
    pub fn write_with_hlc(
        &mut self,
        id: &str,
        payload: &Payload,
        hlc: Hlc,
        base_hlc: Option<Hlc>,
    ) -> Result<()> {
        let plaintext = payload.to_json()?;
        let sealed = self.cipher.seal(id, RECORD_VERSION, &plaintext)?;
        self.clock.observe(hlc, hlc.wall_ms);

        self.store.write_local(
            &Record {
                id: id.to_string(),
                ciphertext: sealed.ciphertext,
                nonce: sealed.nonce,
                hlc,
                deleted: false,
                server_seq: None,
                // Display only (section 12.1), and derived from the timestamp
                // rather than read from a clock.
                updated_at: hlc.wall_ms as i64,
            },
            base_hlc,
        )?;
        Ok(())
    }

    /// Seals a payload for a given entry identifier without storing it.
    ///
    /// The counterpart to [`Self::open_record`]. Used where a record has to be
    /// produced for an entry that is not the one currently stored — the
    /// reconcile path in section 10.4, and the tests that stand in for another
    /// device. The associated data binds the identifier, so a record sealed
    /// here opens only under that identifier.
    pub fn seal_record(&self, id: &str, payload: &Payload) -> Result<(Vec<u8>, Vec<u8>)> {
        let plaintext = payload.to_json()?;
        let sealed = self
            .cipher
            .seal(id, RECORD_VERSION, &plaintext)
            .map_err(VaultError::Cipher)?;
        Ok((sealed.ciphertext, sealed.nonce))
    }

    /// Opens a ciphertext that is not the one currently stored for `id`.
    ///
    /// Used by [`crate::reconcile`] to read the discarded side of a conflict,
    /// which the sync cycle kept precisely because it no longer exists in the
    /// entry table. The associated data still binds the entry identifier and
    /// the record version, so this cannot be used to open a ciphertext
    /// belonging to a different entry.
    pub fn open_record(&self, id: &str, ciphertext: &[u8], nonce: &[u8]) -> Result<Payload> {
        let plaintext = self
            .cipher
            .open(id, RECORD_VERSION, ciphertext, nonce)
            .map_err(VaultError::Cipher)?;
        Ok(Payload::from_json(&plaintext)?)
    }

    /// Replaces the payload of an existing entry (FR-17).
    pub fn update(&mut self, id: &str, payload: &Payload, now_ms: i64) -> Result<()> {
        let existing = self
            .store
            .get(id)?
            .ok_or_else(|| VaultError::NotFound { id: id.to_string() })?;
        self.write(id, payload, now_ms, Some(existing.hlc))
    }

    /// Deletes an entry, leaving a tombstone (FR-18).
    pub fn delete(&mut self, id: &str, now_ms: i64) -> Result<()> {
        let hlc = self.clock.tick(now_ms.max(0) as u64);
        if !self.store.tombstone(id, hlc, now_ms)? {
            return Err(VaultError::NotFound { id: id.to_string() });
        }
        Ok(())
    }

    /// FR-16: finds an existing entry holding the same secret.
    ///
    /// The comparison runs over decrypted payloads, because the server must not
    /// be able to spot a duplicate and neither can a ciphertext comparison —
    /// two encryptions of the same secret differ.
    pub fn find_by_secret(&self, secret: &str) -> Result<Option<String>> {
        let (entries, _) = self.list()?;
        Ok(entries
            .into_iter()
            .find(|entry| {
                entry
                    .payload
                    .as_otp()
                    .is_some_and(|otp| otp.secret.expose() == secret)
            })
            .map(|entry| entry.id))
    }

    /// The stored offset between device time and reference time (FR-38).
    pub fn time_offset_seconds(&self) -> Result<i64> {
        Ok(self.store.time_offset_seconds()?)
    }

    pub fn set_time_offset_seconds(&self, offset: i64) -> Result<()> {
        Ok(self.store.set_time_offset_seconds(offset)?)
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Takes the store back, so a vault can be reopened with a different
    /// cipher. Stage S3 needs this to re-key an existing database.
    pub fn into_store(self) -> Store {
        self.store
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }

    fn write(
        &mut self,
        id: &str,
        payload: &Payload,
        now_ms: i64,
        base_hlc: Option<Hlc>,
    ) -> Result<()> {
        let plaintext = payload.to_json()?;
        let sealed = self.cipher.seal(id, RECORD_VERSION, &plaintext)?;
        let hlc = self.clock.tick(now_ms.max(0) as u64);

        self.store.write_local(
            &Record {
                id: id.to_string(),
                ciphertext: sealed.ciphertext,
                nonce: sealed.nonce,
                hlc,
                deleted: false,
                server_seq: None,
                updated_at: now_ms,
            },
            base_hlc,
        )?;
        Ok(())
    }
}
