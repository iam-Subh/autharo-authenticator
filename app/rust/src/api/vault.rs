//! The Dart-facing surface of the vault.
//!
//! This crate is a translation layer and nothing more. Every rule — what a
//! valid period is, how a duplicate is detected, which timestamp wins — lives
//! in `authcore`, so that the audit in section 14.2 covers one implementation
//! rather than one per platform.
//!
//! Three conventions hold throughout:
//!
//! - **No clock reads.** Dart passes the reference time in. It is the device
//!   clock plus the stored offset (FR-38), and keeping it a parameter is what
//!   lets the whole list render from one consistent instant.
//! - **No secrets returned.** A code goes out; the Base32 secret does not. The
//!   one exception is [`reveal_secret_for_export`], named to be hard to call
//!   by accident.
//! - **Vault keys do not enter Dart on Android.** The device slot needs the
//!   platform keystore, but Rust and Kotlin now exchange protected bytes over
//!   JNI. Dart carries only random one-time handles between those operations.

use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use authcore::account;
use authcore::crypto::{VaultKey, XChaChaCipher};
use authcore::device_slot::{self, OpenRequest, SetupRequest, SlotState};
use authcore::entry::{OtpEntry, Payload};
use authcore::lock_policy::LockPolicy;
use authcore::otp::{self, Algorithm, OtpKind};
use authcore::otpauth::OtpAuthUri;
use authcore::reconcile;
use authcore::store::{MetaStore, Store};
use authcore::vault::Vault;
use zeroize::Zeroizing;

/// The metadata file. Opened first and independently of the vault, because it
/// holds the wrapped key the vault needs (section 12.1).
static META: Mutex<Option<MetaStore>> = Mutex::new(None);

/// The open vault. `None` means locked: FR-31 requires that locking zeroes the
/// vault key, and dropping the vault drops the only copy of it.
static VAULT: Mutex<Option<Vault<XChaChaCipher>>> = Mutex::new(None);

/// A setup or unlock waiting on the platform keystore.
static PENDING_SETUP: Mutex<Option<SetupRequest>> = Mutex::new(None);
static PENDING_OPEN: Mutex<Option<OpenRequest>> = Mutex::new(None);

/// The vault key, kept only while unlocked.
///
/// Held so that the PIN can be set, changed, or removed without making the
/// user unlock a second time — rewrapping needs the key itself, and the vault
/// only keeps subkeys derived from it. Cleared by `lock_vault` along with
/// everything else, so it lives exactly as long as the unlocked session.
static CURRENT_KEY: Mutex<Option<VaultKey>> = Mutex::new(None);

/// A recovery slot prepared for confirmation but not committed.
///
/// It contains ciphertext only. It stays process-local so a cancelled screen
/// or application lock cannot change the accepted recovery phrase.
static PENDING_RECOVERY_SLOT: Mutex<Option<account::RecoverySlot>> = Mutex::new(None);

const BIOMETRIC_WRAPPED_KEY: &str = "device.biometric.wrapped_key";
const BIOMETRIC_NONCE: &str = "device.biometric.nonce";
#[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
const VAULT_PAGE_KEY: &str = "vault.page_key.v1";

/// Converts a protected value into the platform representation.
///
/// Android stores the value in a short-lived Rust registry and returns a
/// random handle. Other targets keep the former byte path until each platform
/// gets its own native keystore bridge.
fn secret_for_platform(value: Vec<u8>) -> Result<Vec<u8>> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        crate::vault_key_bridge::store_secret(value)
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        Ok(value)
    }
}

/// Resolves the platform representation into protected bytes inside Rust.
fn secret_from_platform(value: Vec<u8>) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        crate::vault_key_bridge::take_secret(&value)
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        Ok(Zeroizing::new(value))
    }
}

/// Cancels setup and unlock state after a platform prompt is dismissed.
pub(crate) fn cancel_pending_keystore_operations() {
    if let Ok(mut setup) = PENDING_SETUP.lock() {
        setup.take();
    }
    if let Ok(mut open) = PENDING_OPEN.lock() {
        open.take();
    }
}

fn lock_poisoned() -> anyhow::Error {
    anyhow!("The vault lock was poisoned by an earlier failure. Restart the application.")
}

/// Reads the metadata file, wherever it currently lives.
///
/// While locked it sits in `META`; while unlocked the `Store` owns it. Callers
/// that only want to read it — the slot state, the time offset — should not
/// have to know which, and should not fail merely because the vault happens to
/// be open.
pub(crate) fn with_meta_pub<T>(f: impl FnOnce(&MetaStore) -> Result<T>) -> Result<T> {
    with_meta(f)
}

/// Returns the unlocked vault key to another Rust module.
///
/// This value never enters Dart or the Android method channel. Account-slot
/// maintenance uses it inside the Rust library only.
pub(crate) fn current_vault_key() -> Result<VaultKey> {
    CURRENT_KEY
        .lock()
        .map_err(|_| lock_poisoned())?
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("Unlock the vault before changing account security."))
}

/// Prepares an empty local vault to adopt a synchronized account key.
///
/// Android receives a random JNI handle. It never receives the key bytes in
/// Dart. A non-empty vault is refused because changing its record key would
/// make existing entries unreadable.
pub(crate) fn begin_empty_vault_key_adoption(key: VaultKey) -> Result<Vec<u8>> {
    let has_records = with_vault(|vault| Ok(!vault.store().list(true)?.is_empty()))?;
    if has_records {
        anyhow::bail!(
            "This device already has entries. Export or synchronize them before joining another vault."
        );
    }
    let has_pin = with_meta(|meta| {
        Ok(matches!(
            device_slot::state(meta).map_err(|error| anyhow!("{error}"))?,
            SlotState::PresentNeedsPin
        ))
    })?;
    if has_pin {
        anyhow::bail!(
            "Remove the device PIN before joining an existing account. Set the PIN again after sign-in."
        );
    }
    let request = device_slot::rewrap_without_pin(key).map_err(|error| anyhow!("{error}"))?;
    let handle = secret_for_platform(request.key_to_wrap().to_vec())?;
    *PENDING_SETUP.lock().map_err(|_| lock_poisoned())? = Some(request);
    Ok(handle)
}

pub(crate) fn finish_account_key_adoption(
    vault_path: &str,
    wrapped: Vec<u8>,
    nonce: Vec<u8>,
    new_account: &account::Account,
) -> Result<()> {
    let request = PENDING_SETUP
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| anyhow!("No account sign-in is in progress."))?;
    let mut meta = take_meta()?;
    let key = request
        .complete(&mut meta, wrapped, nonce)
        .map_err(|error| anyhow!("{error}"))?;
    account::save(&meta, new_account).map_err(|error| anyhow!("{error}"))?;
    meta.remove(BIOMETRIC_WRAPPED_KEY)?;
    meta.remove(BIOMETRIC_NONCE)?;
    open_vault_with_key(vault_path, meta, key)
}

fn with_meta<T>(f: impl FnOnce(&MetaStore) -> Result<T>) -> Result<T> {
    if let Some(vault) = VAULT.lock().map_err(|_| lock_poisoned())?.as_ref() {
        return f(vault.store().meta());
    }
    let guard = META.lock().map_err(|_| lock_poisoned())?;
    let meta = guard
        .as_ref()
        .ok_or_else(|| anyhow!("The metadata file is not open."))?;
    f(meta)
}

/// Takes ownership of the metadata file so a vault can be opened with it.
///
/// If a vault is already open this locks it first, because the metadata file
/// cannot be in two places at once. Re-opening over an open vault is what an
/// unlock after a lock timeout looks like, so it has to work rather than fail.
pub(crate) fn take_meta() -> Result<MetaStore> {
    if let Some(meta) = META.lock().map_err(|_| lock_poisoned())?.take() {
        return Ok(meta);
    }
    let vault = VAULT
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| anyhow!("The metadata file is not open."))?;
    Ok(vault.into_store().into_meta())
}

pub(crate) fn restore_meta(meta: MetaStore) -> Result<()> {
    *META.lock().map_err(|_| lock_poisoned())? = Some(meta);
    Ok(())
}

pub(crate) fn metadata_is_open() -> Result<bool> {
    if VAULT.lock().map_err(|_| lock_poisoned())?.is_some() {
        return Ok(true);
    }
    Ok(META.lock().map_err(|_| lock_poisoned())?.is_some())
}

pub(crate) fn page_key(_meta: &MetaStore) -> Result<String> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        let mut bytes = crate::session_store::read_or_create_page_key()?;
        let key = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        bytes.fill(0);
        Ok(key)
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        let bytes = _meta
            .get(VAULT_PAGE_KEY)?
            .ok_or_else(|| anyhow!("Unlock the vault once before background synchronization."))?;
        let key = String::from_utf8(bytes).context("The vault page key is not valid text")?;
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            anyhow::bail!("The vault page key is damaged.");
        }
        Ok(key)
    }
}

fn ensure_page_key(meta: &MetaStore) -> Result<String> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        page_key(meta)
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        if meta.get(VAULT_PAGE_KEY)?.is_some() {
            return page_key(meta);
        }
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow!("random generation failed: {error}"))?;
        let key = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        bytes.fill(0);
        meta.set(VAULT_PAGE_KEY, key.as_bytes())?;
        Ok(key)
    }
}

/// How many records are waiting to reach the server.
///
/// Fails while locked, which the caller must distinguish from zero.
pub(crate) fn outbox_len() -> Result<usize> {
    with_vault(|vault| Ok(vault.store().outbox()?.len()))
}

pub(crate) fn with_vault_pub<T>(
    f: impl FnOnce(&mut Vault<XChaChaCipher>) -> Result<T>,
) -> Result<T> {
    with_vault(f)
}

fn with_vault<T>(f: impl FnOnce(&mut Vault<XChaChaCipher>) -> Result<T>) -> Result<T> {
    let mut guard = VAULT.lock().map_err(|_| lock_poisoned())?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| anyhow!("The vault is locked."))?;
    f(vault)
}

/// The stored slot, on its way to the platform to be unwrapped.
pub struct WrappedKeyBlob {
    pub wrapped: Vec<u8>,
    pub nonce: Vec<u8>,
    /// `keystore-v1` or `keystore-pin-v1`.
    pub scheme: String,
    /// True when the user must supply a PIN as well (section 9.2.4 step 4).
    pub needs_pin: bool,
}

/// The optional biometric-only route to the same vault key.
pub struct BiometricKeyBlob {
    pub wrapped: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// One row of the code list, ready to render.
pub struct EntryView {
    pub id: String,
    /// `"totp"`, `"hotp"`, or `"steam"`.
    pub kind: String,
    pub issuer: Option<String>,
    pub account: String,
    pub code: String,
    /// The next time-based code. HOTP and blocked entries have no value.
    pub next_code: Option<String>,
    pub digits: u32,
    pub period: u32,
    /// Seconds until the code changes. Zero for HOTP, which does not expire.
    pub remaining_seconds: u32,
    pub counter: Option<u64>,
    pub favourite: bool,
    pub icon: Option<String>,
    pub note: String,
    pub tags: Vec<String>,
    /// FR-19: the folder this entry is filed in, if any.
    ///
    /// May name a folder that no longer exists — device A can delete a folder
    /// while device B files something into it. The list treats that as
    /// unfiled, which is the only reading that does not hide the entry.
    pub folder_id: Option<String>,
    /// Epoch milliseconds, for FR-22's "date added".
    ///
    /// The payload's own value, not the record's `updated_at`: an edit changes
    /// when a record was written and must not change where it sorts.
    pub created_at: i64,
    /// FR-22's manual order, a fractional index.
    ///
    /// Empty on an entry that has never been placed by hand, which sorts after
    /// everything that has — a new entry appearing in the middle of a list the
    /// user arranged would look like the arrangement had been lost.
    pub order: String,
    /// True when a conflict resolved while locked is still waiting for section
    /// 10.4's counter rule. `code` is empty and the interface must say why
    /// rather than showing a code that may be behind the issuer's counter.
    pub awaiting_reconcile: bool,
}

/// One entry in the trash. No code or secret leaves Rust for this view.
pub struct TrashEntryView {
    pub id: String,
    pub issuer: Option<String>,
    pub account: String,
    pub trashed_at: i64,
    pub purge_at: i64,
}

/// Trashed entries become tombstones after 30 days.
const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// What an `otpauth://` URI holds, shown before the user commits to adding it.
pub struct EntryPreview {
    pub kind: String,
    pub issuer: Option<String>,
    pub account: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub counter: Option<u64>,
    /// FR-16: the entry already holding this secret, if there is one.
    pub duplicate_of: Option<String>,
}

/// The result of adding an entry. Exactly one field is set.
pub struct AddOutcome {
    pub added_id: Option<String>,
    /// FR-16: an entry already holds this secret.
    pub duplicate_of: Option<String>,
}

impl AddOutcome {
    fn added(id: String) -> Self {
        Self {
            added_id: Some(id),
            duplicate_of: None,
        }
    }

    fn duplicate(existing_id: String) -> Self {
        Self {
            added_id: None,
            duplicate_of: Some(existing_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Device slot (section 9.2.4)
// ---------------------------------------------------------------------------

/// Deletes an unencrypted vault file if one is present (section 12.1 rule 4).
///
/// Must run before [`open_meta`]. Two earlier shapes qualify: the stage S2
/// file with plaintext payloads, and the stage S3 file whose payloads were
/// encrypted but whose pages were not. Neither opens under a key now.
///
/// Discarded rather than migrated because a copy-and-delete would leave the
/// old plaintext pages on flash, where wear levelling makes their removal
/// unprovable. Returns true when something was deleted, so the interface can
/// say so rather than leaving the user to guess why their entries vanished.
#[flutter_rust_bridge::frb(sync)]
pub fn discard_legacy_vault(vault_path: String, meta_path: String) -> Result<bool> {
    Ok(authcore::store::discard_unencrypted_vault(
        &vault_path,
        &meta_path,
    )?)
}

/// Opens the metadata file and reports what this device's key slot needs.
///
/// Returns `"absent"`, `"present"`, or `"present_needs_pin"`. Call this before
/// anything else: it decides whether the next step is setup or unlock.
#[flutter_rust_bridge::frb(sync)]
pub fn open_meta(meta_path: String) -> Result<String> {
    let meta = MetaStore::open(&meta_path).context("The metadata file could not be opened")?;
    let state = device_slot::state(&meta).map_err(|error| anyhow!("{error}"))?;

    *META.lock().map_err(|_| lock_poisoned())? = Some(meta);

    Ok(match state {
        SlotState::Absent => "absent",
        SlotState::Present => "present",
        SlotState::PresentNeedsPin => "present_needs_pin",
    }
    .to_string())
}

/// First run: generates the vault key and prepares it for platform wrapping.
///
/// On Android the returned bytes are a random one-time handle. Kotlin consumes
/// that handle through JNI, so the raw vault key does not enter Dart memory.
pub fn begin_device_setup() -> Result<Vec<u8>> {
    let request = device_slot::begin_setup().map_err(|error| anyhow!("{error}"))?;
    let key = request.key_to_wrap().to_vec();

    *PENDING_SETUP.lock().map_err(|_| lock_poisoned())? = Some(request);
    secret_for_platform(key)
}

/// First run with a PIN: seals the vault key under it, then hands the sealed
/// blob out to be wrapped by the keystore (section 9.2.4 step 4).
///
/// Android returns a one-time handle for the PIN-sealed blob. This keeps all
/// device-slot material out of Dart, including values that are already sealed.
pub fn begin_device_setup_with_pin(pin: String) -> Result<Vec<u8>> {
    let request = device_slot::begin_setup_with_pin(&pin).map_err(|error| anyhow!("{error}"))?;
    let blob = request.key_to_wrap().to_vec();

    *PENDING_SETUP.lock().map_err(|_| lock_poisoned())? = Some(request);
    secret_for_platform(blob)
}

/// Turns the PIN on, off, or changes it, keeping the same vault key.
///
/// The key must not change: every record is already encrypted under it, and
/// re-encrypting the vault to change a PIN would be both slow and a chance to
/// lose data. Returns the blob for the keystore to wrap, exactly as setup does.
pub fn begin_change_pin(new_pin: Option<String>) -> Result<Vec<u8>> {
    let key = CURRENT_KEY
        .lock()
        .map_err(|_| lock_poisoned())?
        .clone()
        .ok_or_else(|| anyhow!("Unlock the vault before changing the PIN."))?;

    let request = match new_pin {
        Some(pin) => device_slot::rewrap_with_pin(key, &pin),
        None => device_slot::rewrap_without_pin(key),
    }
    .map_err(|error| anyhow!("{error}"))?;

    let blob = request.key_to_wrap().to_vec();
    *PENDING_SETUP.lock().map_err(|_| lock_poisoned())? = Some(request);
    secret_for_platform(blob)
}

/// Stores the wrapped key and opens the vault (section 9.2.4 steps 3 and 5).
pub fn finish_device_setup(vault_path: String, wrapped: Vec<u8>, nonce: Vec<u8>) -> Result<()> {
    let request = PENDING_SETUP
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| anyhow!("No setup is in progress."))?;

    let mut meta = take_meta()?;
    let key = request
        .complete(&mut meta, wrapped, nonce)
        .map_err(|error| anyhow!("{error}"))?;

    open_vault_with_key(&vault_path, meta, key)
}

/// Unlock: reads the stored slot for the platform to unwrap.
pub fn begin_device_open() -> Result<WrappedKeyBlob> {
    let request = with_meta(|meta| {
        device_slot::begin_open(meta)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| anyhow!("This device has no key slot yet."))
    })?;

    let blob = WrappedKeyBlob {
        wrapped: request.wrapped_key().to_vec(),
        nonce: request.nonce().to_vec(),
        scheme: request.scheme().as_str().to_string(),
        needs_pin: request.scheme().needs_pin(),
    };

    *PENDING_OPEN.lock().map_err(|_| lock_poisoned())? = Some(request);
    Ok(blob)
}

/// Consumes the platform result and opens the vault.
///
/// On Android `unwrapped` is a one-time handle, not the vault key.
pub fn finish_device_open(vault_path: String, unwrapped: Vec<u8>) -> Result<()> {
    let unwrapped = secret_from_platform(unwrapped)?;
    let request = PENDING_OPEN
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| anyhow!("No unlock is in progress."))?;

    let key = request
        .complete(&unwrapped)
        .map_err(|error| anyhow!("{error}"))?;

    open_vault_with_key(&vault_path, take_meta()?, key)
}

/// Adopts the unwrapped blob and undoes the PIN layer inside it.
///
/// A wrong PIN increments the counter FR-35 reads; a right one clears it, so
/// the limit applies to consecutive failures.
pub fn finish_device_open_with_pin(
    vault_path: String,
    unwrapped: Vec<u8>,
    pin: String,
) -> Result<()> {
    // An empty PIN can never be valid — FR-31 sets a minimum length — so it is
    // not a guess, it is a malformed request, and it must not spend one of
    // FR-35's attempts.
    //
    // This is not hypothetical tidiness. The unlock screen's biometric button
    // called straight through to here with the PIN field untouched, so every
    // press reported "PIN is incorrect" and burned an attempt. With FR-35's
    // wipe armed, ten presses of a button that could never work would have
    // destroyed the vault.
    //
    // Refused here as well as on the screen, because the screen is not the
    // only caller and a counter that can be spent without a guess is a way to
    // destroy someone's data without ever attacking their PIN.
    if pin.is_empty() {
        return Err(anyhow!("Enter your PIN."));
    }

    let unwrapped = secret_from_platform(unwrapped)?;
    let request = PENDING_OPEN
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| anyhow!("No unlock is in progress."))?;

    let key = match request.complete_with_pin(&unwrapped, &pin) {
        Ok(key) => key,
        Err(error) => {
            // Counted before the error is returned, so a caller that stops
            // looking at the result still leaves the count correct.
            let wiped = record_failed_unlock()?;
            if wiped {
                return Err(anyhow!(
                    "Too many wrong attempts. This device has been wiped, as you                      asked it to be. Restore from a backup or from another                      device that has your account."
                ));
            }
            return Err(anyhow!("{error}"));
        }
    };

    let meta = take_meta()?;
    meta.clear_failed_unlocks()?;
    open_vault_with_key(&vault_path, meta, key)
}

/// Prepares the current vault key for a biometric-only Android slot.
///
/// Android receives a random one-time handle. Kotlin consumes the handle
/// through JNI and wraps the key without exposing it to Dart.
pub fn begin_biometric_setup() -> Result<Vec<u8>> {
    let key = CURRENT_KEY
        .lock()
        .map_err(|_| lock_poisoned())?
        .as_ref()
        .ok_or_else(|| anyhow!("Unlock the vault before enabling biometric unlock."))?
        .expose()
        .to_vec();
    secret_for_platform(key)
}

/// Stores the biometric-only slot after Android Keystore wraps it.
pub fn finish_biometric_setup(wrapped: Vec<u8>, nonce: Vec<u8>) -> Result<()> {
    if wrapped.is_empty() || nonce.is_empty() {
        return Err(anyhow!("The biometric key slot is incomplete."));
    }
    with_meta(|meta| {
        meta.set(BIOMETRIC_WRAPPED_KEY, &wrapped)?;
        meta.set(BIOMETRIC_NONCE, &nonce)?;
        Ok(())
    })
}

/// Reads the biometric-only slot for the locked screen.
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_blob() -> Result<Option<BiometricKeyBlob>> {
    with_meta(|meta| {
        let wrapped = meta.get(BIOMETRIC_WRAPPED_KEY)?;
        let nonce = meta.get(BIOMETRIC_NONCE)?;
        match (wrapped, nonce) {
            (None, None) => Ok(None),
            (Some(wrapped), Some(nonce)) => Ok(Some(BiometricKeyBlob { wrapped, nonce })),
            _ => Err(anyhow!("The biometric key slot is incomplete.")),
        }
    })
}

/// Returns every ciphertext that still references an Android Keystore alias.
/// Android uses this list after a metadata commit to delete superseded keys.
#[flutter_rust_bridge::frb(sync)]
pub fn active_keystore_ciphertexts() -> Result<Vec<Vec<u8>>> {
    with_meta(|meta| {
        let mut ciphertexts = Vec::new();
        if let Some(request) = device_slot::begin_open(meta).map_err(|error| anyhow!("{error}"))? {
            ciphertexts.push(request.wrapped_key().to_vec());
        }
        if let Some(wrapped) = meta.get(BIOMETRIC_WRAPPED_KEY)? {
            ciphertexts.push(wrapped);
        }
        Ok(ciphertexts)
    })
}

/// Removes biometric unlock without changing the PIN slot.
pub fn clear_biometric_key() -> Result<()> {
    with_meta(|meta| {
        meta.remove(BIOMETRIC_WRAPPED_KEY)?;
        meta.remove(BIOMETRIC_NONCE)?;
        Ok(())
    })
}

/// Opens the vault with the biometric Keystore result.
///
/// On Android `unwrapped` is a one-time handle, not the vault key.
pub fn finish_biometric_open(vault_path: String, unwrapped: Vec<u8>) -> Result<()> {
    let unwrapped = secret_from_platform(unwrapped)?;
    let key = VaultKey::from_slice(&unwrapped)
        .map_err(|_| anyhow!("The biometric key slot returned an invalid vault key."))?;
    let meta = take_meta()?;
    meta.clear_failed_unlocks()?;
    open_vault_with_key(&vault_path, meta, key)
}

// ---------------------------------------------------------------------------
// Sync account slots (sections 9.2.1, 9.2.3). No server exists until S4.
// ---------------------------------------------------------------------------

/// The recovery phrase, returned once at sign-up and never stored (FR-55).
pub struct RecoveryPhraseView {
    /// The 24 BIP-39 words, space separated.
    pub phrase: String,
    /// Zero-based positions the user must confirm before sign-up completes
    /// (section 9.2.3 step 4).
    pub confirm_indices: Vec<u32>,
}

/// Creates the password and recovery slots around the vault key this device
/// already holds.
///
/// The vault must be unlocked, because the slots wrap the key it holds.
/// Section 9.2.4 forbids generating a new one: every entry is already
/// encrypted under the existing key, and replacing it would orphan all of
/// them.
///
/// Nothing is sent anywhere. The server arrives in S4; until then the slots
/// sit in the metadata file waiting to be uploaded.
pub fn create_account(email: String, password: String) -> Result<RecoveryPhraseView> {
    let key = CURRENT_KEY
        .lock()
        .map_err(|_| lock_poisoned())?
        .clone()
        .ok_or_else(|| anyhow!("Unlock the vault before creating an account."))?;

    with_meta(|meta| {
        let (_, phrase) = account::create_account(meta, &email, &password, &key)
            .map_err(|error| anyhow!("{error}"))?;

        let confirm_indices = phrase
            .indices_to_confirm()
            .map_err(|error| anyhow!("{error}"))?
            .into_iter()
            .map(|index| index as u32)
            .collect();

        Ok(RecoveryPhraseView {
            phrase: phrase.as_str().to_string(),
            confirm_indices,
        })
    })
}

/// FR-29's second half: give the user a recovery phrase they can write down.
///
/// # This rotates, and the interface must say so
///
/// The phrase cannot be reprinted. It *is* the recovery key, 256 bits of it,
/// and section 9.2.3 stores only the vault key sealed under that key — the
/// direction that does not run backwards. So this generates a new phrase and
/// retires the old one, which is what a user in this situation actually needs:
/// they are asking because their copy is lost, destroyed, or was seen.
///
/// **The old phrase stops working.** Anyone who wrote it down — including the
/// user, on a card in a drawer — must replace it. A screen that offers this
/// without saying that has set up a lockout.
///
/// Re-authentication is the account password, per FR-29. Checked by actually
/// unwrapping the password slot rather than by comparing a stored value, so a
/// wrong password cannot get past it.
pub fn rotate_recovery_phrase(password: String) -> Result<RecoveryPhraseView> {
    let live = CURRENT_KEY
        .lock()
        .map_err(|_| lock_poisoned())?
        .clone()
        .ok_or_else(|| anyhow!("Unlock the vault before exporting a recovery phrase."))?;

    with_meta(|meta| {
        // The re-authentication. `unlock_with_password` fails on a wrong
        // password, so reaching the next line is the proof.
        let proven =
            account::unlock_with_password(meta, &password).map_err(|error| anyhow!("{error}"))?;

        // Belt and braces against the one mistake that would be silent and
        // total: wrapping the wrong key into the new slot, leaving a phrase
        // that opens a vault none of these entries belong to.
        if proven.expose() != live.expose() {
            return Err(anyhow!(
                "The stored password slot does not hold this vault's key.                  Nothing has been changed."
            ));
        }

        let (slot, phrase) =
            account::prepare_recovery_rotation(&live).map_err(|error| anyhow!("{error}"))?;
        *PENDING_RECOVERY_SLOT.lock().map_err(|_| lock_poisoned())? = Some(slot);

        let confirm_indices = phrase
            .indices_to_confirm()
            .map_err(|error| anyhow!("{error}"))?
            .into_iter()
            .map(|index| index as u32)
            .collect();

        Ok(RecoveryPhraseView {
            phrase: phrase.as_str().to_string(),
            confirm_indices,
        })
    })
}

/// Returns the pending slot after the supplied phrase proves that it opens
/// the current vault key.
pub(crate) fn pending_recovery_slot(phrase: &str) -> Result<account::RecoverySlot> {
    let slot = PENDING_RECOVERY_SLOT
        .lock()
        .map_err(|_| lock_poisoned())?
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("No recovery-phrase change is waiting for confirmation."))?;
    let live = current_vault_key()?;
    let candidate = account::Account {
        email: account_email()?.unwrap_or_default(),
        password_slot: None,
        recovery_slot: slot.clone(),
    };
    let opened = account::unlock_with_recovery_from_account(&candidate, phrase)
        .map_err(|error| anyhow!("{error}"))?;
    if opened.expose() != live.expose() {
        anyhow::bail!("The recovery phrase does not match the pending key slot.");
    }
    Ok(slot)
}

pub(crate) fn commit_pending_recovery_slot(slot: &account::RecoverySlot) -> Result<()> {
    with_meta(|meta| {
        let mut local_account = account::load(meta)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| anyhow!("This device has no sync account."))?;
        local_account.recovery_slot = slot.clone();
        account::save(meta, &local_account).map_err(|error| anyhow!("{error}"))
    })?;
    PENDING_RECOVERY_SLOT
        .lock()
        .map_err(|_| lock_poisoned())?
        .take();
    Ok(())
}

/// The email address of the sync account, or `None` on a local-only device.
#[flutter_rust_bridge::frb(sync)]
pub fn account_email() -> Result<Option<String>> {
    with_meta(|meta| {
        Ok(account::load(meta)
            .map_err(|error| anyhow!("{error}"))?
            .map(|account| account.email))
    })
}

/// The encrypted vault-key slot stored with one passkey credential.
pub struct PasskeyWrappedKeyView {
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Wraps the unlocked vault key with a WebAuthn PRF result.
///
/// The PRF result enters Rust. The raw vault key does not leave Rust.
pub fn create_passkey_wrapped_key(prf_result: Vec<u8>) -> Result<PasskeyWrappedKeyView> {
    let key = CURRENT_KEY
        .lock()
        .map_err(|_| lock_poisoned())?
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("Unlock the vault before registering a passkey."))?;
    let slot =
        account::wrap_with_passkey_prf(&key, &prf_result).map_err(|error| anyhow!("{error}"))?;
    Ok(PasskeyWrappedKeyView {
        wrapped_key: slot.wrapped_key,
        nonce: slot.nonce,
    })
}

/// Opens the vault with a verified passkey response and its PRF result.
///
/// The server verifies the WebAuthn response before it returns the encrypted
/// slot. This function only unwraps that slot. The raw vault key stays in Rust.
pub fn unlock_with_passkey(
    vault_path: String,
    prf_result: Vec<u8>,
    wrapped_key: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<()> {
    let slot = account::PasskeySlot { wrapped_key, nonce };
    let key =
        account::unlock_with_passkey_prf(&slot, &prf_result).map_err(|error| anyhow!("{error}"))?;
    open_vault_with_key(&vault_path, take_meta()?, key)
}

/// Opens the vault with the account password (section 9.2.1).
pub fn unlock_with_password(vault_path: String, password: String) -> Result<()> {
    let key = with_meta(|meta| {
        account::unlock_with_password(meta, &password).map_err(|error| anyhow!("{error}"))
    })?;
    open_vault_with_key(&vault_path, take_meta()?, key)
}

/// Opens the vault with the 24-word recovery phrase (section 16.4).
pub fn unlock_with_recovery(vault_path: String, phrase: String) -> Result<()> {
    let key = with_meta(|meta| {
        account::unlock_with_recovery(meta, &phrase).map_err(|error| anyhow!("{error}"))
    })?;
    open_vault_with_key(&vault_path, take_meta()?, key)
}

/// What this native library was built from (NFR-13).
pub struct BuildInfo {
    /// Full git commit hash, or `"unknown"` outside a checkout.
    pub commit: String,
    /// True when the working tree had uncommitted changes at build time. A
    /// dirty library cannot be matched against a commit, so a caller checking
    /// provenance has to fall back to the timestamp and say so.
    pub dirty: bool,
    /// Unix seconds at which this library was compiled.
    pub built_at: i64,
}

/// Reports what produced this `.so`.
///
/// Exists because a stale library was once packaged and reported as a
/// successful build. The cargokit wrapper that swallowed that failure is
/// fixed, but this covers the general case: whatever path a library takes into
/// an APK, a test on the device can ask it what it is and refuse to trust a
/// wrong answer.
///
/// Cheap and constant — the values are compiled in by `build.rs`.
#[flutter_rust_bridge::frb(sync)]
pub fn build_info() -> BuildInfo {
    BuildInfo {
        commit: env!("AUTHCORE_BUILD_COMMIT").to_string(),
        dirty: env!("AUTHCORE_BUILD_DIRTY") == "true",
        built_at: env!("AUTHCORE_BUILD_TIME").parse().unwrap_or(0),
    }
}

/// The lock policy (FR-33, FR-33a, FR-34).
///
/// Read from the unencrypted metadata file, so it is available before the
/// vault opens — which is the point of FR-33a. The application has to know
/// whether it may open without asking before it can open anything.
pub struct LockPolicyView {
    /// Seconds in the background before locking. `None` is "never".
    pub timeout_seconds: Option<u32>,
    pub lock_on_background: bool,
    /// FR-35: wipe after this many consecutive failures. `None` is off, and
    /// off is the default — the loss it causes is permanent and the threat it
    /// answers is rare.
    pub wipe_after_failures: Option<u32>,
}

#[flutter_rust_bridge::frb(sync)]
pub fn lock_policy() -> Result<LockPolicyView> {
    with_meta(|meta| {
        let policy = LockPolicy::load(meta)?;
        Ok(LockPolicyView {
            timeout_seconds: policy.timeout_seconds,
            lock_on_background: policy.lock_on_background,
            wipe_after_failures: policy.wipe_after_failures,
        })
    })
}

pub fn set_lock_policy(
    timeout_seconds: Option<u32>,
    lock_on_background: bool,
    wipe_after_failures: Option<u32>,
) -> Result<()> {
    with_meta(|meta| {
        LockPolicy {
            timeout_seconds,
            lock_on_background,
            wipe_after_failures,
        }
        .save(meta)?;
        Ok(())
    })
}

/// The band FR-35's threshold may be set within, for the screen that offers it.
///
/// Read from the core rather than restated in Dart, so the range the interface
/// shows and the range the core enforces cannot drift into disagreeing.
#[flutter_rust_bridge::frb(sync)]
pub fn wipe_threshold_range() -> (u32, u32) {
    (
        authcore::lock_policy::MIN_WIPE_THRESHOLD,
        authcore::lock_policy::MAX_WIPE_THRESHOLD,
    )
}

/// Records one failed unlock and enforces FR-35. Returns true if it wiped.
///
/// # Why the enforcement is here and not in Dart
///
/// This is the only place a failed unlock is counted, so it is the only place
/// the threshold can be applied without being avoidable. A check in the Flutter
/// layer would be a check an attacker with the device simply does not run —
/// the bridge dispatches by numeric identifier and every function in it can be
/// called directly. A protection that lives above the thing it protects is a
/// suggestion.
///
/// The count is written *before* the threshold is read, so a process killed
/// between the two comes back with the attempt already recorded. Losing a wipe
/// is recoverable for the attacker's target; losing the count is not.
fn record_failed_unlock() -> Result<bool> {
    let count = with_meta(|meta| Ok(meta.record_failed_unlock()?))?;

    let threshold = with_meta(|meta| {
        Ok(LockPolicy::load(meta)
            .map_err(|error| anyhow!("{error}"))?
            .wipe_after_failures)
    })?;

    match threshold {
        Some(limit) if count >= limit => {
            wipe_device()?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// FR-35: how many unlock attempts have failed in a row.
#[flutter_rust_bridge::frb(sync)]
pub fn failed_unlock_attempts() -> Result<u32> {
    with_meta(|meta| Ok(meta.failed_unlocks()?))
}

fn open_vault_with_key(vault_path: &str, meta: MetaStore, key: VaultKey) -> Result<()> {
    // Two layers, two keys, both HKDF subkeys of the vault key. SQLCipher
    // covers the file — the schema, the row count, the timestamps — and the
    // record cipher covers each payload inside it.
    // The page key protects database structure and ciphertext at rest. It is
    // not the record key. Android Keystore stores it outside metadata. A
    // locked sync process can move authenticated record ciphertext without
    // opening an OTP payload.
    // Existing installations migrate once from the former vault-derived page
    // key. The new key is stored first, so a crash before rekey can retry with
    // the old key and a crash after rekey can use the new key.
    let page_key = ensure_page_key(&meta)?;
    let previous_page_key = key.sqlcipher_key();
    let store = Store::open_with_key_migration(vault_path, meta, &page_key, &previous_page_key)
        .context("The vault could not be opened")?;
    let mut vault = Vault::open(store, XChaChaCipher::new(&key))?;

    // Section 10.4 step 4: the reconcile runs *inside* the unlock path,
    // before the code list becomes usable. A lazy pass would leave a window in
    // which the user unlocks, taps an HOTP entry, and gets a code from the
    // smaller counter — the exact failure the rule exists to prevent, reached
    // by a different route.
    // No clock is read. Section 10.4 step 7 derives the corrected timestamp
    // from the conflicting records themselves, which is why this call takes
    // no time argument — a clock here would walk around section 10.2's drift
    // bound, and be wrong in both directions.
    let report = reconcile::run(&mut vault).map_err(|error| anyhow!("{error}"))?;
    if report.counters_raised > 0 {
        // Counts only. Section 9.4 forbids naming an entry at any log level.
        eprintln!(
            "reconcile: raised {} counter(s) after a locked conflict",
            report.counters_raised
        );
    }

    *CURRENT_KEY.lock().map_err(|_| lock_poisoned())? = Some(key);
    *VAULT.lock().map_err(|_| lock_poisoned())? = Some(vault);
    Ok(())
}

/// FR-31: "Locking zeroes the vault key in memory."
///
/// Dropping the vault drops the cipher, which drops the only copy of the
/// record key, and `Zeroizing` wipes it on the way out. There is no
/// screen-hiding fallback: after this call the records genuinely cannot be
/// read until the slot is unwrapped again.
#[flutter_rust_bridge::frb(sync)]
pub fn lock_vault() -> Result<()> {
    cancel_pending_keystore_operations();
    crate::api::sync::clear_capabilities();
    PENDING_RECOVERY_SLOT
        .lock()
        .map_err(|_| lock_poisoned())?
        .take();
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    crate::vault_key_bridge::clear_pending_secrets();

    // The key goes first. If anything below fails, the vault is still shut.
    // `VaultKey` wipes its buffer as it drops.
    CURRENT_KEY.lock().map_err(|_| lock_poisoned())?.take();

    let vault = VAULT.lock().map_err(|_| lock_poisoned())?.take();

    // Put the metadata file back so the next unlock can read the slot.
    if let Some(vault) = vault {
        *META.lock().map_err(|_| lock_poisoned())? = Some(vault.into_store().into_meta());
    }
    Ok(())
}

#[flutter_rust_bridge::frb(sync)]
pub fn is_vault_open() -> bool {
    VAULT.lock().map(|guard| guard.is_some()).unwrap_or(false)
}

/// Section 9.2.4, **Wipe this device**: destroys the slot and every entry.
///
/// Both halves matter. Without the slot the records cannot be read, but
/// ciphertext left on disk is ciphertext an attacker can keep, so the entries
/// go too.
pub fn wipe_device() -> Result<()> {
    cancel_pending_keystore_operations();
    crate::api::sync::clear_capabilities();
    PENDING_RECOVERY_SLOT
        .lock()
        .map_err(|_| lock_poisoned())?
        .take();
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    crate::vault_key_bridge::clear_pending_secrets();

    CURRENT_KEY.lock().map_err(|_| lock_poisoned())?.take();
    let existing = VAULT.lock().map_err(|_| lock_poisoned())?.take();

    let mut meta = match existing {
        Some(mut vault) => {
            vault.store_mut().clear_entries()?;
            vault.into_store().into_meta()
        }
        None => take_meta()?,
    };

    // The synchronization session is not in meta.db on Android. Clear its
    // dedicated Keystore-backed file as part of the same device wipe.
    crate::api::sync::clear_session(&meta)?;
    meta.clear_all()?;
    // Dart completes platform-owned cleanup. Keep a durable marker because an
    // automatic wipe can occur before Dart regains control.
    meta.set(META_WIPE_CLEANUP_REQUIRED, b"1")?;
    *META.lock().map_err(|_| lock_poisoned())? = Some(meta);
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    crate::session_store::clear_page_key()?;
    Ok(())
}

const META_WIPE_CLEANUP_REQUIRED: &str = "security.wipe_cleanup_required";

#[flutter_rust_bridge::frb(sync)]
pub fn wipe_cleanup_required() -> Result<bool> {
    with_meta(|meta| Ok(meta.get(META_WIPE_CLEANUP_REQUIRED)?.is_some()))
}

pub fn finish_wipe_cleanup() -> Result<()> {
    with_meta(|meta| {
        meta.remove(META_WIPE_CLEANUP_REQUIRED)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// Every entry with its code at `now_unix_seconds`.
pub fn list_entries(now_unix_seconds: i64) -> Result<Vec<EntryView>> {
    with_vault(|vault| {
        let (entries, unreadable) = vault.list()?;
        if unreadable > 0 {
            // Not fatal: the readable entries still render. Nothing is logged
            // about their contents, only the count.
            eprintln!("vault: {unreadable} record(s) could not be read");
        }

        let mut views = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some(otp_entry) = entry.payload.as_otp() else {
                continue; // A folder is not a row in the code list.
            };
            if otp_entry.trashed_at.is_some() {
                continue;
            }
            // Taken from the payload rather than mapped through `OtpKind`,
            // which has only the two RFC kinds in it. A Steam entry is neither,
            // and collapsing it to "totp" here would produce five characters of
            // the wrong alphabet — a code that looks right and never works.
            let kind = entry.payload.type_name();

            // Section 10.4 step 3. Belt to the unlock-path brace: if a
            // reconcile is still pending, this entry may be holding the
            // smaller counter, and a code from it is one the issuer has
            // already rejected. Refusing beats being confidently wrong.
            if vault.store().reconcile_pending_for(&entry.id)? {
                views.push(EntryView {
                    id: entry.id,
                    kind: kind.to_string(),
                    issuer: otp_entry.issuer.clone(),
                    account: otp_entry.account.clone(),
                    code: String::new(),
                    next_code: None,
                    digits: u32::from(otp_entry.digits),
                    period: otp_entry.period,
                    remaining_seconds: 0,
                    counter: otp_entry.counter,
                    favourite: otp_entry.favourite,
                    icon: otp_entry.icon.clone(),
                    note: otp_entry.note.clone(),
                    tags: otp_entry.tags.clone(),
                    folder_id: otp_entry.folder_id.clone(),
                    created_at: otp_entry.created_at,
                    order: otp_entry.order.clone(),
                    awaiting_reconcile: true,
                });
                continue;
            }

            let secret = otp_entry
                .secret
                .decode()
                .map_err(|error| anyhow!("{error}"))?;

            let (code, next_code, remaining) = match kind {
                "hotp" => (
                    otp::hotp(
                        &secret,
                        otp_entry.counter.unwrap_or(0),
                        otp_entry.digits,
                        otp_entry.algorithm,
                    )?,
                    None,
                    0,
                ),
                // FR-06. The stored digits and period are deliberately not
                // passed: both are fixed by the format, and an entry that
                // arrived with a wrong value must still produce a working code.
                "steam" => {
                    let remaining =
                        otp::totp_remaining_seconds(now_unix_seconds, otp::DEFAULT_PERIOD);
                    (
                        otp::steam_at(&secret, now_unix_seconds)?,
                        Some(otp::steam_at(
                            &secret,
                            now_unix_seconds.saturating_add(i64::from(remaining)),
                        )?),
                        remaining,
                    )
                }
                _ => {
                    let remaining = otp::totp_remaining_seconds(now_unix_seconds, otp_entry.period);
                    (
                        otp::totp_at(
                            &secret,
                            now_unix_seconds,
                            otp_entry.period,
                            otp_entry.digits,
                            otp_entry.algorithm,
                        )?,
                        Some(otp::totp_at(
                            &secret,
                            now_unix_seconds.saturating_add(i64::from(remaining)),
                            otp_entry.period,
                            otp_entry.digits,
                            otp_entry.algorithm,
                        )?),
                        remaining,
                    )
                }
            };

            views.push(EntryView {
                id: entry.id,
                kind: kind.to_string(),
                issuer: otp_entry.issuer.clone(),
                account: otp_entry.account.clone(),
                code,
                next_code,
                digits: u32::from(otp_entry.digits),
                period: otp_entry.period,
                remaining_seconds: remaining,
                counter: otp_entry.counter,
                favourite: otp_entry.favourite,
                icon: otp_entry.icon.clone(),
                note: otp_entry.note.clone(),
                tags: otp_entry.tags.clone(),
                folder_id: otp_entry.folder_id.clone(),
                created_at: otp_entry.created_at,
                order: otp_entry.order.clone(),
                awaiting_reconcile: false,
            });
        }
        Ok(views)
    })
}

/// Reads an `otpauth://` URI without storing anything (FR-10, FR-11, FR-12).
pub fn preview_uri(uri: String) -> Result<EntryPreview> {
    let parsed = OtpAuthUri::parse(&uri).map_err(|error| anyhow!("{error}"))?;
    let duplicate = with_vault(|vault| Ok(vault.find_by_secret(parsed.secret.expose())?))?;

    Ok(EntryPreview {
        kind: parsed.kind.as_str().to_string(),
        issuer: parsed.issuer.clone(),
        account: parsed.account.clone(),
        algorithm: parsed.algorithm.as_str().to_string(),
        digits: u32::from(parsed.digits),
        period: parsed.period,
        counter: parsed.counter,
        duplicate_of: duplicate,
    })
}

/// Adds an entry from a scanned or pasted URI.
pub fn add_from_uri(uri: String, now_ms: i64) -> Result<AddOutcome> {
    let parsed = OtpAuthUri::parse(&uri).map_err(|error| anyhow!("{error}"))?;
    with_vault(|vault| {
        if let Some(existing_id) = vault.find_by_secret(parsed.secret.expose())? {
            return Ok(AddOutcome::duplicate(existing_id));
        }
        let payload = OtpEntry::from_uri(&parsed, now_ms);
        Ok(AddOutcome::added(vault.add(&payload, now_ms)?))
    })
}

/// Adds an entry the user typed in (FR-13).
#[allow(clippy::too_many_arguments)]
pub fn add_manual(
    issuer: Option<String>,
    account: String,
    secret: String,
    kind: String,
    algorithm: String,
    digits: u32,
    period: u32,
    counter: Option<u64>,
    now_ms: i64,
) -> Result<AddOutcome> {
    // Rebuilding a URI and parsing it means the manual path and the scan path
    // run the same validation, rather than two versions that drift apart.
    let kind = match kind.as_str() {
        "hotp" => OtpKind::Hotp,
        "totp" => OtpKind::Totp,
        other => return Err(anyhow!("'{other}' is not a supported entry type.")),
    };
    let algorithm = Algorithm::parse(&algorithm)
        .ok_or_else(|| anyhow!("'{algorithm}' is not a supported hash algorithm."))?;
    let secret = authcore::base32::normalize(&secret).map_err(|error| anyhow!("{error}"))?;

    let digits =
        u8::try_from(digits).map_err(|_| anyhow!("{digits} is not a valid digit count."))?;
    otp::check_digits(digits)?;
    otp::check_period(period)?;
    if kind == OtpKind::Hotp && counter.is_none() {
        return Err(anyhow!("An HOTP entry needs a starting counter."));
    }

    with_vault(|vault| {
        if let Some(existing_id) = vault.find_by_secret(secret.as_str())? {
            return Ok(AddOutcome::duplicate(existing_id));
        }

        let payload = Payload::from_json(&build_payload(
            kind,
            issuer.clone(),
            &account,
            secret.as_str(),
            algorithm,
            digits,
            period,
            counter,
            now_ms,
        )?)?;
        Ok(AddOutcome::added(vault.add(&payload, now_ms)?))
    })
}

/// FR-17: rename an entry. The secret is not editable and is not a parameter.
pub fn rename_entry(
    id: String,
    issuer: Option<String>,
    account: String,
    icon: Option<String>,
    note: Option<String>,
    tags: Option<Vec<String>>,
    now_ms: i64,
) -> Result<()> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let mut payload = existing.payload.clone();
        match &mut payload {
            Payload::Totp(entry) | Payload::Hotp(entry) | Payload::Steam(entry) => {
                entry.issuer = issuer.clone().filter(|value| !value.trim().is_empty());
                entry.account = account.clone();
                // Empty means "no choice", which is not the same as an icon
                // named "". Without the filter, clearing the field would store
                // a blank string that the list would then render as a blank
                // tile rather than falling back to the monogram.
                entry.icon = icon
                    .clone()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
                if let Some(note) = &note {
                    entry.note = note.trim().to_string();
                }
                if let Some(tags) = &tags {
                    if tags.len() > 20 {
                        return Err(anyhow!("An entry can have at most 20 tags."));
                    }
                    let mut normalized = Vec::new();
                    for tag in tags {
                        let tag = tag.trim();
                        if tag.is_empty() {
                            continue;
                        }
                        if tag.chars().count() > 32 {
                            return Err(anyhow!("A tag can have at most 32 characters."));
                        }
                        if !normalized
                            .iter()
                            .any(|existing: &String| existing.eq_ignore_ascii_case(tag))
                        {
                            normalized.push(tag.to_string());
                        }
                    }
                    entry.tags = normalized;
                }
            }
            Payload::Folder(folder) => folder.name = account.clone(),
        }
        vault.update(&id, &payload, now_ms)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Folders (FR-19)
// ---------------------------------------------------------------------------

/// One folder, for the filter row above the code list.
pub struct FolderView {
    pub id: String,
    pub name: String,
    /// How many live entries name this folder. Shown beside it, because a
    /// folder whose count is zero is usually one the user thought they had
    /// filled.
    pub count: u32,
}

/// Every folder, with the number of entries in each.
///
/// Sorted by name rather than by creation order: a filter row is scanned, and
/// a list that reorders itself as folders are added is one the user has to
/// re-read every time.
pub fn list_folders() -> Result<Vec<FolderView>> {
    with_vault(|vault| {
        let (entries, _) = vault.list()?;

        let mut folders: Vec<FolderView> = Vec::new();
        for entry in &entries {
            if let Payload::Folder(folder) = &entry.payload {
                folders.push(FolderView {
                    id: entry.id.clone(),
                    name: folder.name.clone(),
                    count: 0,
                });
            }
        }

        for entry in &entries {
            let Some(otp) = entry.payload.as_otp() else {
                continue;
            };
            if otp.trashed_at.is_some() {
                continue;
            }
            let Some(folder_id) = &otp.folder_id else {
                continue;
            };
            // A miss is not an error. Device A can delete a folder while
            // device B files something into it, and after they sync the entry
            // names a folder that no longer exists. It counts as unfiled,
            // which is the only answer that does not lose the entry.
            if let Some(folder) = folders.iter_mut().find(|f| &f.id == folder_id) {
                folder.count += 1;
            }
        }

        folders.sort_by_key(|folder| folder.name.to_lowercase());
        Ok(folders)
    })
}

/// Creates a folder and returns its identifier.
pub fn create_folder(name: String, now_ms: i64) -> Result<String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(anyhow!("A folder needs a name."));
    }
    with_vault(|vault| {
        let payload = Payload::Folder(authcore::entry::Folder {
            v: 1,
            name,
            order: String::new(),
            created_at: now_ms,
            extra: Default::default(),
        });
        Ok(vault.add(&payload, now_ms)?)
    })
}

/// Renames a folder. Reuses the entry path, which already handles folders.
pub fn rename_folder(id: String, name: String, now_ms: i64) -> Result<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(anyhow!("A folder needs a name."));
    }
    rename_entry(id, None, name, None, None, None, now_ms)
}

/// Deletes a folder and unfiles everything in it.
///
/// # Why the entries are updated rather than left dangling
///
/// [`list_folders`] already treats an unknown folder identifier as unfiled, so
/// this would work without touching a single entry — and that is the right
/// behaviour for the concurrent case, which cannot be prevented.
///
/// It is the wrong behaviour to *rely* on. An entry still carrying the
/// identifier of a folder that was deliberately deleted would silently re-file
/// itself if that identifier ever came back, and it exports and syncs a
/// reference to something that no longer exists. Clearing them makes the state
/// on disk mean what it says.
///
/// Never destroys an entry. Deleting a folder is a filing decision, and a user
/// who lost forty codes to one would be entitled to be furious.
pub fn delete_folder(id: String, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        let (entries, _) = vault.list()?;

        for entry in entries {
            let Some(otp) = entry.payload.as_otp() else {
                continue;
            };
            if otp.folder_id.as_deref() != Some(id.as_str()) {
                continue;
            }
            let mut payload = entry.payload.clone();
            if let Payload::Totp(inner) | Payload::Hotp(inner) | Payload::Steam(inner) =
                &mut payload
            {
                inner.folder_id = None;
            }
            vault.update(&entry.id, &payload, now_ms)?;
        }

        // The folder itself last. A failure part way through leaves entries
        // unfiled and the folder present, which the user can see and finish;
        // the other order leaves entries pointing at nothing.
        vault.delete(&id, now_ms)?;
        Ok(())
    })
}

/// Files an entry into a folder, or takes it out of one with `None`.
pub fn set_entry_folder(id: String, folder_id: Option<String>, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let mut payload = existing.payload.clone();
        match &mut payload {
            Payload::Totp(entry) | Payload::Hotp(entry) | Payload::Steam(entry) => {
                entry.folder_id = folder_id.clone().filter(|value| !value.trim().is_empty());
            }
            // A folder inside a folder is not a thing this supports. Refused
            // rather than ignored: silently doing nothing to a nested drag
            // would look like the app losing the action.
            Payload::Folder(_) => {
                return Err(anyhow!("A folder cannot be put inside another folder."));
            }
        }
        vault.update(&id, &payload, now_ms)?;
        Ok(())
    })
}

/// Moves one entry to encrypted trash.
pub fn move_entry_to_trash(id: String, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let mut payload = existing.payload.clone();
        let otp = match &mut payload {
            Payload::Totp(otp) | Payload::Hotp(otp) | Payload::Steam(otp) => otp,
            Payload::Folder(_) => return Err(anyhow!("A folder cannot be moved to trash.")),
        };
        otp.trashed_at = Some(now_ms);
        vault.update(&id, &payload, now_ms)?;
        Ok(())
    })
}

/// Restores one entry from encrypted trash.
pub fn restore_entry(id: String, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let mut payload = existing.payload.clone();
        let otp = match &mut payload {
            Payload::Totp(otp) | Payload::Hotp(otp) | Payload::Steam(otp) => otp,
            Payload::Folder(_) => return Err(anyhow!("A folder is not a trash entry.")),
        };
        if otp.trashed_at.take().is_none() {
            return Err(anyhow!("This entry is not in trash."));
        }
        vault.update(&id, &payload, now_ms)?;
        Ok(())
    })
}

/// Lists encrypted trash without returning an OTP code or secret.
pub fn list_trashed_entries() -> Result<Vec<TrashEntryView>> {
    with_vault(|vault| {
        let (entries, _) = vault.list()?;
        let mut trash = Vec::new();
        for entry in entries {
            let Some(otp) = entry.payload.as_otp() else {
                continue;
            };
            let Some(trashed_at) = otp.trashed_at else {
                continue;
            };
            trash.push(TrashEntryView {
                id: entry.id,
                issuer: otp.issuer.clone(),
                account: otp.account.clone(),
                trashed_at,
                purge_at: trashed_at.saturating_add(TRASH_RETENTION_MS),
            });
        }
        trash.sort_by_key(|entry| std::cmp::Reverse(entry.trashed_at));
        Ok(trash)
    })
}

/// Permanently deletes trash entries that reached the 30-day limit.
pub fn purge_expired_trash(now_ms: i64) -> Result<u32> {
    with_vault(|vault| {
        let (entries, _) = vault.list()?;
        let ids: Vec<String> = entries
            .into_iter()
            .filter_map(|entry| {
                let trashed_at = entry.payload.as_otp()?.trashed_at?;
                (trashed_at.saturating_add(TRASH_RETENTION_MS) <= now_ms).then_some(entry.id)
            })
            .collect();

        for id in &ids {
            vault.delete(id, now_ms)?;
        }
        Ok(ids.len() as u32)
    })
}

/// Returns groups of live entry identifiers that contain the same secret.
/// Secret comparison stays inside Rust.
pub fn find_duplicate_groups() -> Result<Vec<Vec<String>>> {
    with_vault(|vault| {
        let (entries, _) = vault.list()?;
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| {
                entry
                    .payload
                    .as_otp()
                    .is_some_and(|otp| otp.trashed_at.is_none())
            })
            .collect();
        let mut grouped = vec![false; entries.len()];
        let mut groups = Vec::new();

        for left in 0..entries.len() {
            if grouped[left] {
                continue;
            }
            let Some(left_otp) = entries[left].payload.as_otp() else {
                continue;
            };
            let mut group = vec![entries[left].id.clone()];
            for right in (left + 1)..entries.len() {
                if grouped[right] {
                    continue;
                }
                let Some(right_otp) = entries[right].payload.as_otp() else {
                    continue;
                };
                if left_otp.secret.expose() == right_otp.secret.expose() {
                    grouped[right] = true;
                    group.push(entries[right].id.clone());
                }
            }
            if group.len() > 1 {
                grouped[left] = true;
                groups.push(group);
            }
        }
        Ok(groups)
    })
}

/// Permanently deletes an entry and leaves a synchronization tombstone.
pub fn delete_entry(id: String, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        vault.delete(&id, now_ms)?;
        Ok(())
    })
}

/// FR-20: pin an entry to the top of the list.
pub fn set_favourite(id: String, favourite: bool, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let mut payload = existing.payload.clone();
        if let Payload::Totp(entry) | Payload::Hotp(entry) | Payload::Steam(entry) = &mut payload {
            entry.favourite = favourite;
        }
        vault.update(&id, &payload, now_ms)?;
        Ok(())
    })
}

/// FR-02: "Increase the counter when the user taps the entry."
///
/// The counter is written before the new code is returned, so a crash between
/// the two leaves the stored counter ahead rather than behind. A counter that
/// lags produces a code the issuer has already rejected.
pub fn advance_hotp(id: String, now_ms: i64) -> Result<String> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let Payload::Hotp(mut entry) = existing.payload.clone() else {
            return Err(anyhow!("This entry is not an HOTP entry."));
        };

        let next = entry.counter.unwrap_or(0).saturating_add(1);
        entry.counter = Some(next);

        let secret = entry.secret.decode().map_err(|error| anyhow!("{error}"))?;
        let code = otp::hotp(&secret, next, entry.digits, entry.algorithm)?;

        vault.update(&id, &Payload::Hotp(entry), now_ms)?;
        Ok(code)
    })
}

/// FR-38: the stored offset between device time and reference time.
///
/// Readable while locked, because it lives in the metadata file rather than
/// the vault, and the unlock screen needs it to warn about clock drift.
pub fn time_offset_seconds() -> Result<i64> {
    with_meta(|meta| Ok(meta.time_offset_seconds()?))
}

pub fn set_time_offset_seconds(offset: i64) -> Result<()> {
    with_meta(|meta| Ok(meta.set_time_offset_seconds(offset)?))
}

/// Returns the Base32 secret of one entry.
///
/// The only way a secret leaves the core, for the QR export in FR-30 and the
/// plain-text backup in FR-27. FR-36 requires an unlock before either. The
/// name is deliberately awkward so a call site stands out in review.
pub fn reveal_secret_for_export(id: String) -> Result<String> {
    with_vault(|vault| {
        let entry = vault.get(&id)?;
        let otp_entry = entry
            .payload
            .as_otp()
            .ok_or_else(|| anyhow!("This entry holds no secret."))?;
        refuse_if_trashed(otp_entry)?;
        Ok(otp_entry.secret.expose().to_string())
    })
}

/// Refuses a secret that belongs to an entry the user has deleted.
///
/// Trash is recoverable inside the application; it is not a thing to carry off
/// the device. Somebody who removed an account and then exported it — as a
/// file, a QR code, or a plain setup key — would be handed back a secret they
/// believe is gone, and in FR-27's plain export it would be readable.
///
/// The code list already hides these. The single-secret paths and the backup
/// did not, which is the sort of gap that opens whenever a new state is added
/// to a payload and only the obvious reader is updated.
fn refuse_if_trashed(entry: &authcore::entry::OtpEntry) -> Result<()> {
    if entry.trashed_at.is_some() {
        return Err(anyhow!(
            "This account is in the trash. Restore it before exporting it."
        ));
    }
    Ok(())
}

/// FR-30: one entry as an `otpauth://` URI, for display as a QR code.
///
/// # Why this exists next to the backup file
///
/// A backup moves everything and needs a file the other application can read.
/// This moves *one* account to something standing in front of you — a second
/// phone, a desktop client, a friend's app — with no file, no cloud, and no
/// account in common. It is the oldest transfer path in this ecosystem and
/// still the one that always works.
///
/// FR-36 is `with_vault`: locked means no. The name of the caller is deliberate
/// too — this returns a live secret, and a call site should be obvious in
/// review.
///
/// A Steam entry comes back as `otpauth://steam/…`, which is Aegis's form and
/// what 2FAS reads. Not an RFC, but an entry this app can import and cannot
/// hand back is one the user cannot take anywhere else.
pub fn export_entry_uri(id: String) -> Result<String> {
    with_vault(|vault| {
        let entry = vault.get(&id)?;
        let otp_entry = entry
            .payload
            .as_otp()
            .ok_or_else(|| anyhow!("This entry holds no secret."))?;
        refuse_if_trashed(otp_entry)?;

        let kind = match entry.payload.type_name() {
            "hotp" => OtpKind::Hotp,
            "steam" => OtpKind::Steam,
            _ => OtpKind::Totp,
        };

        let uri = authcore::otpauth::OtpAuthUri {
            kind,
            issuer: otp_entry.issuer.clone(),
            account: otp_entry.account.clone(),
            secret: otp_entry.secret.clone(),
            algorithm: otp_entry.algorithm,
            digits: otp_entry.digits,
            period: otp_entry.period,
            counter: otp_entry.counter,
        };
        Ok(uri.to_uri().to_string())
    })
}

/// Builds an `EntryPayload` for the manual path.
///
/// Going through JSON keeps `EntryPayload`'s field defaults in one place rather
/// than restating them here, where they could drift from section 12.2.
#[allow(clippy::too_many_arguments)]
fn build_payload(
    kind: OtpKind,
    issuer: Option<String>,
    account: &str,
    secret: &str,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    counter: Option<u64>,
    now_ms: i64,
) -> Result<Vec<u8>> {
    let mut object = serde_json::Map::new();
    object.insert("v".into(), 1.into());
    object.insert("type".into(), kind.as_str().into());
    if let Some(issuer) = issuer.filter(|value| !value.trim().is_empty()) {
        object.insert("issuer".into(), issuer.into());
    }
    object.insert("account".into(), account.into());
    object.insert("secret".into(), secret.into());
    object.insert("algorithm".into(), algorithm.as_str().into());
    object.insert("digits".into(), digits.into());
    object.insert("period".into(), period.into());
    object.insert(
        "counter".into(),
        match counter {
            Some(value) => value.into(),
            None => serde_json::Value::Null,
        },
    );
    object.insert("created_at".into(), now_ms.into());
    Ok(serde_json::to_vec(&serde_json::Value::Object(object))?)
}

/// FR-22: how the code list is ordered, remembered between runs.
///
/// Kept in `meta` rather than in Flutter's own preferences, following FR-33a's
/// precedent: this project has one place for settings that outlive a run, and a
/// second one would be a second thing to wipe, migrate and reason about.
///
/// The value is opaque here on purpose. What the modes mean is a presentation
/// question and lives in Dart; this only has to remember the answer.
const META_LIST_SORT: &str = "ui.list_sort";

/// Enables the optional local service-symbol pack. The setting stays in the
/// vault metadata so a device wipe removes it with the other application
/// settings. The pack performs no network requests.
const META_BRAND_ICONS: &str = "ui.brand_icons";

/// Whether the first-run screen has been shown (FR-47).
const META_WELCOME_SEEN: &str = "ui.welcome_seen";

/// True once the user has been past the first-run choice — or has plainly never
/// needed it.
///
/// # Why an entry counts as having seen it
///
/// The flag alone is wrong for everybody who already had the app. It does not
/// exist in their metadata, so on the release that introduces it every existing
/// user would be shown a first-run screen offering to import the accounts they
/// have been using for months.
///
/// A vault with anything in it has been past first run by definition, whatever
/// the flag says. Asking the vault is the honest test; the flag only has to
/// answer for the genuinely empty case.
///
/// This was found by a test, not by thinking about it: `app_test.dart` starts
/// the real application and expects the code list, and it got the welcome
/// screen instead.
///
/// Kept in `meta` rather than in Flutter's preferences, for the same reason as
/// the sort order: this project has one place for settings that outlive a run,
/// and a second would be a second thing to wipe and reason about. It also means
/// "Wipe this device" genuinely returns the app to first-run state rather than
/// to one that looks used and holds nothing.
#[flutter_rust_bridge::frb(sync)]
pub fn welcome_seen() -> Result<bool> {
    if with_meta(|meta| Ok(meta.get(META_WELCOME_SEEN)?.is_some()))? {
        return Ok(true);
    }

    // Locked, or not yet open. Nothing can be shown over a locked vault
    // anyway — the unlock screen comes first — so the safe answer is "seen",
    // which shows one screen too few rather than one too many.
    let has_entries = with_vault(|vault| Ok(!vault.store().list(false)?.is_empty()));
    Ok(has_entries.unwrap_or(true))
}

pub fn mark_welcome_seen() -> Result<()> {
    with_meta(|meta| {
        meta.set(META_WELCOME_SEEN, b"1")?;
        Ok(())
    })
}

#[flutter_rust_bridge::frb(sync)]
pub fn list_sort() -> Result<Option<String>> {
    with_meta(|meta| {
        Ok(meta
            .get(META_LIST_SORT)?
            .and_then(|bytes| String::from_utf8(bytes).ok()))
    })
}

pub fn set_list_sort(mode: String) -> Result<()> {
    with_meta(|meta| {
        meta.set(META_LIST_SORT, mode.as_bytes())?;
        Ok(())
    })
}

#[flutter_rust_bridge::frb(sync)]
pub fn brand_icons_enabled() -> Result<bool> {
    with_meta(|meta| {
        Ok(match meta.get(META_BRAND_ICONS)?.as_deref() {
            Some(b"1") => true,
            _ => false,
        })
    })
}

pub fn set_brand_icons_enabled(enabled: bool) -> Result<()> {
    with_meta(|meta| {
        meta.set(META_BRAND_ICONS, if enabled { b"1" } else { b"0" })?;
        Ok(())
    })
}

/// FR-22's manual order: places an entry between two others.
///
/// `order` is a fractional index — a string that sorts between its neighbours —
/// so two devices can insert between the same pair without a conflict
/// (section 10.4). Computing it is the caller's job; this writes it.
///
/// The secret is untouched. FR-17 is explicit that it cannot be edited, and a
/// reorder is the last place anyone would look for a change to one.
pub fn set_entry_order(id: String, order: String, now_ms: i64) -> Result<()> {
    with_vault(|vault| {
        let mut entry = vault.get(&id).map_err(|error| anyhow!("{error}"))?;
        match &mut entry.payload {
            Payload::Totp(otp) | Payload::Hotp(otp) | Payload::Steam(otp) => otp.order = order,
            Payload::Folder(folder) => folder.order = order,
        }
        vault
            .update(&id, &entry.payload, now_ms)
            .map_err(|error| anyhow!("{error}"))?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// FR-14: importing from Google Authenticator
// ---------------------------------------------------------------------------

/// The batch being scanned, if any.
///
/// State, because a multi-code export arrives one camera frame at a time and
/// nothing above this layer should have to hold half an import. It is cleared
/// on completion and by [`migration_reset`], so an abandoned scan cannot bleed
/// into the next one.
static MIGRATION: Mutex<Option<authcore::import::google::Batch>> = Mutex::new(None);

/// What one scanned export code did.
pub struct MigrationScanView {
    /// How many codes are still to scan. Zero means ready to import.
    pub remaining: u32,
    /// Entries understood so far, across every part.
    pub ready: u32,
    /// Entries that could not be read (FR-15d). Named in the report at the end.
    pub refused: u32,
    /// True when this code had already been scanned. Not a failure: a camera
    /// reads the same code many times a second.
    pub already_seen: bool,
    /// True when this code belongs to a different export.
    pub different_export: bool,
}

/// Reads one `otpauth-migration://` code and adds it to the batch in progress.
///
/// Nothing is written to the vault here. FR-14 requires every part before the
/// import runs, and an import that happened per-code would leave a user who
/// scanned two of three believing they were finished.
pub fn migration_scan(uri: String) -> Result<MigrationScanView> {
    use authcore::import::google::{parse_part, Added};

    let part = parse_part(&uri).map_err(|error| anyhow!("{error}"))?;

    let mut guard = MIGRATION.lock().map_err(|_| lock_poisoned())?;
    let batch = guard.get_or_insert_with(authcore::import::google::Batch::new);

    let outcome = batch.add(part);
    let (already_seen, different_export) = match outcome {
        Added::AlreadyHave => (true, false),
        Added::DifferentExport => (false, true),
        _ => (false, false),
    };

    Ok(MigrationScanView {
        remaining: batch.remaining(),
        ready: batch.entries_so_far() as u32,
        refused: batch.refused_so_far() as u32,
        already_seen,
        different_export,
    })
}

/// One entry that could not be imported, for the report FR-15d requires.
pub struct RefusedView {
    pub label: String,
    pub reason: String,
}

/// What an import produced.
pub struct ImportReportView {
    pub imported: u32,
    /// Entries already in the vault (FR-16). Not failures, and not imported
    /// twice.
    pub duplicates: u32,
    pub refused: Vec<RefusedView>,
}

/// Writes the completed batch into the vault.
///
/// Refuses while parts are missing — the whole point of collecting them.
///
/// FR-15d: one bad entry never fails the rest. Anything that cannot be written
/// joins the report rather than aborting the import, so a user moving forty
/// accounts with one malformed entry ends up with thirty-nine and a list.
pub fn migration_finish(now_ms: i64) -> Result<ImportReportView> {
    let batch = MIGRATION
        .lock()
        .map_err(|_| lock_poisoned())?
        .take()
        .ok_or_else(|| anyhow!("No export has been scanned yet."))?;

    let report = batch.finish().ok_or_else(|| {
        anyhow!("Some of the export codes are still missing. Scan the rest before importing.")
    })?;

    let refused: Vec<RefusedView> = report
        .refused
        .into_iter()
        .map(|item| RefusedView {
            label: item.label,
            reason: item.reason,
        })
        .collect();

    absorb(report.entries, refused, now_ms)
}

/// Writes imported entries into the vault, whatever they were read from.
///
/// Shared by every import path — QR migration, and the backup files in FR-28 —
/// so the two rules that matter are applied once rather than restated. FR-16
/// skips an entry whose secret is already stored: importing a duplicate leaves
/// two rows producing identical codes, and deleting the wrong one later looks
/// like data loss. FR-15d keeps going past a failure and names it, so a user
/// moving forty accounts with one bad entry ends with thirty-nine and a list.
///
/// `with_vault` fails while locked, which is FR-36 for the import direction.
pub(crate) fn absorb(
    entries: Vec<authcore::entry::Payload>,
    mut refused: Vec<RefusedView>,
    now_ms: i64,
) -> Result<ImportReportView> {
    let mut imported = 0u32;
    let mut duplicates = 0u32;

    with_vault(|vault| {
        for payload in entries {
            let label = payload
                .as_otp()
                .map(|entry| match &entry.issuer {
                    Some(issuer) => format!("{issuer} ({})", entry.account),
                    None => entry.account.clone(),
                })
                .unwrap_or_default();

            let existing = payload
                .as_otp()
                .map(|entry| vault.find_by_secret(entry.secret.expose()))
                .transpose()
                .map_err(|error| anyhow!("{error}"))?
                .flatten();

            if existing.is_some() {
                duplicates += 1;
                continue;
            }

            match vault.add(&payload, now_ms) {
                Ok(_) => imported += 1,
                Err(error) => refused.push(RefusedView {
                    label,
                    reason: format!("{error}"),
                }),
            }
        }
        Ok(())
    })?;

    Ok(ImportReportView {
        imported,
        duplicates,
        refused,
    })
}

// ---------------------------------------------------------------------------
// File imports: Aegis and 2FAS (FR-15, FR-15a)
// ---------------------------------------------------------------------------

/// What a chosen file turned out to be.
pub struct DetectedFileView {
    /// `Aegis`, `2FAS`, or `backup`. For the screen's wording, not for
    /// branching: the reader dispatches on the file itself.
    pub source: String,
    pub encrypted: bool,
}

/// Identifies an export file without reading its contents.
///
/// Lets the screen ask for a password before the user waits through scrypt,
/// and — the half that matters more — lets it not ask when the file is plain.
#[flutter_rust_bridge::frb(sync)]
pub fn detect_import_file(text: String) -> Result<DetectedFileView> {
    let detected = authcore::import::file::detect(&text).map_err(|error| anyhow!("{error}"))?;
    Ok(DetectedFileView {
        source: detected.source.label().to_string(),
        encrypted: detected.encrypted,
    })
}

/// Imports an Aegis export, a 2FAS backup, or a backup this app wrote.
///
/// The format is detected rather than chosen. Making the user pick the
/// application first adds a step whose only outcomes are "correct, so it was
/// not needed" and "wrong, so a good file is reported as unreadable" — and the
/// person doing this has just installed the app and is deciding whether to keep
/// it.
///
/// Goes through the same [`absorb`] as every other import, so FR-16's duplicate
/// rule and FR-15d's partial report hold here without being restated.
pub fn import_file(
    text: String,
    password: Option<String>,
    now_ms: i64,
) -> Result<ImportReportView> {
    let report = authcore::import::file::read(&text, password.as_deref())
        .map_err(|error| anyhow!("{error}"))?;

    let refused = report
        .refused
        .into_iter()
        .map(|item| RefusedView {
            label: item.label,
            reason: item.reason,
        })
        .collect();

    absorb(report.entries, refused, now_ms)
}

// ---------------------------------------------------------------------------
// Backup: getting the data out again (FR-26 to FR-29, FR-36)
// ---------------------------------------------------------------------------

/// FR-26 and FR-27: every entry, written to a file the user keeps.
///
/// `passphrase` present means FR-26's encrypted backup; absent means FR-27's
/// plain one, which is every secret in clear text and must not be reachable
/// without the double confirmation the interface puts in front of it.
///
/// FR-36 is `with_vault`: it fails while locked, so neither kind can be
/// produced from a locked app. That is the same gate `reveal_secret_for_export`
/// sits behind, and for the same reason.
///
/// Returns the file contents rather than writing a file. Where a backup is
/// allowed to land is a platform question — the share sheet, the documents
/// picker, a directory the app may not touch on Android 13 — and the core has
/// no business guessing at it.
pub fn export_backup(passphrase: Option<String>) -> Result<String> {
    let payloads = with_vault(|vault| {
        let (entries, unreadable) = vault.list()?;
        // Refused, not silently short. `list` skips a record it cannot open so
        // that one damaged row does not hide every other code — right for a
        // screen, wrong for a backup, where the missing entry would not be
        // noticed until the file was needed.
        if unreadable > 0 {
            return Err(anyhow!(
                "{unreadable} entr{} in this vault could not be read, so a backup                  would be missing {}. Nothing has been exported. Sync this device                  and try again.",
                if unreadable == 1 { "y" } else { "ies" },
                if unreadable == 1 { "it" } else { "them" },
            ));
        }
        // Trashed entries are left out. A user who deletes an account and then
        // makes a backup does not expect the secret they just removed to be in
        // the file — and in FR-27's plain export it would be readable. Trash is
        // recoverable inside the app; it is not something to carry off the
        // device.
        //
        // Restoring is unaffected: a live entry exports and comes back live.
        Ok(entries
            .into_iter()
            .filter(|entry| {
                entry
                    .payload
                    .as_otp()
                    .is_none_or(|otp| otp.trashed_at.is_none())
            })
            .map(|entry| entry.payload)
            .collect::<Vec<_>>())
    })?;

    let text = match passphrase {
        Some(passphrase) => authcore::backup::export_encrypted(&payloads, &passphrase),
        None => authcore::backup::export_plain(&payloads),
    }
    .map_err(|error| anyhow!("{error}"))?;

    Ok(text.to_string())
}

/// Whether a chosen file needs a passphrase, before the user waits on Argon2id.
///
/// Also the answer to "is this even one of ours", which is why it can fail.
#[flutter_rust_bridge::frb(sync)]
pub fn backup_needs_passphrase(text: String) -> Result<bool> {
    authcore::backup::needs_passphrase(&text).map_err(|error| anyhow!("{error}"))
}

#[derive(Debug, Clone)]
pub struct BackupVerificationView {
    pub entry_count: u32,
    pub folder_count: u32,
    pub was_encrypted: bool,
}

/// Opens and validates a backup without writing to the vault.
pub fn verify_backup(text: String, passphrase: Option<String>) -> Result<BackupVerificationView> {
    let report = authcore::backup::verify(&text, passphrase.as_deref())
        .map_err(|error| anyhow!("{error}"))?;
    Ok(BackupVerificationView {
        entry_count: report.entry_count.try_into().unwrap_or(u32::MAX),
        folder_count: report.folder_count.try_into().unwrap_or(u32::MAX),
        was_encrypted: report.was_encrypted,
    })
}

/// FR-28: reads a backup this app wrote, of either kind.
///
/// Goes through the same [`absorb`] as every other import, so FR-16's duplicate
/// rule and FR-15d's partial report apply here without being restated. That
/// matters most for the case people actually hit: restoring a backup onto a
/// device that already has some of the accounts on it.
pub fn import_backup(
    text: String,
    passphrase: Option<String>,
    now_ms: i64,
) -> Result<ImportReportView> {
    let backup =
        authcore::backup::read(&text, passphrase.as_deref()).map_err(|error| anyhow!("{error}"))?;
    absorb(backup.entries, Vec::new(), now_ms)
}

/// Abandons a partly scanned export.
pub fn migration_reset() -> Result<()> {
    *MIGRATION.lock().map_err(|_| lock_poisoned())? = None;
    Ok(())
}
