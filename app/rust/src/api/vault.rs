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
//! - **One exception, and it is deliberate.** The device slot (section 9.2.4)
//!   needs the platform keystore to wrap the vault key, and a non-exportable
//!   keystore key can only be driven from platform code. The raw vault key
//!   therefore crosses this boundary once at setup and once at each unlock.
//!   See [`begin_device_setup`] for what that costs.

use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use authcore::crypto::{VaultKey, XChaChaCipher};
use authcore::device_slot::{self, OpenRequest, SetupRequest, SlotState};
use authcore::entry::{OtpEntry, Payload};
use authcore::lock_policy::LockPolicy;
use authcore::otp::{self, Algorithm, OtpKind};
use authcore::otpauth::OtpAuthUri;
use authcore::store::{MetaStore, Store};
use authcore::vault::Vault;

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

fn lock_poisoned() -> anyhow::Error {
    anyhow!("The vault lock was poisoned by an earlier failure. Restart the application.")
}

/// Reads the metadata file, wherever it currently lives.
///
/// While locked it sits in `META`; while unlocked the `Store` owns it. Callers
/// that only want to read it — the slot state, the time offset — should not
/// have to know which, and should not fail merely because the vault happens to
/// be open.
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
fn take_meta() -> Result<MetaStore> {
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

/// One row of the code list, ready to render.
pub struct EntryView {
    pub id: String,
    /// `"totp"` or `"hotp"`.
    pub kind: String,
    pub issuer: Option<String>,
    pub account: String,
    pub code: String,
    pub digits: u32,
    pub period: u32,
    /// Seconds until the code changes. Zero for HOTP, which does not expire.
    pub remaining_seconds: u32,
    pub counter: Option<u64>,
    pub favourite: bool,
    pub icon: Option<String>,
}

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

/// Deletes a stage S2 plaintext database if one is present.
///
/// Must run before [`open_meta`]. An S2 file cannot be read by this build —
/// its payloads were never encrypted, so they fail to decrypt and are reported
/// as damaged, which is indistinguishable from data loss. Returns true when
/// something was discarded, so the caller can say so rather than leaving the
/// user to guess why their development entries vanished.
#[flutter_rust_bridge::frb(sync)]
pub fn discard_legacy_vault(vault_path: String, meta_path: String) -> Result<bool> {
    Ok(authcore::store::discard_legacy_plaintext_vault(
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

/// First run: generates the vault key and hands it out to be wrapped.
///
/// # What this exposes
///
/// The returned bytes are the vault key in the clear. They exist in Dart for
/// as long as it takes to pass them to the keystore, and Dart cannot wipe
/// memory the way `Zeroizing` does — the garbage collector may keep copies.
/// This is the unavoidable cost of a non-exportable keystore key: the wrap has
/// to happen in platform code, and platform code cannot be reached from Rust
/// without an out-of-band handle to the JVM.
///
/// The caller must pass these straight to the wrap call, overwrite the buffer,
/// and never store or log them. Section 9.4's "do not log key material" covers
/// the Dart side as much as this one.
pub fn begin_device_setup() -> Result<Vec<u8>> {
    let request = device_slot::begin_setup().map_err(|error| anyhow!("{error}"))?;
    let key = request.key_to_wrap().to_vec();

    *PENDING_SETUP.lock().map_err(|_| lock_poisoned())? = Some(request);
    Ok(key)
}

/// First run with a PIN: seals the vault key under it, then hands the sealed
/// blob out to be wrapped by the keystore (section 9.2.4 step 4).
///
/// What crosses the boundary here is already ciphertext, so this call does not
/// carry the exposure that [`begin_device_setup`] does.
pub fn begin_device_setup_with_pin(pin: String) -> Result<Vec<u8>> {
    let request = device_slot::begin_setup_with_pin(&pin).map_err(|error| anyhow!("{error}"))?;
    let blob = request.key_to_wrap().to_vec();

    *PENDING_SETUP.lock().map_err(|_| lock_poisoned())? = Some(request);
    Ok(blob)
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
    Ok(blob)
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

/// Adopts the unwrapped key and opens the vault.
///
/// The same exposure note as [`begin_device_setup`] applies to `unwrapped`.
pub fn finish_device_open(vault_path: String, unwrapped: Vec<u8>) -> Result<()> {
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
            with_meta(|meta| Ok(meta.record_failed_unlock()?))?;
            return Err(anyhow!("{error}"));
        }
    };

    let meta = take_meta()?;
    meta.clear_failed_unlocks()?;
    open_vault_with_key(&vault_path, meta, key)
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
}

#[flutter_rust_bridge::frb(sync)]
pub fn lock_policy() -> Result<LockPolicyView> {
    with_meta(|meta| {
        let policy = LockPolicy::load(meta)?;
        Ok(LockPolicyView {
            timeout_seconds: policy.timeout_seconds,
            lock_on_background: policy.lock_on_background,
        })
    })
}

pub fn set_lock_policy(timeout_seconds: Option<u32>, lock_on_background: bool) -> Result<()> {
    with_meta(|meta| {
        LockPolicy {
            timeout_seconds,
            lock_on_background,
        }
        .save(meta)?;
        Ok(())
    })
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
    let store = Store::open(vault_path, meta, Some(&key.sqlcipher_key()))
        .context("The vault could not be opened")?;
    let vault = Vault::open(store, XChaChaCipher::new(&key))?;

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
    CURRENT_KEY.lock().map_err(|_| lock_poisoned())?.take();
    let existing = VAULT.lock().map_err(|_| lock_poisoned())?.take();

    let mut meta = match existing {
        Some(mut vault) => {
            vault.store_mut().clear_entries()?;
            vault.into_store().into_meta()
        }
        None => take_meta()?,
    };

    device_slot::wipe(&mut meta).map_err(|error| anyhow!("{error}"))?;
    *META.lock().map_err(|_| lock_poisoned())? = Some(meta);
    Ok(())
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
            let kind = match entry.payload {
                Payload::Hotp(_) => OtpKind::Hotp,
                _ => OtpKind::Totp,
            };

            let secret = otp_entry
                .secret
                .decode()
                .map_err(|error| anyhow!("{error}"))?;

            let (code, remaining) = match kind {
                OtpKind::Totp => (
                    otp::totp_at(
                        &secret,
                        now_unix_seconds,
                        otp_entry.period,
                        otp_entry.digits,
                        otp_entry.algorithm,
                    )?,
                    otp::totp_remaining_seconds(now_unix_seconds, otp_entry.period),
                ),
                OtpKind::Hotp => (
                    otp::hotp(
                        &secret,
                        otp_entry.counter.unwrap_or(0),
                        otp_entry.digits,
                        otp_entry.algorithm,
                    )?,
                    0,
                ),
            };

            views.push(EntryView {
                id: entry.id,
                kind: kind.as_str().to_string(),
                issuer: otp_entry.issuer.clone(),
                account: otp_entry.account.clone(),
                code,
                digits: u32::from(otp_entry.digits),
                period: otp_entry.period,
                remaining_seconds: remaining,
                counter: otp_entry.counter,
                favourite: otp_entry.favourite,
                icon: otp_entry.icon.clone(),
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
    now_ms: i64,
) -> Result<()> {
    with_vault(|vault| {
        let existing = vault.get(&id)?;
        let mut payload = existing.payload.clone();
        match &mut payload {
            Payload::Totp(entry) | Payload::Hotp(entry) => {
                entry.issuer = issuer.clone().filter(|value| !value.trim().is_empty());
                entry.account = account.clone();
            }
            Payload::Folder(folder) => folder.name = account.clone(),
        }
        vault.update(&id, &payload, now_ms)?;
        Ok(())
    })
}

/// FR-18: delete an entry, leaving a tombstone.
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
        if let Payload::Totp(entry) | Payload::Hotp(entry) = &mut payload {
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
        Ok(otp_entry.secret.expose().to_string())
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
