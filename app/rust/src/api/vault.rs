//! The Dart-facing surface of the vault.
//!
//! This crate is a translation layer and nothing more. Every rule — what a
//! valid period is, how a duplicate is detected, which timestamp wins — lives
//! in `authcore`, so that the audit in section 14.2 covers one implementation
//! rather than one per platform.
//!
//! Two conventions hold throughout:
//!
//! - **No clock reads.** Dart passes the reference time in. It is the device
//!   clock plus the stored offset (FR-38), and keeping it a parameter is what
//!   lets the whole list render from one consistent instant.
//! - **No secrets returned.** A code goes out; the Base32 secret does not. The
//!   one exception is [`reveal_secret_for_export`], which is named to be hard
//!   to call by accident.

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use authcore::base32;
use authcore::entry::{OtpEntry, Payload};
use authcore::otp::{self, Algorithm, OtpKind};
use authcore::otpauth::OtpAuthUri;
use authcore::store::Store;
use authcore::vault::{NullCipher, Vault};

/// The open vault. One per process; the application has exactly one.
static VAULT: Mutex<Option<Vault<NullCipher>>> = Mutex::new(None);

fn with_vault<T>(f: impl FnOnce(&mut Vault<NullCipher>) -> Result<T>) -> Result<T> {
    let mut guard = VAULT
        .lock()
        .map_err(|_| anyhow!("The vault lock was poisoned by an earlier failure."))?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| anyhow!("The vault is not open."))?;
    f(vault)
}

/// One row of the code list, ready to render.
///
/// The code is computed here rather than in Dart so the OTP engine stays in one
/// place. `remaining_seconds` comes along with it so the row and its countdown
/// cannot disagree about which time step they are showing.
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
    /// The current counter, for HOTP entries only.
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

/// The result of adding an entry.
///
/// Exactly one field is set. This is a struct rather than an enum with data
/// because the latter makes the bridge generate a `freezed` union, which would
/// pull a second code generator and a `build_runner` step into the Flutter
/// build for the sake of one type.
pub struct AddOutcome {
    /// Set when the entry was stored.
    pub added_id: Option<String>,
    /// FR-16: "Reject a duplicate secret and offer to open the existing entry."
    /// A duplicate is not a failure — the user interface offers to open the
    /// entry that already holds this secret — so it comes back as an outcome.
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

/// Opens the vault at `db_path`, creating it if it does not exist.
///
/// Safe to call again; a second call replaces the open vault, which is what a
/// re-lock and unlock cycle needs.
#[flutter_rust_bridge::frb(sync)]
pub fn open_vault(db_path: String) -> Result<()> {
    let store = Store::open(&db_path).context("The local database could not be opened")?;
    let vault = Vault::open(store, NullCipher)?;

    let mut guard = VAULT
        .lock()
        .map_err(|_| anyhow!("The vault lock was poisoned by an earlier failure."))?;
    *guard = Some(vault);
    Ok(())
}

/// Closes the vault and drops the handle. Called when the lock engages.
#[flutter_rust_bridge::frb(sync)]
pub fn close_vault() -> Result<()> {
    let mut guard = VAULT
        .lock()
        .map_err(|_| anyhow!("The vault lock was poisoned by an earlier failure."))?;
    *guard = None;
    Ok(())
}

#[flutter_rust_bridge::frb(sync)]
pub fn is_vault_open() -> bool {
    VAULT.lock().map(|guard| guard.is_some()).unwrap_or(false)
}

/// Every entry with its code at `now_unix_seconds`.
///
/// `now_unix_seconds` must already include the FR-38 offset. The caller passes
/// one value for the whole list so every row shows the same time step.
pub fn list_entries(now_unix_seconds: i64) -> Result<Vec<EntryView>> {
    with_vault(|vault| {
        let (entries, unreadable) = vault.list()?;
        if unreadable > 0 {
            // Not fatal: the readable entries still render. The count is
            // logged rather than returned because there is nothing the user
            // can do about it until the S3 recovery path exists.
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

            // Decoded once per row into a wiped buffer; the Base32 text stays
            // owned by the payload, which is dropped at the end of the loop.
            let secret = otp_entry.secret.decode().map_err(|error| anyhow!("{error}"))?;

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
///
/// The scan screen shows this so the user can see what they are about to add,
/// and so a duplicate is caught before it is written.
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
///
/// The secret arrives as the user typed it and is normalized here, so that the
/// same validation applies whether an entry was scanned or typed.
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
    let secret = base32::normalize(&secret).map_err(|error| anyhow!("{error}"))?;

    let digits = u8::try_from(digits).map_err(|_| anyhow!("{digits} is not a valid digit count."))?;
    otp::check_digits(digits)?;
    otp::check_period(period)?;
    if kind == OtpKind::Hotp && counter.is_none() {
        return Err(anyhow!("An HOTP entry needs a starting counter."));
    }

    with_vault(|vault| {
        if let Some(existing_id) = vault.find_by_secret(secret.as_str())? {
            return Ok(AddOutcome::duplicate(existing_id));
        }

        let payload = Payload::from_json(&serde_payload(
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
pub fn time_offset_seconds() -> Result<i64> {
    with_vault(|vault| Ok(vault.time_offset_seconds()?))
}

pub fn set_time_offset_seconds(offset: i64) -> Result<()> {
    with_vault(|vault| {
        vault.set_time_offset_seconds(offset)?;
        Ok(())
    })
}

/// Returns the Base32 secret of one entry.
///
/// This is the only way a secret leaves the core, and it exists for the QR
/// export in FR-30 and for the plain-text backup in FR-27. FR-36 requires an
/// unlock before either. The name is deliberately awkward so that a call site
/// stands out in review.
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
fn serde_payload(
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
