//! The sync account, from Dart's side (PRD sections 9.2.1, 9.5, 10.3).
//!
//! Every decision lives in `authcore`; this file translates. The one thing it
//! owns is where the server address and the session live, and that is a
//! deliberate choice worth stating.
//!
//! # Where the session is kept
//!
//! Android stores the access/refresh pair in a dedicated AES-GCM file. A
//! non-exportable Android Keystore key opens that file. The key does not
//! require user authentication, so a locked application can still run OFF-09
//! background synchronization. Dart never receives either token.
//!
//! Older Android versions of this application wrote both tokens to `meta.db`.
//! The first read migrates that pair to the native store, records the migration,
//! and securely deletes the old rows. Other targets retain the metadata backend
//! until they have an equivalent platform credential store.

use anyhow::{anyhow, Context, Result};
use authcore::account;
use authcore::backoff;
use authcore::secret::SecretString;
use authcore::session::{self, SessionClient, SessionError};
use authcore::store::MetaStore;
use authcore::time_offset::{self, Measurement};

use crate::http::ReqwestClient;
#[cfg(any(target_os = "android", feature = "jni-host-check"))]
use crate::session_store;
use crate::session_store::SessionTokens;

/// Non-secret sync settings in `meta.db`.
const META_SERVER_URL: &str = "sync.server_url";
/// Legacy plaintext keys. Android reads these only during one-way migration.
const META_ACCESS_TOKEN: &str = "sync.access_token";
const META_REFRESH_TOKEN: &str = "sync.refresh_token";
/// Prevents a sign-out or wipe from re-importing legacy rows after the native
/// store has been cleared.
#[cfg(any(target_os = "android", feature = "jni-host-check"))]
const META_TOKEN_STORE: &str = "sync.token_store";
#[cfg(any(target_os = "android", feature = "jni-host-check"))]
const ANDROID_TOKEN_STORE_V1: &[u8] = b"android_keystore_v1";
#[cfg(any(target_os = "android", feature = "jni-host-check"))]
const ANDROID_TOKEN_STORE_V1_ROTATE: &[u8] = b"android_keystore_v1_rotate_legacy";
/// OFF-05: the time of the last cycle that finished, and why the last one did
/// not. Both live in `meta` rather than the vault, for the same reason the
/// token does — a locked device syncs, so a locked device must be able to
/// record that it did.
const META_LAST_SUCCESS: &str = "sync.last_success_ms";
const META_LAST_ERROR: &str = "sync.last_error";

/// Everything OFF-05 needs: three states and the time of the last success.
///
/// The state itself is not stored. It is derived by the caller from these
/// facts, because a stored state goes stale the moment anything happens
/// without writing it back — and the one thing a status indicator must never
/// do is confidently report the wrong thing.
pub struct SyncStatusView {
    pub server_url: Option<String>,
    /// True when a session token is stored. It may still have expired — only a
    /// request finds that out, and the answer is a sign-in prompt either way.
    pub signed_in: bool,
    pub email: Option<String>,
    /// Records waiting to reach the server. Zero while locked, because the
    /// outbox lives in the encrypted database — see [`sync_status`].
    pub pending: u32,
    /// True when the count above could actually be read.
    ///
    /// Without it, "0 pending" and "cannot tell" are the same number, and the
    /// user interface would show a locked device as fully synced.
    pub pending_known: bool,
    /// Epoch milliseconds of the last cycle that completed.
    pub last_success_ms: Option<i64>,
    /// Why the last attempt failed, if the one after it has not succeeded.
    pub last_error: Option<String>,
}

/// Reads the sync status without touching the network.
#[flutter_rust_bridge::frb(sync)]
pub fn sync_status() -> Result<SyncStatusView> {
    // The outbox lives in the encrypted database, so a locked device cannot
    // count it. That is reported as "unknown" rather than as zero: a locked
    // device with work waiting would otherwise read as fully synced, which is
    // the one answer a status indicator must never give wrongly.
    let (pending, pending_known) = match crate::api::vault::outbox_len() {
        Ok(count) => (count as u32, true),
        Err(_) => (0, false),
    };

    crate::api::vault::with_meta_pub(|meta| {
        Ok(SyncStatusView {
            server_url: text(meta, META_SERVER_URL)?,
            signed_in: session_is_stored(meta)?,
            email: account::load(meta)
                .map_err(|error| anyhow!("{error}"))?
                .map(|account| account.email),
            pending,
            pending_known,
            last_success_ms: text(meta, META_LAST_SUCCESS)?.and_then(|value| value.parse().ok()),
            last_error: text(meta, META_LAST_ERROR)?,
        })
    })
}

/// Records how a cycle ended, for OFF-05.
///
/// A success clears the last error. Leaving it would mean the interface still
/// showing "could not reach the server" over a vault that is up to date, which
/// trains the user to ignore the indicator.
fn record_outcome(result: core::result::Result<(), String>) -> Result<()> {
    crate::api::vault::with_meta_pub(|meta| {
        match result {
            Ok(()) => {
                meta.set(META_LAST_SUCCESS, now_ms().to_string().as_bytes())?;
                meta.remove(META_LAST_ERROR)?;
            }
            Err(detail) => {
                meta.set(META_LAST_ERROR, detail.as_bytes())?;
            }
        }
        Ok(())
    })
}

/// Points this device at a server. Stored, not contacted.
pub fn set_server_url(url: String) -> Result<()> {
    let trimmed = url.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("Enter the address of a sync server."));
    }
    check_scheme(&trimmed, cfg!(debug_assertions))?;

    crate::api::vault::with_meta_pub(|meta| {
        meta.set(META_SERVER_URL, trimmed.as_bytes())?;
        Ok(())
    })
}

/// Registers the account this device already built locally, then signs in.
///
/// The slots must exist first: `create_account` wraps the vault key this device
/// holds, and section 9.2.4 forbids minting a new one — every entry is already
/// encrypted under the existing key.
///
/// Registration and sign-in are one call because a half-finished sign-up is a
/// state with no good recovery: the account exists on the server, the device
/// has no session, and trying again gets "already registered". If sign-in fails
/// after a successful registration the error says so, and [`sign_in`] on its
/// own is the way back.
pub fn register_account(password: String, device_name: Option<String>) -> Result<()> {
    let (account, base) = crate::api::vault::with_meta_pub(|meta| {
        let account = account::load(meta)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| anyhow!("Create an account on this device before registering it."))?;
        let base =
            text(meta, META_SERVER_URL)?.ok_or_else(|| anyhow!("Choose a sync server first."))?;
        Ok((account, base))
    })?;

    let slot = account
        .password_slot
        .as_ref()
        .ok_or_else(|| anyhow!("This device has no password slot to register."))?;
    let auth_key = account::derive_auth_key(&password, slot).map_err(|error| anyhow!("{error}"))?;

    let client = SessionClient::new(ReqwestClient::new(), &base);
    client
        .register(&account, &auth_key)
        .map_err(|error| anyhow!("{error}"))?;

    let session = client
        .login(&account.email, &auth_key, device_name.as_deref())
        .map_err(|error| {
            anyhow!(
                "The account was created, but signing in failed: {error} \
                 Sign in to finish setting up sync."
            )
        })?;

    store_session(&session)
}

/// Signs in on a device that does not hold the account yet.
///
/// The second-device path. The server hands back the wrapped vault key, and
/// this device unwraps it with a key-encryption key it derives itself from the
/// password and the salt `prelogin` returned. The server never sees either.
///
/// Section 9.5: `prelogin` answers for an unknown address exactly as it does
/// for a known one, so nothing here may treat a successful response as evidence
/// the account exists. It does not — it derives a key and tries to sign in, and
/// a wrong address and a wrong password fail identically.
pub fn sign_in(email: String, password: String, device_name: Option<String>) -> Result<()> {
    let base = crate::api::vault::with_meta_pub(|meta| {
        text(meta, META_SERVER_URL)?.ok_or_else(|| anyhow!("Choose a sync server first."))
    })?;

    let client = SessionClient::new(ReqwestClient::new(), &base);
    let prelogin = client
        .prelogin(&email)
        .map_err(|error| anyhow!("{error}"))?;

    let salt: [u8; 16] = prelogin
        .client_salt
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("The sync server sent a salt this app cannot use."))?;

    let auth_key = account::derive_auth_key(
        &password,
        &account::PasswordSlot {
            salt,
            params: prelogin.params,
            // Not read by the derivation: it needs the salt and the cost
            // parameters, and the wrapped key is what the server is about to
            // hand back.
            wrapped_key: Vec::new(),
            nonce: Vec::new(),
        },
    )
    .map_err(|error| anyhow!("{error}"))?;

    let session = client
        .login(&email, &auth_key, device_name.as_deref())
        .map_err(|error| anyhow!("{error}"))?;

    let account = session::slots_for_account(&email, &prelogin, &session)
        .map_err(|error| anyhow!("{error}"))?;

    crate::api::vault::with_meta_pub(|meta| {
        account::save(meta, &account).map_err(|error| anyhow!("{error}"))?;
        Ok(())
    })?;

    store_session(&session)?;
    Ok(())
}

/// Forgets the session. The vault and its entries stay.
///
/// Not a wipe: signing out of sync must not cost the user their codes. Wiping
/// is [`crate::api::vault::wipe_device`], which is a different button with a
/// different confirmation.
pub fn sign_out() -> Result<()> {
    crate::api::vault::with_meta_pub(clear_session)
}

// ---------------------------------------------------------------------------
// Section 9.5: devices, sign-out, and deletion
// ---------------------------------------------------------------------------

/// One device on the account, for the "your devices" screen.
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub platform: String,
    /// RFC 3339 as the server wrote it, or absent. Formatted in Dart, which
    /// already owns every other date the user reads.
    pub last_seen: Option<String>,
    pub current: bool,
    pub revoked: bool,
}

/// Section 9.5: every device that has signed in to this account.
pub fn list_devices() -> Result<Vec<DeviceView>> {
    with_account(|client, token| {
        Ok(client
            .devices(token)?
            .into_iter()
            .map(|device| DeviceView {
                id: device.id,
                name: device.name,
                platform: device.platform,
                last_seen: device.last_seen,
                current: device.current,
                revoked: device.revoked,
            })
            .collect())
    })
}

/// Cuts one device off. Its sessions end in the same request on the server.
///
/// Revoking *this* device is allowed, and leaves the local tokens useless. The
/// caller is expected to sign out locally afterwards — see the screen, which
/// asks first.
pub fn revoke_device(device_id: String) -> Result<u64> {
    with_account(|client, token| Ok(client.revoke_device(token, &device_id)?))
}

/// Ends every session on the account, including this one.
///
/// The local tokens are cleared afterwards rather than left to fail on the next
/// cycle. A device that believes it is signed in and gets a 401 every fifteen
/// minutes is the silent-stop failure this project already fixed once.
pub fn sign_out_everywhere() -> Result<u64> {
    let ended = with_account(|client, token| Ok(client.sign_out_everywhere(token)?))?;
    sign_out()?;
    Ok(ended)
}

/// Deletes the account on the server and signs this device out.
///
/// # What this does not do
///
/// It does not touch the local vault. The codes on this device keep working,
/// which is the correct behaviour and worth being deliberate about: a user
/// deleting a *sync account* is saying "stop storing my encrypted blobs", not
/// "destroy the authenticator I use every day". Wiping the device is a separate
/// action, on a separate screen, with its own confirmation.
///
/// Requires the account password, which is derived here into the same
/// authentication key the server verifies at sign-in. A stolen access token
/// must not be enough to destroy an account.
pub fn delete_account(password: String) -> Result<i64> {
    let auth_key = crate::api::vault::with_meta_pub(|meta| {
        let account = authcore::account::load(meta)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| anyhow!("This device has no sync account."))?;
        let slot = account
            .password_slot
            .ok_or_else(|| anyhow!("This account has no password set."))?;
        authcore::account::derive_auth_key(&password, &slot).map_err(|error| anyhow!("{error}"))
    })?;

    let deleted = with_account(|client, token| Ok(client.delete_account(token, &auth_key)?))?;

    // The tokens name an account that no longer exists. Leaving them would
    // make every later cycle fail against a server that has nothing to say.
    sign_out()?;
    Ok(deleted)
}

/// Runs one authenticated call, refreshing the session once if it has expired.
///
/// The retry is not politeness. The access token lasts fifteen minutes and this
/// screen is opened rarely, so the *common* case is an expired token — without
/// the retry, "your devices" would usually greet the user with a sign-out
/// message on a device that is perfectly signed in.
fn with_account<T>(
    call: impl Fn(&SessionClient<ReqwestClient>, &SecretString) -> Result<T>,
) -> Result<T> {
    rotate_migrated_session_if_needed()?;

    let (base, token) = crate::api::vault::with_meta_pub(|meta| {
        let base = server_url(meta)?.ok_or_else(|| anyhow!("Choose a sync server first."))?;
        let token = load_session(meta)?.map(|session| session.access);
        Ok((base, token))
    })?;

    let client = SessionClient::new(ReqwestClient::new(), &base);

    if let Some(token) = &token {
        match call(&client, token) {
            Err(error) if is_unauthorized(&error) => {}
            other => return other,
        }
    }

    if !try_refresh()? {
        return Err(anyhow!(
            "This device has been signed out. Sign in again to manage your devices."
        ));
    }

    let token = crate::api::vault::with_meta_pub(access_token)?
        .ok_or_else(|| anyhow!("This device has been signed out."))?;
    call(&client, &token)
}

/// Whether an error is the server saying the session is gone.
///
/// Matched on the typed variant where possible. `with_account`'s callers wrap
/// `SessionError` in `anyhow`, so the string is the only thing left by the time
/// it arrives here — which is fragile, and the reason `SessionError` gained a
/// distinct `Unauthorized` variant rather than reusing `InvalidCredentials`:
/// the two need different messages and only one of them means "retry".
fn is_unauthorized(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<SessionError>()
        .is_some_and(|inner| matches!(inner, SessionError::Unauthorized))
}

/// Section 13: "A release build must refuse a server address that is not
/// `https`. Plain HTTP is for local development only."
///
/// `allow_http` is the build profile, passed in rather than read here so the
/// rule is testable in both directions from one build. A previous version of
/// this test asserted `cfg!(debug_assertions)` inside `#[cfg(debug_assertions)]`,
/// which is a tautology — clippy caught it, and it was the same vacuous shape
/// this project keeps finding by hand.
///
/// The check it replaced was worse than vacuous: it accepted `http://` while
/// its own message said it did not. A reader would have believed plain HTTP was
/// refused, and stopped looking.
fn check_scheme(url: &str, allow_http: bool) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if allow_http && url.starts_with("http://") {
        // Allowed, and said out loud. The development server has no
        // certificate and the phone reaches it over a LAN address, so this
        // path has to exist — but a developer should be reminded that the
        // token and every record are readable on the wire.
        tracing_http_warning(url);
        return Ok(());
    }
    Err(anyhow!(
        "The address must start with https://. Plain http:// sends your          session token and your records in the clear, so release builds          refuse it."
    ))
}

/// Says, loudly, that a development build is about to use plain HTTP.
///
/// Not a silent allowance: the whole reason the release build refuses this is
/// that the traffic is readable, and a developer testing over http should be
/// reminded of what they are looking at.
fn tracing_http_warning(url: &str) {
    eprintln!(
        "authcore: WARNING: {url} is plain HTTP. The session token and every          record cross the network readable. A release build refuses this."
    );
}

/// Renews the session with the stored refresh token (section 13).
///
/// Returns false when the refresh token itself is spent or expired, which is
/// the only case that genuinely needs the user's password again.
///
/// Called when a cycle gets a 401. Without it a device syncs for fifteen
/// minutes after signing in and then stops for good — silently, because a
/// background cycle has nobody watching it.
pub(crate) fn try_refresh() -> Result<bool> {
    let (base, refresh_token) = crate::api::vault::with_meta_pub(|meta| {
        let base = server_url(meta)?.ok_or_else(|| anyhow!("Choose a sync server first."))?;
        let token = load_session(meta)?.map(|session| session.refresh);
        Ok((base, token))
    })?;

    let Some(refresh_token) = refresh_token else {
        return Ok(false);
    };

    let client = SessionClient::new(ReqwestClient::new(), &base);
    match client.refresh(&refresh_token) {
        Ok(renewal) => {
            // Both halves. The server revoked the token that was spent, so
            // keeping the old one would sign this device out at the next
            // renewal — the same defect one step later.
            crate::api::vault::with_meta_pub(|meta| {
                save_session(
                    meta,
                    &SessionTokens {
                        access: renewal.access_token,
                        refresh: renewal.refresh_token,
                    },
                )
            })?;
            Ok(true)
        }
        // The refresh token is gone too. This is the real sign-out.
        Err(SessionError::InvalidCredentials) => {
            // A spent or revoked refresh token is not a usable session. Clear
            // it now so status reports "signed out" instead of retrying the
            // same dead credential on every cycle.
            crate::api::vault::with_meta_pub(clear_session)?;
            Ok(false)
        }
        Err(error) => Err(anyhow!("{error}")),
    }
}

fn store_session(session: &session::Session) -> Result<()> {
    crate::api::vault::with_meta_pub(|meta| {
        save_session(
            meta,
            &SessionTokens {
                access: session.access_token.clone(),
                refresh: session.refresh_token.clone(),
            },
        )
    })
}

/// Reads both halves together. Refresh rotation is an atomic pair, so callers
/// must never observe a new access token with an old refresh token.
fn load_session(meta: &MetaStore) -> Result<Option<SessionTokens>> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        migrate_legacy_session(meta)?;
        session_store::read_session()
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        legacy_session(meta)
    }
}

fn session_is_stored(meta: &MetaStore) -> Result<bool> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        migrate_legacy_session(meta)?;
        session_store::has_session()
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        Ok(legacy_session(meta)?.is_some())
    }
}

fn save_session(meta: &MetaStore, tokens: &SessionTokens) -> Result<()> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        // The encrypted file lands first. If the process stops before the
        // marker or cleanup, the next read sees the native value and finishes
        // migration without losing the session.
        session_store::write_session(tokens)?;
        meta.set(META_TOKEN_STORE, ANDROID_TOKEN_STORE_V1)?;
        remove_legacy_session(meta)?;
        Ok(())
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        meta.set(META_ACCESS_TOKEN, tokens.access.expose().as_bytes())?;
        meta.set(META_REFRESH_TOKEN, tokens.refresh.expose().as_bytes())?;
        Ok(())
    }
}

/// Clears credentials without clearing account metadata or encrypted entries.
/// Kept `pub(crate)` so **Wipe this device** cannot leave a live session in the
/// dedicated native store.
pub(crate) fn clear_session(meta: &MetaStore) -> Result<()> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        // Write the one-way marker before deleting anything. A process stop
        // can then never cause an old metadata row to be imported again.
        meta.set(META_TOKEN_STORE, ANDROID_TOKEN_STORE_V1)?;
        remove_legacy_session(meta)?;
        session_store::clear_session()
    }

    #[cfg(not(any(target_os = "android", feature = "jni-host-check")))]
    {
        remove_legacy_session(meta)
    }
}

#[cfg(any(target_os = "android", feature = "jni-host-check"))]
fn migrate_legacy_session(meta: &MetaStore) -> Result<()> {
    let marker = meta.get(META_TOKEN_STORE)?;
    if let Some(marker) = marker {
        if marker.as_slice() != ANDROID_TOKEN_STORE_V1
            && marker.as_slice() != ANDROID_TOKEN_STORE_V1_ROTATE
        {
            return Err(anyhow!(
                "This application does not support the stored synchronization token format."
            ));
        }
        // Finish cleanup after a process stop between marker commit and row
        // deletion. The marker forbids re-import.
        remove_legacy_session(meta)?;
        return Ok(());
    }

    let legacy = legacy_session(meta)?;
    let migrated_plaintext = legacy.is_some();
    match session_store::read_session() {
        Ok(Some(_)) => {
            // The encrypted write completed, but the marker did not. Reading
            // it first proves that a corrupted file will not replace a usable
            // legacy pair.
        }
        Ok(None) => {
            if let Some(tokens) = legacy {
                session_store::write_session(&tokens)?;
            }
        }
        Err(error) => {
            let Some(tokens) = legacy else {
                return Err(error);
            };
            // A damaged native file and an intact legacy pair can occur only
            // during migration or external file corruption. Repair it before
            // deleting the only usable pair.
            session_store::clear_session()?;
            session_store::write_session(&tokens)?;
        }
    }
    meta.set(
        META_TOKEN_STORE,
        if migrated_plaintext {
            ANDROID_TOKEN_STORE_V1_ROTATE
        } else {
            ANDROID_TOKEN_STORE_V1
        },
    )?;
    remove_legacy_session(meta)
}

/// Rotates a pair that ever existed in plaintext metadata.
///
/// SQLite `secure_delete` overwrites the live cell. It cannot erase a copy in
/// a filesystem journal, flash remapping layer, or old device backup. Refresh
/// rotation revokes that old pair at the server, so recovered residue no
/// longer authenticates after the first successful online operation.
fn rotate_migrated_session_if_needed() -> Result<()> {
    #[cfg(any(target_os = "android", feature = "jni-host-check"))]
    {
        let pending = crate::api::vault::with_meta_pub(|meta| {
            migrate_legacy_session(meta)?;
            Ok(meta.get(META_TOKEN_STORE)?.as_deref() == Some(ANDROID_TOKEN_STORE_V1_ROTATE))
        })?;
        if pending && !try_refresh()? {
            return Err(anyhow!(
                "This device has been signed out. Sign in again to keep syncing."
            ));
        }
    }
    Ok(())
}

fn legacy_session(meta: &MetaStore) -> Result<Option<SessionTokens>> {
    let access = legacy_token(meta, META_ACCESS_TOKEN)?;
    let refresh = legacy_token(meta, META_REFRESH_TOKEN)?;
    match (access, refresh) {
        (Some(access), Some(refresh)) => Ok(Some(SessionTokens { access, refresh })),
        // A half-written old pair cannot authenticate or refresh. Treat it as
        // signed out instead of combining it with a future value.
        _ => Ok(None),
    }
}

fn legacy_token(meta: &MetaStore, key: &str) -> Result<Option<SecretString>> {
    let Some(mut bytes) = meta.get(key)? else {
        return Ok(None);
    };
    let result = core::str::from_utf8(&bytes)
        .context("a stored synchronization token is not valid text")
        .map(SecretString::new);
    bytes.fill(0);
    result.map(Some)
}

fn remove_legacy_session(meta: &MetaStore) -> Result<()> {
    meta.remove(META_ACCESS_TOKEN)?;
    meta.remove(META_REFRESH_TOKEN)?;
    Ok(())
}

/// The access token, for the sync cycle.
pub(crate) fn access_token(meta: &MetaStore) -> Result<Option<SecretString>> {
    Ok(load_session(meta)?.map(|session| session.access))
}

pub(crate) fn server_url(meta: &MetaStore) -> Result<Option<String>> {
    text(meta, META_SERVER_URL)
}

fn text(meta: &MetaStore, key: &str) -> Result<Option<String>> {
    match meta.get(key)? {
        None => Ok(None),
        Some(bytes) => Ok(Some(
            String::from_utf8(bytes).context("a stored sync setting is not valid text")?,
        )),
    }
}

/// What one sync run did, for the UI.
pub struct SyncRunView {
    pub pulled: u32,
    pub applied: u32,
    pub pushed: u32,
    pub conflicts: u32,
    /// Entries whose HOTP counter section 10.4's rule had to correct.
    pub counters_corrected: u32,
    /// Set when the session has expired. The UI asks for a sign-in rather than
    /// retrying, which with the same token would loop forever.
    pub needs_sign_in: bool,
    /// True when OFF-06's backoff meant no attempt was made at all.
    ///
    /// Reported rather than hidden. A caller that cannot tell "nothing to do"
    /// from "not yet" has no way to schedule its next wake-up, and a user
    /// watching a spinner that resolves to nothing learns the button is
    /// broken.
    pub skipped_by_backoff: bool,
    /// Milliseconds until the next attempt is due, when one was skipped.
    pub retry_in_ms: i64,
}

/// Runs one sync cycle now.
///
/// Requires an open vault. A locked device can sync — OFF-09 is explicit that
/// it must be able to — but that path needs the cycle to run without a `Vault`
/// and is wired separately; this is the foreground one, called from the UI and
/// after an unlock.
///
/// A stale cursor is handled here rather than reported: section 10.6 says the
/// only correct answer is a full re-sync, so there is nothing for the user to
/// decide.
pub fn sync_now(force: bool) -> Result<SyncRunView> {
    let now_ms = now_ms();

    // OFF-06. A user pressing the button is never made to wait: they can see
    // the state on screen, and refusing them is how an application earns a
    // reputation for being stuck. The backoff exists to stop *automatic*
    // retries hammering a server that is already failing.
    if !force {
        let schedule = crate::api::vault::with_meta_pub(|meta| {
            backoff::load(meta).map_err(|error| anyhow!("{error}"))
        })?;
        if !schedule.is_due(now_ms) {
            return Ok(SyncRunView {
                pulled: 0,
                applied: 0,
                pushed: 0,
                conflicts: 0,
                counters_corrected: 0,
                needs_sign_in: false,
                skipped_by_backoff: true,
                retry_in_ms: schedule.wait_ms(now_ms) as i64,
            });
        }
    }

    // A pair migrated out of plaintext storage is replaced before it performs
    // any other authenticated operation. The server revokes the old session
    // during refresh, which invalidates token residue outside the live SQLite
    // database.
    rotate_migrated_session_if_needed()?;

    let (base, token) = crate::api::vault::with_meta_pub(|meta| {
        let base = server_url(meta)?.ok_or_else(|| anyhow!("Choose a sync server first."))?;
        let token = access_token(meta)?.ok_or_else(|| anyhow!("Sign in to sync this device."))?;
        Ok((base, token))
    })?;

    let mut transport =
        authcore::transport::ServerTransport::new(ReqwestClient::new(), &base, token);

    let outcome = run_one_cycle(&mut transport, now_ms);

    // OFF-05, recorded whichever way it went. A status indicator that only
    // updates on success shows "synced, 2 minutes ago" through an outage.
    // A 401 is not a sign-out: the access token lasts fifteen minutes and is
    // *expected* to expire. Renew and try once more. Only a refresh token that
    // is itself spent means the user has to type a password again.
    //
    // Once, not in a loop. A second 401 straight after a successful renewal is
    // a disagreement this cycle cannot resolve, and retrying it would spin.
    let outcome = match &outcome {
        Ok(run) if run.needs_sign_in => {
            if try_refresh()? {
                let token = crate::api::vault::with_meta_pub(|meta| {
                    access_token(meta)?.ok_or_else(|| anyhow!("the renewed session was not stored"))
                })?;
                transport.set_token(token);
                run_one_cycle(&mut transport, now_ms)
            } else {
                outcome
            }
        }
        _ => outcome,
    };

    // FR-37 and FR-38, from requests the cycle was making anyway. Done before
    // the verdict is recorded so that a *failed* cycle still corrects the
    // clock: a wrong clock is one of the reasons a request fails, and a device
    // that never syncs is the one most in need of the answer.
    record_clock_measurement(&transport)?;

    let verdict = match &outcome {
        Ok(run) if run.needs_sign_in => Err("this device has been signed out".to_string()),
        Ok(_) => Ok(()),
        Err(error) => Err(error.to_string()),
    };
    record_outcome(verdict.clone())?;

    // OFF-06's schedule, moved by the same verdict that moved the status. Two
    // sources of truth for "did that work" would drift, and the one that
    // drifted would be the one nobody was watching.
    crate::api::vault::with_meta_pub(|meta| {
        match &verdict {
            Ok(()) => backoff::record_success(meta).map_err(|error| anyhow!("{error}"))?,
            Err(_) => {
                backoff::record_failure(meta, now_ms, jitter())
                    .map_err(|error| anyhow!("{error}"))?;
            }
        }
        Ok(())
    })?;

    outcome
}

/// One cycle, without the session handling around it.
///
/// Extracted so it can run twice: once, and again after a 401 has been
/// answered by renewing the session. Keeping it in one place means the retry
/// exercises the same code as the first attempt, rather than a second version
/// of it that drifts.
fn run_one_cycle(
    transport: &mut authcore::transport::ServerTransport<ReqwestClient>,
    now_ms: u64,
) -> Result<SyncRunView> {
    crate::api::vault::with_vault_pub(|vault| {
        use authcore::sync::SyncError;
        use authcore::vault::SyncFailure;

        match vault.sync(transport, now_ms) {
            Ok(outcome) => Ok(SyncRunView {
                pulled: outcome.cycle.pulled as u32,
                applied: outcome.cycle.applied as u32,
                pushed: outcome.cycle.pushed as u32,
                conflicts: outcome.cycle.conflicts as u32,
                counters_corrected: outcome.reconcile.counters_raised as u32,
                needs_sign_in: false,
                skipped_by_backoff: false,
                retry_in_ms: 0,
            }),

            // Section 10.6. Not a failure to report: the cursor is unusable and
            // a full re-sync is the only correct response, so do it rather than
            // asking the user about a cursor they have never heard of.
            Err(SyncFailure::Cycle(SyncError::CursorTooOld)) => {
                let outcome = vault
                    .full_resync(transport, now_ms)
                    .map_err(|error| anyhow!("{error}"))?;
                Ok(SyncRunView {
                    pulled: outcome.applied as u32,
                    applied: outcome.applied as u32,
                    pushed: 0,
                    conflicts: 0,
                    counters_corrected: outcome.reconcile.counters_raised as u32,
                    needs_sign_in: false,
                    skipped_by_backoff: false,
                    retry_in_ms: 0,
                })
            }

            // Handled outside this closure: renewing needs the metadata file,
            // and the vault is holding it for the duration of this borrow.
            Err(SyncFailure::Cycle(SyncError::Unauthorized)) => Ok(SyncRunView {
                pulled: 0,
                applied: 0,
                pushed: 0,
                conflicts: 0,
                counters_corrected: 0,
                needs_sign_in: true,
                skipped_by_backoff: false,
                retry_in_ms: 0,
            }),

            Err(error) => Err(anyhow!("{error}")),
        }
    })
}

/// Stores what the last request said about this device's clock (FR-38).
///
/// FR-39: nothing here sets a system clock. The offset is stored and added when
/// a code is generated, which is the only place it is wanted.
fn record_clock_measurement(
    transport: &authcore::transport::ServerTransport<ReqwestClient>,
) -> Result<()> {
    let Some(sample) = transport.latest_sample() else {
        // Nothing measured. Deliberately not written as zero — see
        // `time_offset::Measurement::None`.
        return Ok(());
    };

    let Measurement::Offset { seconds, .. } = time_offset::measure(sample) else {
        // Too slow, or implausible. A wrong offset is worse than none: none
        // shows in the interface as unmeasured, and wrong shows as correct.
        return Ok(());
    };

    crate::api::vault::with_meta_pub(|meta| {
        let stored = meta.time_offset_seconds()?;
        if time_offset::worth_storing(stored, seconds) {
            meta.set_time_offset_seconds(seconds)?;
        }
        Ok(())
    })
}

/// A value in 0.0 to 1.0 for OFF-06's jitter.
///
/// Not cryptographic and not required to be: its only job is to stop every
/// device that lost the same server returning in the same second. Derived from
/// the clock's sub-second remainder, which differs between devices for free
/// and needs no source of randomness inside a sync path.
fn jitter() -> f64 {
    (now_ms() % 1000) as f64 / 1000.0
}

/// Wall-clock milliseconds, for the sync cycle's drift bound.
///
/// The wall clock and not the monotonic one, deliberately: section 10.2's
/// comparison is against timestamps other devices issued, which are wall-clock
/// values. The monotonic clock is for the lock timeout (FR-33a), where the
/// question is how long this device has been idle and a user changing the
/// system time must not shorten it.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::check_scheme;

    #[test]
    fn https_is_accepted_by_every_build() {
        assert!(check_scheme("https://sync.example.invalid", true).is_ok());
        assert!(check_scheme("https://sync.example.invalid", false).is_ok());
    }

    #[test]
    fn a_release_build_refuses_plain_http() {
        // Section 13. On plain HTTP the bearer token and every record cross the
        // network readable, so this is refused rather than warned about.
        let error = check_scheme("http://192.168.1.10:8080", false).unwrap_err();
        assert!(
            error.to_string().contains("https://"),
            "the message must say what is wanted, not just that this is wrong"
        );
    }

    #[test]
    fn a_development_build_allows_it_because_the_test_server_has_no_certificate() {
        assert!(check_scheme("http://192.168.1.10:8080", true).is_ok());
    }

    #[test]
    fn anything_that_is_not_a_url_is_refused_by_both() {
        // Including schemes that merely start the right way. `httpsx://` and a
        // bare host are both things a user can type.
        for url in [
            "",
            "sync.example.invalid",
            "ftp://sync.example.invalid",
            "javascript:alert(1)",
            "HTTPS://sync.example.invalid",
        ] {
            assert!(check_scheme(url, true).is_err(), "{url:?} was allowed");
            assert!(check_scheme(url, false).is_err(), "{url:?} was allowed");
        }
    }
}
