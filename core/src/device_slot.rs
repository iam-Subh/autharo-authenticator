//! The device slot (PRD section 9.2.4).
//!
//! Every device holds one, including a device that never creates a sync
//! account. It is what makes a local-only vault encrypted at rest, and it is
//! never uploaded.
//!
//! # Where the wrapping happens, and why not here
//!
//! Section 9.2.4 requires the wrapping key to live inside the platform
//! keystore and be marked non-exportable. A non-exportable key cannot be read
//! out, so the wrap and unwrap operations must run where the keystore runs —
//! in platform code, not in Rust. This module therefore does not encrypt
//! anything. It defines the shape of the slot, decides when one must be
//! created, and stores the result.
//!
//! The consequence is that the vault key crosses the language boundary once at
//! setup and once at each unlock. [`SetupRequest`] and [`OpenRequest`] name
//! that crossing explicitly rather than letting it happen implicitly inside
//! some larger call, so that every place it occurs is visible in the type.
//!
//! # Both factors, when a PIN exists
//!
//! Section 9.2.4 step 4: with a PIN set, the vault key is wrapped by the
//! keystore key *and* by a PIN-derived KEK, and both are needed. Neither alone
//! is enough — "A PIN alone is short, and a keystore key alone does not
//! survive a stolen unlocked device." [`WrapScheme`] records which of the two
//! arrangements a given slot uses, so a device that gains a PIN later can tell
//! what it is holding.

use core::fmt;

use zeroize::Zeroizing;

use crate::crypto::{CryptoError, NONCE_LEN, VaultKey, XChaChaCipher};
use crate::pin::{self, KdfParams, PinError, SALT_LEN};
use crate::store::{MetaStore, StoreError, WrappedVaultKey};
use crate::vault::RecordCipher;

/// Associated data for the PIN layer, so its ciphertext cannot be replayed as
/// a record and a record cannot be replayed as a slot.
const PIN_SLOT_ID: &str = "authcore/device-slot";
const PIN_SLOT_VERSION: u32 = 1;

/// The PIN layer's blob: everything needed to undo it, and nothing that is
/// useful without the keystore key that sits outside it.
///
/// Laid out this way rather than as extra `meta` columns so that the salt and
/// the cost parameters are themselves behind the keystore. They are not
/// secrets, but there is no reason to publish which vaults use which cost, and
/// keeping the layer self-describing means a future parameter change needs no
/// schema change.
///
/// ```text
/// [salt 16][memory 4][iterations 4][lanes 4][nonce 24][ciphertext ..]
/// ```
const PIN_HEADER_LEN: usize = SALT_LEN + 12 + NONCE_LEN;

fn encode_pin_blob(
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut blob = Vec::with_capacity(PIN_HEADER_LEN + ciphertext.len());
    blob.extend_from_slice(salt);
    blob.extend_from_slice(&params.memory_kib.to_be_bytes());
    blob.extend_from_slice(&params.iterations.to_be_bytes());
    blob.extend_from_slice(&params.lanes.to_be_bytes());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(ciphertext);
    Zeroizing::new(blob)
}

/// The PIN layer, taken apart. Named rather than a tuple so the call site
/// says what each part is.
struct PinLayer<'a> {
    salt: [u8; SALT_LEN],
    params: KdfParams,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn decode_pin_blob(blob: &[u8]) -> Result<PinLayer<'_>> {
    if blob.len() <= PIN_HEADER_LEN {
        return Err(DeviceSlotError::UnwrapProducedGarbage);
    }
    let u32_at = |offset: usize| {
        u32::from_be_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ])
    };

    let salt: [u8; SALT_LEN] = blob[..SALT_LEN]
        .try_into()
        .map_err(|_| DeviceSlotError::UnwrapProducedGarbage)?;
    let params = KdfParams {
        memory_kib: u32_at(SALT_LEN),
        iterations: u32_at(SALT_LEN + 4),
        lanes: u32_at(SALT_LEN + 8),
    };
    Ok(PinLayer {
        salt,
        params,
        nonce: &blob[SALT_LEN + 12..PIN_HEADER_LEN],
        ciphertext: &blob[PIN_HEADER_LEN..],
    })
}

/// How a stored device slot was wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapScheme {
    /// Keystore key only. The vault opens without user interaction.
    Keystore,
    /// Keystore key over a PIN-derived KEK. Both are required (step 4).
    KeystoreAndPin,
}

impl WrapScheme {
    /// The string written to `meta`. Part of the on-disk format: changing one
    /// of these makes an existing slot unreadable.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keystore => "keystore-v1",
            Self::KeystoreAndPin => "keystore-pin-v1",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "keystore-v1" => Some(Self::Keystore),
            "keystore-pin-v1" => Some(Self::KeystoreAndPin),
            _ => None,
        }
    }

    /// Whether opening this slot needs a PIN from the user.
    pub fn needs_pin(self) -> bool {
        matches!(self, Self::KeystoreAndPin)
    }
}

impl fmt::Display for WrapScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What this device needs to do before the vault can be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotState {
    /// No slot exists. First run: generate a vault key and wrap it.
    Absent,
    /// A slot exists and can be opened without a PIN.
    Present,
    /// A slot exists and needs the user's PIN as well as the keystore key.
    PresentNeedsPin,
}

/// Why a device slot operation failed.
#[derive(Debug)]
pub enum DeviceSlotError {
    Store(StoreError),
    Crypto(CryptoError),
    /// The stored scheme is not one this build understands, which means the
    /// vault was written by a newer release.
    UnknownScheme {
        found: String,
    },
    /// The platform returned key material that is not a vault key.
    UnwrapProducedGarbage,
    /// The PIN was wrong. Indistinguishable from a damaged slot by design:
    /// the AEAD tag is the only check, and it does not say which.
    WrongPin,
    /// This slot needs a PIN and none was supplied, or the reverse.
    PinMismatch {
        expected: bool,
    },
    Pin(PinError),
}

impl fmt::Display for DeviceSlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(inner) => write!(f, "{inner}"),
            Self::Crypto(inner) => write!(f, "{inner}"),
            Self::UnknownScheme { found } => write!(
                f,
                "This vault was protected by a newer version of the application \
                 ('{found}'). Update to open it."
            ),
            Self::UnwrapProducedGarbage => write!(
                f,
                "This device's key could not be unwrapped. If you restored this \
                 application from a backup, the key it needs did not come with it."
            ),
            Self::WrongPin => f.write_str("That PIN is not correct."),
            Self::PinMismatch { expected: true } => f.write_str("This vault needs a PIN to open."),
            Self::PinMismatch { expected: false } => f.write_str("This vault does not use a PIN."),
            Self::Pin(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for DeviceSlotError {}

impl From<StoreError> for DeviceSlotError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<CryptoError> for DeviceSlotError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<PinError> for DeviceSlotError {
    fn from(value: PinError) -> Self {
        Self::Pin(value)
    }
}

type Result<T> = core::result::Result<T, DeviceSlotError>;

/// A freshly generated vault key, on its way out to be wrapped.
///
/// This type exists to make the boundary crossing legible. Holding one means
/// raw key material is about to leave Rust; it should be handed to the
/// platform wrap call and dropped in the same breath.
pub struct SetupRequest {
    key: VaultKey,
    /// What the platform should wrap: the bare vault key, or the PIN layer
    /// around it. The scheme says which.
    to_wrap: Zeroizing<Vec<u8>>,
    scheme: WrapScheme,
}

impl SetupRequest {
    /// The bytes for the platform to wrap.
    ///
    /// With a PIN this is already ciphertext, so the platform is wrapping a
    /// wrapped key. Without one it is the vault key itself.
    pub fn key_to_wrap(&self) -> &[u8] {
        &self.to_wrap
    }

    pub fn scheme(&self) -> WrapScheme {
        self.scheme
    }

    /// Records the wrapped result and returns the key for immediate use.
    ///
    /// The slot is written before the key is handed back, so a crash between
    /// the two leaves a device that can be opened rather than a vault whose
    /// key was never stored.
    pub fn complete(
        self,
        meta: &mut MetaStore,
        wrapped: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<VaultKey> {
        meta.set_device_slot(&WrappedVaultKey {
            wrapped,
            nonce,
            scheme: self.scheme.as_str().to_string(),
        })?;
        meta.clear_failed_unlocks()?;
        Ok(self.key)
    }
}

/// Redacted rather than derived. This type holds the vault key and, with a
/// PIN, the sealed blob around it; a derived `Debug` would print both the
/// moment anything logged or panicked on it (section 9.4).
impl fmt::Debug for SetupRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SetupRequest({}, <redacted>)", self.scheme)
    }
}

/// The stored slot, on its way out to be unwrapped.
pub struct OpenRequest {
    slot: WrappedVaultKey,
    scheme: WrapScheme,
}

impl OpenRequest {
    pub fn wrapped_key(&self) -> &[u8] {
        &self.slot.wrapped
    }

    pub fn nonce(&self) -> &[u8] {
        &self.slot.nonce
    }

    pub fn scheme(&self) -> WrapScheme {
        self.scheme
    }

    /// Adopts the key the platform produced, for a slot with no PIN.
    ///
    /// A wrong length here means the platform handed back something that is
    /// not a vault key — a failed unwrap that was not reported as one, for
    /// instance — and that must be an error rather than a key of the wrong
    /// size reaching the cipher.
    pub fn complete(self, unwrapped: &[u8]) -> Result<VaultKey> {
        if self.scheme.needs_pin() {
            return Err(DeviceSlotError::PinMismatch { expected: true });
        }
        VaultKey::from_slice(unwrapped).map_err(|_| DeviceSlotError::UnwrapProducedGarbage)
    }

    /// Undoes the PIN layer that sits inside what the platform just unwrapped.
    ///
    /// The salt and the cost parameters come out of the blob rather than from
    /// `meta`, so a slot written under different parameters still opens.
    pub fn complete_with_pin(self, unwrapped: &[u8], pin: &str) -> Result<VaultKey> {
        if !self.scheme.needs_pin() {
            return Err(DeviceSlotError::PinMismatch { expected: false });
        }

        let layer = decode_pin_blob(unwrapped)?;
        let kek = pin::derive_kek(pin, &layer.salt, layer.params)?;

        let opened = XChaChaCipher::new(&pin::kek_as_key(&kek))
            .open(PIN_SLOT_ID, PIN_SLOT_VERSION, layer.ciphertext, layer.nonce)
            // The tag is the only check there is, and it cannot distinguish a
            // wrong PIN from a damaged slot. Reported as a wrong PIN because
            // that is overwhelmingly what it is, and because saying "damaged"
            // would send a user to restore a backup they do not need.
            .map_err(|_| DeviceSlotError::WrongPin)?;

        VaultKey::from_slice(&opened).map_err(|_| DeviceSlotError::UnwrapProducedGarbage)
    }
}

/// Reads what state this device's slot is in.
pub fn state(meta: &MetaStore) -> Result<SlotState> {
    let Some(slot) = meta.device_slot()? else {
        return Ok(SlotState::Absent);
    };
    let scheme = WrapScheme::parse(&slot.scheme).ok_or_else(|| DeviceSlotError::UnknownScheme {
        found: slot.scheme.clone(),
    })?;

    Ok(if scheme.needs_pin() {
        SlotState::PresentNeedsPin
    } else {
        SlotState::Present
    })
}

/// Begins first-run setup: generates the vault key that this device will use
/// for the rest of its life (section 9.2.4 step 1).
///
/// Generated before the first entry exists, so no entry is ever written under
/// a different key and no re-encryption is ever needed — including when the
/// user later adds a sync account, which adds slots around this same key.
pub fn begin_setup() -> Result<SetupRequest> {
    let key = VaultKey::generate()?;
    let to_wrap = Zeroizing::new(key.expose().to_vec());
    Ok(SetupRequest {
        key,
        to_wrap,
        scheme: WrapScheme::Keystore,
    })
}

/// First-run setup with a PIN (section 9.2.4 step 4).
///
/// The vault key is sealed under the PIN first; the platform then wraps that.
/// Both are needed to get back to the key, and the keystore is the outer of
/// the two so that no PIN guess can be made off the device.
pub fn begin_setup_with_pin(pin: &str) -> Result<SetupRequest> {
    pin::validate(pin)?;
    seal_under_pin(VaultKey::generate()?, pin)
}

/// Puts an existing vault key behind a PIN, keeping the key itself.
///
/// Used when the user turns the lock on after the fact. The key must not
/// change: every record is already encrypted under it.
pub fn rewrap_with_pin(key: VaultKey, pin: &str) -> Result<SetupRequest> {
    pin::validate(pin)?;
    seal_under_pin(key, pin)
}

/// Drops the PIN layer, keeping the same vault key.
pub fn rewrap_without_pin(key: VaultKey) -> Result<SetupRequest> {
    let to_wrap = Zeroizing::new(key.expose().to_vec());
    Ok(SetupRequest {
        key,
        to_wrap,
        scheme: WrapScheme::Keystore,
    })
}

fn seal_under_pin(key: VaultKey, pin: &str) -> Result<SetupRequest> {
    let salt = pin::generate_salt()?;
    let params = KdfParams::default();
    let kek = pin::derive_kek(pin, &salt, params)?;

    let sealed = XChaChaCipher::new(&pin::kek_as_key(&kek))
        .seal(PIN_SLOT_ID, PIN_SLOT_VERSION, key.expose())
        .map_err(|_| DeviceSlotError::UnwrapProducedGarbage)?;

    let to_wrap = encode_pin_blob(&salt, params, &sealed.nonce, &sealed.ciphertext);
    Ok(SetupRequest {
        key,
        to_wrap,
        scheme: WrapScheme::KeystoreAndPin,
    })
}

/// Begins an unlock: reads the stored slot for the platform to unwrap.
pub fn begin_open(meta: &MetaStore) -> Result<Option<OpenRequest>> {
    let Some(slot) = meta.device_slot()? else {
        return Ok(None);
    };
    let scheme = WrapScheme::parse(&slot.scheme).ok_or_else(|| DeviceSlotError::UnknownScheme {
        found: slot.scheme.clone(),
    })?;

    Ok(Some(OpenRequest { slot, scheme }))
}

/// Destroys the device slot (section 9.2.4, **Wipe this device**).
///
/// The entries are not touched here and do not need to be: without the slot
/// there is no key, and without the key the records are unreadable. The caller
/// should still delete them, because ciphertext left on disk is ciphertext an
/// attacker can keep.
pub fn wipe(meta: &mut MetaStore) -> Result<()> {
    meta.clear_device_slot()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> MetaStore {
        MetaStore::open_in_memory().unwrap()
    }

    /// Stands in for the platform keystore. The real one is non-exportable and
    /// lives in Android Keystore; this one exists so the state machine around
    /// it can be tested without a device.
    fn fake_wrap(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let nonce = vec![0xAB; 12];
        let wrapped = key.iter().map(|b| b ^ 0x5A).collect();
        (wrapped, nonce)
    }

    fn fake_unwrap(wrapped: &[u8]) -> Vec<u8> {
        wrapped.iter().map(|b| b ^ 0x5A).collect()
    }

    #[test]
    fn a_new_device_has_no_slot() {
        assert_eq!(state(&meta()).unwrap(), SlotState::Absent);
        assert!(begin_open(&meta()).unwrap().is_none());
    }

    #[test]
    fn setup_stores_a_slot_and_yields_the_key() {
        let mut meta = meta();

        let request = begin_setup().unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        let key = request.complete(&mut meta, wrapped, nonce).unwrap();

        assert_eq!(state(&meta).unwrap(), SlotState::Present);

        // The stored slot must round trip back to the same key.
        let open = begin_open(&meta).unwrap().unwrap();
        assert_eq!(open.scheme(), WrapScheme::Keystore);
        let unwrapped = fake_unwrap(open.wrapped_key());
        let reopened = open.complete(&unwrapped).unwrap();

        assert_eq!(reopened, key, "the same vault key must come back");
    }

    /// Nothing readable may sit next to the wrapped key. The whole point of
    /// the device slot is that `meta.db` is unencrypted.
    #[test]
    fn the_stored_slot_is_not_the_vault_key() {
        let mut meta = meta();
        let request = begin_setup().unwrap();
        let plaintext = request.key_to_wrap().to_vec();
        let (wrapped, nonce) = fake_wrap(&plaintext);
        request.complete(&mut meta, wrapped, nonce).unwrap();

        let stored = meta.device_slot().unwrap().unwrap();
        assert_ne!(
            stored.wrapped, plaintext,
            "the vault key must never be stored as it is"
        );
    }

    #[test]
    fn a_pin_scheme_is_reported_as_needing_a_pin() {
        let mut meta = meta();
        let request = begin_setup_with_pin("284915").unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        request.complete(&mut meta, wrapped, nonce).unwrap();

        assert_eq!(state(&meta).unwrap(), SlotState::PresentNeedsPin);
        assert!(
            begin_open(&meta).unwrap().unwrap().scheme().needs_pin(),
            "the caller must know to ask for the PIN"
        );
    }

    #[test]
    fn a_scheme_from_a_newer_release_is_refused_by_name() {
        let mut meta = meta();
        meta.set_device_slot(&WrappedVaultKey {
            wrapped: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            scheme: "keystore-pin-v9".to_string(),
        })
        .unwrap();

        let error = state(&meta).unwrap_err();
        assert!(matches!(error, DeviceSlotError::UnknownScheme { .. }));
        assert!(error.to_string().contains("keystore-pin-v9"));
    }

    /// A failed platform unwrap that returns something short must not become a
    /// short key handed to the cipher.
    #[test]
    fn an_unwrap_of_the_wrong_length_is_refused() {
        let mut meta = meta();
        let request = begin_setup().unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        request.complete(&mut meta, wrapped, nonce).unwrap();

        let open = begin_open(&meta).unwrap().unwrap();
        assert!(matches!(
            open.complete(&[0u8; 16]).unwrap_err(),
            DeviceSlotError::UnwrapProducedGarbage
        ));
    }

    #[test]
    fn a_wipe_leaves_the_device_unable_to_open_its_vault() {
        let mut meta = meta();
        let request = begin_setup().unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        request.complete(&mut meta, wrapped, nonce).unwrap();
        assert_eq!(state(&meta).unwrap(), SlotState::Present);

        wipe(&mut meta).unwrap();

        assert_eq!(state(&meta).unwrap(), SlotState::Absent);
        assert!(begin_open(&meta).unwrap().is_none());
    }

    /// A half-written slot must be reported, not silently treated as absent —
    /// treating it as absent would generate a second vault key and orphan
    /// every existing entry.
    #[test]
    fn a_slot_missing_its_nonce_is_an_error_not_an_absence() {
        let meta = meta();
        meta.set("device_slot.wrapped_key", &[1, 2, 3]).unwrap();

        assert!(matches!(
            state(&meta).unwrap_err(),
            DeviceSlotError::Store(StoreError::CorruptDeviceSlot { .. })
        ));
    }

    /// The whole point of section 9.2.4 step 4: neither factor alone opens the
    /// vault.
    #[test]
    fn both_the_keystore_and_the_pin_are_required() {
        let mut meta = meta();

        let request = begin_setup_with_pin("284915").unwrap();
        assert_eq!(request.scheme(), WrapScheme::KeystoreAndPin);

        // What the platform is handed is already ciphertext, not the key.
        let inner = request.key_to_wrap().to_vec();
        let (wrapped, nonce) = fake_wrap(&inner);
        let key = request.complete(&mut meta, wrapped, nonce).unwrap();

        // The keystore alone gets only as far as the PIN layer.
        let open = begin_open(&meta).unwrap().unwrap();
        let unwrapped = fake_unwrap(open.wrapped_key());
        assert!(
            matches!(
                open.complete(&unwrapped).unwrap_err(),
                DeviceSlotError::PinMismatch { expected: true }
            ),
            "a PIN slot must not open without one"
        );

        // The right PIN gets the rest of the way.
        let open = begin_open(&meta).unwrap().unwrap();
        let unwrapped = fake_unwrap(open.wrapped_key());
        assert_eq!(open.complete_with_pin(&unwrapped, "284915").unwrap(), key);

        // A wrong one does not.
        let open = begin_open(&meta).unwrap().unwrap();
        let unwrapped = fake_unwrap(open.wrapped_key());
        assert!(matches!(
            open.complete_with_pin(&unwrapped, "999888").unwrap_err(),
            DeviceSlotError::WrongPin
        ));
    }

    /// The stored blob must not contain the vault key, even before the
    /// keystore wraps it.
    #[test]
    fn the_pin_layer_already_hides_the_key() {
        let key_bytes;
        let inner;
        {
            let request = begin_setup_with_pin("284915").unwrap();
            inner = request.key_to_wrap().to_vec();
            let mut meta = meta();
            let (wrapped, nonce) = fake_wrap(&inner);
            key_bytes = request
                .complete(&mut meta, wrapped, nonce)
                .unwrap()
                .expose()
                .to_vec();
        }

        assert!(
            !inner.windows(32).any(|w| w == &key_bytes[..]),
            "the vault key appears inside the PIN layer"
        );
    }

    /// Turning the lock on later must not change the vault key: every record
    /// is already encrypted under it.
    #[test]
    fn adding_a_pin_keeps_the_same_vault_key() {
        let mut meta = meta();

        let request = begin_setup().unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        let original = request.complete(&mut meta, wrapped, nonce).unwrap();

        let request = rewrap_with_pin(original.clone(), "284915").unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        let after = request.complete(&mut meta, wrapped, nonce).unwrap();

        assert_eq!(after, original, "the vault key must survive the change");
        assert_eq!(state(&meta).unwrap(), SlotState::PresentNeedsPin);

        // And it opens with the PIN.
        let open = begin_open(&meta).unwrap().unwrap();
        let unwrapped = fake_unwrap(open.wrapped_key());
        assert_eq!(
            open.complete_with_pin(&unwrapped, "284915").unwrap(),
            original
        );
    }

    #[test]
    fn removing_the_pin_keeps_the_same_vault_key() {
        let mut meta = meta();

        let request = begin_setup_with_pin("284915").unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        let original = request.complete(&mut meta, wrapped, nonce).unwrap();

        let request = rewrap_without_pin(original.clone()).unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        let after = request.complete(&mut meta, wrapped, nonce).unwrap();

        assert_eq!(after, original);
        assert_eq!(state(&meta).unwrap(), SlotState::Present);
    }

    #[test]
    fn a_pin_that_fails_fr31_never_reaches_the_kdf() {
        assert!(matches!(
            begin_setup_with_pin("12345"),
            Err(DeviceSlotError::Pin(_))
        ));
        assert!(matches!(
            begin_setup_with_pin("123456"),
            Err(DeviceSlotError::Pin(_))
        ));
    }

    /// Section 9.4 again: the request carries the vault key, so its Debug
    /// output must not.
    #[test]
    fn a_setup_request_does_not_print_its_key() {
        let request = begin_setup().unwrap();
        let rendered = format!("{request:?}");

        // Use an exact allowlist. Comparing individual random bytes with the
        // decimal digits in normal text makes the test fail by chance.
        assert_eq!(rendered, "SetupRequest(keystore-v1, <redacted>)");
    }

    /// FR-35 counts consecutive failures, so a success must reset it.
    #[test]
    fn the_failure_counter_counts_consecutive_failures() {
        let mut meta = meta();
        assert_eq!(meta.failed_unlocks().unwrap(), 0);

        assert_eq!(meta.record_failed_unlock().unwrap(), 1);
        assert_eq!(meta.record_failed_unlock().unwrap(), 2);

        // Completing a setup counts as a success.
        let request = begin_setup().unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        request.complete(&mut meta, wrapped, nonce).unwrap();

        assert_eq!(meta.failed_unlocks().unwrap(), 0);
    }
}
