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

use crate::crypto::{CryptoError, VaultKey};
use crate::store::{MetaStore, StoreError, WrappedVaultKey};

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

type Result<T> = core::result::Result<T, DeviceSlotError>;

/// A freshly generated vault key, on its way out to be wrapped.
///
/// This type exists to make the boundary crossing legible. Holding one means
/// raw key material is about to leave Rust; it should be handed to the
/// platform wrap call and dropped in the same breath.
pub struct SetupRequest {
    key: VaultKey,
}

impl SetupRequest {
    /// The bytes for the platform to wrap.
    pub fn key_to_wrap(&self) -> &[u8] {
        self.key.expose()
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
        scheme: WrapScheme,
    ) -> Result<VaultKey> {
        meta.set_device_slot(&WrappedVaultKey {
            wrapped,
            nonce,
            scheme: scheme.as_str().to_string(),
        })?;
        Ok(self.key)
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

    /// Adopts the key the platform produced.
    ///
    /// A wrong length here means the platform handed back something that is
    /// not a vault key — a failed unwrap that was not reported as one, for
    /// instance — and that must be an error rather than a key of the wrong
    /// size reaching the cipher.
    pub fn complete(self, unwrapped: &[u8]) -> Result<VaultKey> {
        VaultKey::from_slice(unwrapped).map_err(|_| DeviceSlotError::UnwrapProducedGarbage)
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
    Ok(SetupRequest {
        key: VaultKey::generate()?,
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
        let key = request
            .complete(&mut meta, wrapped, nonce, WrapScheme::Keystore)
            .unwrap();

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
        request
            .complete(&mut meta, wrapped, nonce, WrapScheme::Keystore)
            .unwrap();

        let stored = meta.device_slot().unwrap().unwrap();
        assert_ne!(
            stored.wrapped, plaintext,
            "the vault key must never be stored as it is"
        );
    }

    #[test]
    fn a_pin_scheme_is_reported_as_needing_a_pin() {
        let mut meta = meta();
        let request = begin_setup().unwrap();
        let (wrapped, nonce) = fake_wrap(request.key_to_wrap());
        request
            .complete(&mut meta, wrapped, nonce, WrapScheme::KeystoreAndPin)
            .unwrap();

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
        request
            .complete(&mut meta, wrapped, nonce, WrapScheme::Keystore)
            .unwrap();

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
        request
            .complete(&mut meta, wrapped, nonce, WrapScheme::Keystore)
            .unwrap();
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
}
