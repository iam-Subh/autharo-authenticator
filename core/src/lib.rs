//! authcore — shared core for the authenticator app (PRD stage S1).

pub mod account;
pub mod base32;
pub mod crypto;
pub mod device_slot;
pub mod entry;
pub mod hlc;
pub mod lock_policy;
pub mod otp;
pub mod otpauth;
pub mod pin;
pub mod reconcile;
pub mod secret;
pub mod store;
pub mod sync;
pub mod vault;

pub use base32::Base32Error;
pub use crypto::{VaultKey, XChaChaCipher};
pub use device_slot::{SlotState, WrapScheme};
pub use entry::{OtpEntry, Payload, PayloadError};
pub use hlc::{Hlc, HlcClock};
pub use otp::{Algorithm, OtpError, OtpKind};
pub use otpauth::{OtpAuthError, OtpAuthUri};
pub use secret::SecretString;
pub use store::{MetaStore, Record, Store, StoreError};
pub use vault::{RecordCipher, Vault, VaultEntry, VaultError};
