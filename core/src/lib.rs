//! authcore — shared core for the authenticator app (PRD stage S1).

pub mod base32;
pub mod entry;
pub mod hlc;
pub mod otp;
pub mod otpauth;
pub mod secret;
pub mod store;

pub use base32::Base32Error;
pub use entry::{OtpEntry, Payload, PayloadError};
pub use hlc::{Hlc, HlcClock};
pub use otp::{Algorithm, OtpError, OtpKind};
pub use otpauth::{OtpAuthError, OtpAuthUri};
pub use secret::SecretString;
pub use store::{Record, Store, StoreError};
