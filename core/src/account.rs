//! The password and recovery slots (PRD sections 9.2.1, 9.2.3, 16.2).
//!
//! # The vault key is not generated here
//!
//! Section 9.2.4: "When the user later creates a sync account, keep the same
//! vault key. Add a password slot or a passkey slot and a recovery slot around
//! it. Do not re-encrypt the entries."
//!
//! This is the single most important rule in this module. Every entry on the
//! device is already encrypted under the device slot's vault key. Generating a
//! fresh key at sign-up would leave every one of them unreadable, and the
//! failure would be silent until the user looked for a code. So
//! [`create_account`] takes the existing key as an argument; there is no code
//! path here that makes one.
//!
//! # Nothing here depends on a server
//!
//! The server arrives in stage S4. Until then the slots are built and stored
//! locally, ready to upload. The authentication key is *derived* — by
//! [`derive_auth_key`], on demand — and never stored, because storing it would
//! mean holding something whose only purpose is to be sent somewhere that does
//! not exist yet.
//!
//! # The salt
//!
//! Section 9.2.1: "The client generates that salt at sign-up. Do not derive
//! the salt from the email address. A salt shared across services lets one
//! precomputed table attack every account that uses the same address." So it
//! is 128 random bits, generated here, stored with the slot, and uploaded at
//! S4 for `prelogin` to return.

use core::fmt;

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, KEY_LEN, VaultKey, XChaChaCipher};
use crate::pin::{self, KdfParams, PinError, SALT_LEN};
use crate::store::{MetaStore, StoreError};
use crate::vault::RecordCipher;

/// Associated data for the slot wraps, so a slot ciphertext cannot be replayed
/// as a record, nor one slot's as another's.
const PASSWORD_SLOT_ID: &str = "authcore/password-slot";
const RECOVERY_SLOT_ID: &str = "authcore/recovery-slot";
const SLOT_VERSION: u32 = 1;

/// HKDF labels splitting the master key (section 9.2.1 step 4).
const INFO_AUTH: &[u8] = b"authcore/v1/auth";
const INFO_KEK: &[u8] = b"authcore/v1/kek";

/// `meta` keys. These are wrapped keys and public parameters, so the
/// unencrypted metadata file is the right place: nothing here opens anything
/// without the password or the recovery phrase.
const META_EMAIL: &str = "account.email";
const META_PW_SALT: &str = "account.password.salt";
const META_PW_PARAMS: &str = "account.password.params";
const META_PW_WRAPPED: &str = "account.password.wrapped";
const META_PW_NONCE: &str = "account.password.nonce";
const META_RECOVERY_WRAPPED: &str = "account.recovery.wrapped";
const META_RECOVERY_NONCE: &str = "account.recovery.nonce";

/// Words in the recovery phrase. 256 bits plus its checksum is 24 words.
pub const RECOVERY_WORDS: usize = 24;
/// Section 9.2.3 step 4: "Require the user to confirm 3 random words."
pub const WORDS_TO_CONFIRM: usize = 3;

/// Why an account operation failed.
#[derive(Debug)]
pub enum AccountError {
    Store(StoreError),
    Crypto(CryptoError),
    Kdf(PinError),
    /// Section 16.4 and decision 6: every synced account needs an email
    /// address. Recovery, device approval, and support all key on it.
    EmailRequired,
    /// The password did not open the slot. Indistinguishable from a damaged
    /// slot by design — the AEAD tag is the only check.
    WrongPassword,
    /// The recovery phrase was not 24 valid BIP-39 words, or its checksum
    /// failed. Caught before any key derivation.
    BadRecoveryPhrase {
        detail: String,
    },
    /// The recovery phrase parsed but does not open this vault.
    WrongRecoveryKey,
    /// No account has been created on this device.
    NoAccount,
    /// A stored slot is present but incomplete.
    CorruptSlot {
        detail: String,
    },
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(inner) => write!(f, "{inner}"),
            Self::Crypto(inner) => write!(f, "{inner}"),
            Self::Kdf(inner) => write!(f, "{inner}"),
            Self::EmailRequired => f.write_str(
                "An email address is required. Without one there is no way to \
                 recover this account if you lose your devices.",
            ),
            Self::WrongPassword => f.write_str("That password is not correct."),
            Self::BadRecoveryPhrase { detail } => {
                write!(f, "That recovery phrase is not valid: {detail}")
            }
            Self::WrongRecoveryKey => f.write_str(
                "That recovery phrase is a valid phrase, but it does not belong \
                 to this vault.",
            ),
            Self::NoAccount => f.write_str("No account has been created on this device."),
            Self::CorruptSlot { detail } => {
                write!(f, "A stored key record is damaged: {detail}")
            }
        }
    }
}

impl std::error::Error for AccountError {}

impl From<StoreError> for AccountError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<CryptoError> for AccountError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<PinError> for AccountError {
    fn from(value: PinError) -> Self {
        Self::Kdf(value)
    }
}

type Result<T> = core::result::Result<T, AccountError>;

/// The 24 words shown once at sign-up (section 9.2.3 step 3).
///
/// Wiped on drop, and redacted in `Debug`: these words unwrap the vault key,
/// so section 9.4's rule about key material at any log level covers them.
pub struct RecoveryPhrase {
    words: Zeroizing<String>,
}

impl RecoveryPhrase {
    pub fn as_str(&self) -> &str {
        &self.words
    }

    pub fn words(&self) -> Vec<&str> {
        self.words.split_whitespace().collect()
    }

    /// Zero-based indices of the words the user must confirm, chosen at
    /// random (section 9.2.3 step 4).
    ///
    /// Random rather than fixed, so that confirming becomes a reason to read
    /// the whole phrase rather than three known positions.
    pub fn indices_to_confirm(&self) -> Result<Vec<usize>> {
        let mut chosen: Vec<usize> = Vec::with_capacity(WORDS_TO_CONFIRM);
        while chosen.len() < WORDS_TO_CONFIRM {
            let mut byte = [0u8; 1];
            getrandom::fill(&mut byte).map_err(|error| {
                AccountError::Crypto(CryptoError::NoRandomness {
                    reason: error.to_string(),
                })
            })?;
            let index = usize::from(byte[0]) % RECOVERY_WORDS;
            if !chosen.contains(&index) {
                chosen.push(index);
            }
        }
        chosen.sort_unstable();
        Ok(chosen)
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryPhrase(<redacted, {RECOVERY_WORDS} words>)")
    }
}

/// The stored password slot. Everything here is public: a salt, cost
/// parameters, and a wrapped key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSlot {
    pub salt: [u8; SALT_LEN],
    pub params: KdfParams,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// The stored recovery slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySlot {
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// What this device knows about the sync account, before any server exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub email: String,
    pub password_slot: Option<PasswordSlot>,
    /// Mandatory on a synced account (section 9.2, and 9.2.3 for passkeys).
    pub recovery_slot: RecoverySlot,
}

/// Creates the account slots around an **existing** vault key.
///
/// `vault_key` must be the key the device slot already holds. Passing a fresh
/// one would orphan every entry — see the module documentation.
///
/// Returns the recovery phrase, which is shown once and never stored.
pub fn create_account(
    meta: &MetaStore,
    email: &str,
    password: &str,
    vault_key: &VaultKey,
) -> Result<(Account, RecoveryPhrase)> {
    let email = email.trim();
    if email.is_empty() {
        return Err(AccountError::EmailRequired);
    }

    let password_slot = build_password_slot(password, vault_key)?;
    let (recovery_slot, phrase) = build_recovery_slot(vault_key)?;

    let account = Account {
        email: email.to_string(),
        password_slot: Some(password_slot),
        recovery_slot,
    };
    save(meta, &account)?;

    Ok((account, phrase))
}

/// Derives the password slot's KEK and wraps the vault key (section 9.2.1).
fn build_password_slot(password: &str, vault_key: &VaultKey) -> Result<PasswordSlot> {
    let salt = pin::generate_salt()?;
    let params = KdfParams::default();

    let master = pin::derive_kek(password, &salt, params)?;
    let kek = expand(&master, INFO_KEK);

    let sealed = XChaChaCipher::new(&pin::kek_as_key(&kek))
        .seal(PASSWORD_SLOT_ID, SLOT_VERSION, vault_key.expose())
        .map_err(|_| AccountError::CorruptSlot {
            detail: "the password slot could not be sealed".to_string(),
        })?;

    Ok(PasswordSlot {
        salt,
        params,
        wrapped_key: sealed.ciphertext,
        nonce: sealed.nonce,
    })
}

/// Generates the recovery key and wraps the vault key with it (section 9.2.3).
fn build_recovery_slot(vault_key: &VaultKey) -> Result<(RecoverySlot, RecoveryPhrase)> {
    let recovery_key = VaultKey::generate()?;

    let sealed = XChaChaCipher::new(&recovery_key)
        .seal(RECOVERY_SLOT_ID, SLOT_VERSION, vault_key.expose())
        .map_err(|_| AccountError::CorruptSlot {
            detail: "the recovery slot could not be sealed".to_string(),
        })?;

    // 256 bits of entropy is 24 words in BIP-39, which is what section 9.2.3
    // specifies. The word list is the standard English one, so the phrase can
    // be written down and read back with the usual tools.
    let mnemonic =
        Mnemonic::from_entropy_in(Language::English, recovery_key.expose()).map_err(|error| {
            AccountError::CorruptSlot {
                detail: format!("the recovery phrase could not be built: {error}"),
            }
        })?;

    Ok((
        RecoverySlot {
            wrapped_key: sealed.ciphertext,
            nonce: sealed.nonce,
        },
        RecoveryPhrase {
            words: Zeroizing::new(mnemonic.to_string()),
        },
    ))
}

/// The authentication key that stage S4 will send to the server.
///
/// Derived on demand and never stored. The KEK from the same master key never
/// leaves the device; only this half is ever transmitted, and only once a
/// server exists.
pub fn derive_auth_key(password: &str, slot: &PasswordSlot) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let master = pin::derive_kek(password, &slot.salt, slot.params)?;
    Ok(expand(&master, INFO_AUTH))
}

/// Unwraps the vault key with the account password.
pub fn unlock_with_password(meta: &MetaStore, password: &str) -> Result<VaultKey> {
    let account = load(meta)?.ok_or(AccountError::NoAccount)?;
    let slot = account.password_slot.ok_or(AccountError::NoAccount)?;

    let master = pin::derive_kek(password, &slot.salt, slot.params)?;
    let kek = expand(&master, INFO_KEK);

    let opened = XChaChaCipher::new(&pin::kek_as_key(&kek))
        .open(
            PASSWORD_SLOT_ID,
            SLOT_VERSION,
            &slot.wrapped_key,
            &slot.nonce,
        )
        .map_err(|_| AccountError::WrongPassword)?;

    Ok(VaultKey::from_slice(&opened)?)
}

/// Unwraps the vault key with the 24-word recovery phrase (section 16.4).
///
/// The phrase is validated as BIP-39 first, so a typo is reported as a typo
/// rather than as a wrong vault.
pub fn unlock_with_recovery(meta: &MetaStore, phrase: &str) -> Result<VaultKey> {
    let account = load(meta)?.ok_or(AccountError::NoAccount)?;

    let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim()).map_err(|error| {
        AccountError::BadRecoveryPhrase {
            detail: error.to_string(),
        }
    })?;

    let (entropy, len) = mnemonic.to_entropy_array();
    if len != KEY_LEN {
        return Err(AccountError::BadRecoveryPhrase {
            detail: format!(
                "expected {RECOVERY_WORDS} words, not {}",
                mnemonic.word_count()
            ),
        });
    }
    let recovery_key = VaultKey::from_slice(&entropy[..len])?;

    let opened = XChaChaCipher::new(&recovery_key)
        .open(
            RECOVERY_SLOT_ID,
            SLOT_VERSION,
            &account.recovery_slot.wrapped_key,
            &account.recovery_slot.nonce,
        )
        .map_err(|_| AccountError::WrongRecoveryKey)?;

    Ok(VaultKey::from_slice(&opened)?)
}

/// HKDF-SHA-256 over the master key (section 9.2.1 step 4).
fn expand(master: &Zeroizing<[u8; KEY_LEN]>, info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, master.as_slice())
        .expand(info, out.as_mut_slice())
        .expect("32 bytes is far below the HKDF output limit");
    out
}

/// Writes the account and its slots.
pub fn save(meta: &MetaStore, account: &Account) -> Result<()> {
    meta.set(META_EMAIL, account.email.as_bytes())?;

    if let Some(slot) = &account.password_slot {
        meta.set(META_PW_SALT, &slot.salt)?;
        meta.set(META_PW_PARAMS, encode_params(slot.params).as_bytes())?;
        meta.set(META_PW_WRAPPED, &slot.wrapped_key)?;
        meta.set(META_PW_NONCE, &slot.nonce)?;
    }
    meta.set(META_RECOVERY_WRAPPED, &account.recovery_slot.wrapped_key)?;
    meta.set(META_RECOVERY_NONCE, &account.recovery_slot.nonce)?;
    Ok(())
}

/// Reads the account, or `None` on a device with no sync account.
pub fn load(meta: &MetaStore) -> Result<Option<Account>> {
    let Some(email) = meta.get(META_EMAIL)? else {
        return Ok(None);
    };
    let email = String::from_utf8(email).map_err(|_| AccountError::CorruptSlot {
        detail: "the stored email address is not valid text".to_string(),
    })?;

    let recovery_slot = RecoverySlot {
        wrapped_key: required(meta, META_RECOVERY_WRAPPED, "the recovery key")?,
        nonce: required(meta, META_RECOVERY_NONCE, "the recovery nonce")?,
    };

    let password_slot = match meta.get(META_PW_WRAPPED)? {
        None => None,
        Some(wrapped) => {
            let salt_bytes = required(meta, META_PW_SALT, "the password salt")?;
            let salt: [u8; SALT_LEN] =
                salt_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| AccountError::CorruptSlot {
                        detail: format!(
                            "the password salt is {} bytes, not {SALT_LEN}",
                            salt_bytes.len()
                        ),
                    })?;
            Some(PasswordSlot {
                salt,
                params: decode_params(&required(meta, META_PW_PARAMS, "the KDF parameters")?)?,
                wrapped_key: wrapped,
                nonce: required(meta, META_PW_NONCE, "the password nonce")?,
            })
        }
    };

    Ok(Some(Account {
        email,
        password_slot,
        recovery_slot,
    }))
}

fn required(meta: &MetaStore, key: &str, what: &str) -> Result<Vec<u8>> {
    meta.get(key)?.ok_or_else(|| AccountError::CorruptSlot {
        detail: format!("{what} is missing"),
    })
}

fn encode_params(params: KdfParams) -> String {
    format!(
        "{},{},{}",
        params.memory_kib, params.iterations, params.lanes
    )
}

fn decode_params(bytes: &[u8]) -> Result<KdfParams> {
    let text = String::from_utf8_lossy(bytes);
    let parts: Vec<&str> = text.split(',').collect();
    if parts.len() != 3 {
        return Err(AccountError::CorruptSlot {
            detail: format!("the KDF parameters are unreadable: {text:?}"),
        });
    }
    let parse = |value: &str| -> Result<u32> {
        value.trim().parse().map_err(|_| AccountError::CorruptSlot {
            detail: format!("the KDF parameters are unreadable: {text:?}"),
        })
    };
    Ok(KdfParams {
        memory_kib: parse(parts[0])?,
        iterations: parse(parts[1])?,
        lanes: parse(parts[2])?,
    })
}
