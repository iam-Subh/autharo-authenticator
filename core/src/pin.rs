//! The PIN factor of the device slot (PRD sections 9.2.4 and 8.5).
//!
//! Section 9.2.4 step 4: "If the user sets a PIN or a passphrase, derive a
//! second KEK from it with Argon2id and wrap the vault key again. Require both
//! the keystore key and the PIN KEK to unwrap. A PIN alone is short, and a
//! keystore key alone does not survive a stolen unlocked device."
//!
//! # Why the keystore goes on the outside
//!
//! The vault key is wrapped by the PIN first, and that result is wrapped by
//! the keystore key:
//!
//! ```text
//! vault key --wrap(PIN KEK)--> inner --wrap(keystore key)--> stored in meta.db
//! ```
//!
//! The order is what makes an offline attack impossible rather than merely
//! expensive. With the keystore on the outside, someone who copies `meta.db`
//! off the device holds ciphertext they cannot even begin on: they must first
//! get past a non-exportable hardware key, which confines every PIN guess to
//! the device itself, where the keystore's own rate limiting applies. Reverse
//! the order and the PIN-wrapped blob would be exposed the moment the file was
//! read, and a six digit PIN is a million guesses — hours, at any KDF cost
//! that is tolerable to a user opening their authenticator.
//!
//! # There is no separate verifier
//!
//! OFF-03 asks for the PIN to be checked offline. Nothing extra is stored for
//! that: a wrong PIN produces a wrong KEK, and Poly1305 rejects the unwrap. A
//! stored hash of the PIN would be a second, weaker thing to attack, and it
//! would tell an attacker when they had guessed right without their having to
//! get past the keystore first.

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::{KEY_LEN, VaultKey};

/// FR-31: "a PIN of 6 or more digits, or ... a passphrase".
pub const MIN_PIN_DIGITS: usize = 6;
/// A passphrase is held to the same total length, counted in characters.
pub const MIN_PASSPHRASE_LEN: usize = 6;

/// Salt length. 128 bits, matching the account salt in section 9.2.1.
pub const SALT_LEN: usize = 16;

/// Argon2id cost, from section 9.2.1's mobile figures: 64 MiB, 3 iterations,
/// 4 lanes.
///
/// Section 9.2.1 sets these for the account password. They are applied to the
/// PIN as well, and the reasoning is stronger here, not weaker: a six digit
/// PIN holds about twenty bits, so the KDF is doing most of the work. Stored
/// alongside the slot so that raising them later does not orphan an existing
/// vault.
pub const MEMORY_KIB: u32 = 64 * 1024;
pub const ITERATIONS: u32 = 3;
pub const LANES: u32 = 4;

/// Upper bounds for parameters read from a server, backup, or metadata file.
/// These bounds prevent an untrusted value from requesting unbounded memory
/// or CPU work before Argon2 can reject it.
pub const MAX_MEMORY_KIB: u32 = 256 * 1024;
pub const MAX_ITERATIONS: u32 = 10;
pub const MAX_LANES: u32 = 8;

/// The cost parameters a particular slot was created with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: MEMORY_KIB,
            iterations: ITERATIONS,
            lanes: LANES,
        }
    }
}

impl KdfParams {
    pub fn validate(self) -> Result<(), PinError> {
        if self.memory_kib == 0
            || self.memory_kib > MAX_MEMORY_KIB
            || self.iterations == 0
            || self.iterations > MAX_ITERATIONS
            || self.lanes == 0
            || self.lanes > MAX_LANES
        {
            return Err(PinError::KdfParametersOutOfRange);
        }
        Ok(())
    }
}

/// Why a PIN could not be accepted or used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// FR-31's minimum. Reported with what was supplied so the interface can
    /// say how much more is needed.
    TooShort { found: usize, minimum: usize },
    /// A PIN that is all one digit, or a straight run. Refused because these
    /// are the first guesses anyone makes.
    TooPredictable,
    /// Parameters from external data exceed the application's resource
    /// limits or contain zero.
    KdfParametersOutOfRange,
    /// The KDF could not run, which on a phone means it could not get its
    /// 64 MiB.
    KdfFailed { reason: String },
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { found, minimum } => write!(
                f,
                "A PIN needs at least {minimum} digits. This one has {found}."
            ),
            Self::TooPredictable => f.write_str(
                "Choose a less predictable PIN. Repeated digits and runs like \
                 123456 are the first ones an attacker tries.",
            ),
            Self::KdfParametersOutOfRange => {
                f.write_str("The key derivation parameters are outside the supported range.")
            }
            Self::KdfFailed { reason } => {
                write!(f, "This device could not prepare the PIN for use: {reason}")
            }
        }
    }
}

impl std::error::Error for PinError {}

/// Checks a PIN or passphrase against FR-31 before it is ever used.
///
/// Validation happens here rather than in the interface so that every entry
/// point — first setup, a change, a platform that has not been written yet —
/// gets the same answer.
pub fn validate(pin: &str) -> Result<(), PinError> {
    let characters: Vec<char> = pin.chars().collect();
    let all_digits = !characters.is_empty() && characters.iter().all(|c| c.is_ascii_digit());

    let minimum = if all_digits {
        MIN_PIN_DIGITS
    } else {
        MIN_PASSPHRASE_LEN
    };
    if characters.len() < minimum {
        return Err(PinError::TooShort {
            found: characters.len(),
            minimum,
        });
    }

    // Only applied to all-digit PINs. A passphrase with a run in it is not the
    // same kind of guess, and refusing one would be an unhelpful surprise.
    if all_digits && (is_one_repeated_digit(&characters) || is_a_run(&characters)) {
        return Err(PinError::TooPredictable);
    }

    Ok(())
}

fn is_one_repeated_digit(characters: &[char]) -> bool {
    characters.windows(2).all(|pair| pair[0] == pair[1])
}

/// A straight run in either direction: 123456 and 654321 alike.
fn is_a_run(characters: &[char]) -> bool {
    let step = |a: char, b: char| b as i32 - a as i32;
    let first = step(characters[0], characters[1]);
    (first == 1 || first == -1)
        && characters
            .windows(2)
            .all(|pair| step(pair[0], pair[1]) == first)
}

/// Derives the PIN's key encryption key.
///
/// The KEK never leaves memory and is never stored. What is stored is the salt
/// and the parameters, both of which are public.
pub fn derive_kek(
    pin: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, PinError> {
    params.validate()?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.lanes,
            Some(KEY_LEN),
        )
        .map_err(|error| PinError::KdfFailed {
            reason: error.to_string(),
        })?,
    );

    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(pin.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|error| PinError::KdfFailed {
            reason: error.to_string(),
        })?;

    Ok(kek)
}

/// A KEK, in the form the wrapping functions take.
///
/// Wrapping reuses `XChaChaCipher` through `VaultKey`, so that the PIN layer
/// and the record layer share one audited construction rather than growing a
/// second one.
pub fn kek_as_key(kek: &Zeroizing<[u8; KEY_LEN]>) -> VaultKey {
    VaultKey::from_slice(kek.as_slice()).expect("a KEK is KEY_LEN bytes by construction")
}

/// Generates a salt for a new PIN slot.
pub fn generate_salt() -> Result<[u8; SALT_LEN], PinError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|error| PinError::KdfFailed {
        reason: format!("no secure random numbers are available: {error}"),
    })?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters. The real cost is asserted separately; using 64 MiB in
    /// every test would make the suite unusable.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
        }
    }

    #[test]
    fn a_short_pin_is_refused_with_the_numbers_in_it() {
        assert_eq!(
            validate("12345").unwrap_err(),
            PinError::TooShort {
                found: 5,
                minimum: 6
            }
        );
        assert!(validate("13579").is_err());
        assert!(validate("284915").is_ok());
    }

    #[test]
    fn predictable_pins_are_refused() {
        for pin in ["000000", "111111", "123456", "654321", "12345678"] {
            assert_eq!(
                validate(pin).unwrap_err(),
                PinError::TooPredictable,
                "{pin} should be refused"
            );
        }
    }

    /// The run and repetition rules must not reach a passphrase, where they
    /// would refuse reasonable input.
    #[test]
    fn a_passphrase_is_held_to_length_only() {
        assert!(validate("correct horse battery staple").is_ok());
        assert!(
            validate("abcdef").is_ok(),
            "a run of letters is not a PIN run"
        );
        assert!(validate("abc").is_err(), "but it is still too short");
    }

    #[test]
    fn the_same_pin_and_salt_give_the_same_key() {
        let salt = [9u8; SALT_LEN];
        let first = derive_kek("284915", &salt, fast()).unwrap();
        let second = derive_kek("284915", &salt, fast()).unwrap();

        assert_eq!(first.as_slice(), second.as_slice());
        assert_ne!(first.as_slice(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn a_different_pin_or_salt_gives_a_different_key() {
        let salt = [9u8; SALT_LEN];
        let base = derive_kek("284915", &salt, fast()).unwrap();

        assert_ne!(
            derive_kek("284916", &salt, fast()).unwrap().as_slice(),
            base.as_slice()
        );
        assert_ne!(
            derive_kek("284915", &[8u8; SALT_LEN], fast())
                .unwrap()
                .as_slice(),
            base.as_slice(),
            "the salt must change the key, or two devices with the same PIN \
             would share a KEK"
        );
    }

    #[test]
    fn two_generated_salts_differ() {
        assert_ne!(generate_salt().unwrap(), generate_salt().unwrap());
    }

    /// Section 9.2.1's figures are the floor. A change to these is a change to
    /// how hard the PIN is to attack, so it should not pass unnoticed.
    #[test]
    fn the_default_cost_matches_the_specification() {
        let params = KdfParams::default();
        assert_eq!(params.memory_kib, 64 * 1024, "64 MiB");
        assert_eq!(params.iterations, 3);
        assert_eq!(params.lanes, 4);
    }

    #[test]
    fn untrusted_parameters_cannot_request_unbounded_resources() {
        for params in [
            KdfParams {
                memory_kib: MAX_MEMORY_KIB + 1,
                iterations: 1,
                lanes: 1,
            },
            KdfParams {
                memory_kib: 8,
                iterations: MAX_ITERATIONS + 1,
                lanes: 1,
            },
            KdfParams {
                memory_kib: 8,
                iterations: 1,
                lanes: MAX_LANES + 1,
            },
            KdfParams {
                memory_kib: 0,
                iterations: 1,
                lanes: 1,
            },
        ] {
            assert_eq!(params.validate(), Err(PinError::KdfParametersOutOfRange));
        }
    }

    /// The end-to-end property the module exists for: the PIN layer wraps and
    /// unwraps the vault key, and a wrong PIN is rejected rather than silently
    /// producing a wrong key.
    #[test]
    fn a_wrong_pin_cannot_unwrap_the_vault_key() {
        use crate::vault::RecordCipher;

        let vault_key = VaultKey::generate().unwrap();
        let salt = [4u8; SALT_LEN];

        let cipher = crate::crypto::XChaChaCipher::new(&kek_as_key(
            &derive_kek("284915", &salt, fast()).unwrap(),
        ));
        let sealed = cipher.seal("device-slot", 1, vault_key.expose()).unwrap();

        // The right PIN returns the key.
        let opened = cipher
            .open("device-slot", 1, &sealed.ciphertext, &sealed.nonce)
            .unwrap();
        assert_eq!(VaultKey::from_slice(&opened).unwrap(), vault_key);

        // A wrong one is refused by the tag, with no verifier stored anywhere.
        let wrong = crate::crypto::XChaChaCipher::new(&kek_as_key(
            &derive_kek("999888", &salt, fast()).unwrap(),
        ));
        assert!(
            wrong
                .open("device-slot", 1, &sealed.ciphertext, &sealed.nonce)
                .is_err(),
            "a wrong PIN must fail the unwrap"
        );
    }
}
