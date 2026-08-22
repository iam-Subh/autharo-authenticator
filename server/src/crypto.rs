//! The two server-side cryptographic jobs (PRD sections 9.2.1, 9.5).
//!
//! Neither of them is decryption. The server cannot read a vault, and nothing
//! in this file moves it closer to being able to: one function hashes an
//! authentication key so a stolen dump does not let anyone sign in, and the
//! other fabricates a salt so an unauthenticated caller cannot tell whether an
//! address has an account.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Argon2id cost for the server-side hash of the authentication key.
///
/// Lower than the client's, and deliberately so. The client's Argon2id is what
/// stands between a password and the master key; by the time a value reaches
/// here it is already a 256-bit HKDF output with full entropy, so the server's
/// pass is not stretching a guessable secret. Its job is to make a stolen
/// `auth_hash` useless for signing in, and for that a lower cost is enough —
/// and it has to be, because this runs on every sign-in for every account
/// while the client's runs once on one device.
const SERVER_MEMORY_KIB: u32 = 19 * 1024;
const SERVER_ITERATIONS: u32 = 2;
const SERVER_LANES: u32 = 1;

/// Section 9.2.1 step 5: "The server hashes the authentication key again with
/// Argon2id and a server-side salt, then stores the result. The server never
/// stores the authentication key itself."
///
/// The salt is generated per hash by `SaltString` and travels inside the
/// returned PHC string, so no separate column is needed.
pub fn hash_auth_key(auth_key: &[u8]) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Ok(argon()?.hash_password(auth_key, &salt)?.to_string())
}

/// Verifies an authentication key against a stored hash.
///
/// Argon2's verifier compares in constant time, so a wrong key costs the same
/// as a right one and reveals nothing by timing.
pub fn verify_auth_key(auth_key: &[u8], stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    let Ok(argon) = argon() else {
        return false;
    };
    argon.verify_password(auth_key, &parsed).is_ok()
}

fn argon() -> Result<Argon2<'static>, argon2::password_hash::Error> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(SERVER_MEMORY_KIB, SERVER_ITERATIONS, SERVER_LANES, None)?,
    ))
}

/// Fabricates the salt returned by `prelogin` for an address with no account
/// (section 9.5).
///
/// # Why an HMAC and not a random value
///
/// "The same address must always produce the same fake values, or the
/// difference itself leaks the answer." A random salt per request would answer
/// the attacker's question immediately: ask twice, and a real account gives
/// the same salt while a fake one does not.
///
/// The server key makes the output unpredictable, so an attacker cannot
/// compute the expected fake salt offline and compare. Without it, a fake
/// would be recognisable by construction.
///
/// This is only half of the defence. A body that matches but a response time
/// that does not still answers the question — see `auth::prelogin` for the
/// other half.
pub fn fake_client_salt(server_key: &[u8], email: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(server_key)
        .expect("HMAC accepts a key of any length");
    // Domain-separated so this key can be reused for another purpose later
    // without the two outputs colliding.
    mac.update(b"authcore/v1/prelogin-fake-salt\x00");
    mac.update(normalise_email(email).as_bytes());

    // 128 bits, the same length as a real client salt (section 9.2.1 step 2).
    // A different length would be as good as a label saying "no account".
    mac.finalize().into_bytes()[..16].to_vec()
}

/// Lowercased and trimmed, matching the `CITEXT` comparison the account table
/// uses. Without this, `Rupsa@` and `rupsa@` would produce different fake
/// salts for what the database treats as one address.
pub fn normalise_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(text)
}

/// A random token for the session table.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system must supply randomness");
    b64_encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hashed_auth_key_verifies_and_a_wrong_one_does_not() {
        let key = [7u8; 32];
        let stored = hash_auth_key(&key).unwrap();

        assert!(verify_auth_key(&key, &stored));
        assert!(!verify_auth_key(&[8u8; 32], &stored));
    }

    /// The stored value must not contain the authentication key. This is the
    /// whole point of section 9.2.1 step 5: a dump must not let anyone sign in.
    #[test]
    fn the_stored_hash_does_not_contain_the_key() {
        let key = b"an-authentication-key-of-32-bytes";
        let stored = hash_auth_key(key).unwrap();

        assert!(!stored.contains("an-authentication-key"));
        assert!(!stored.as_bytes().windows(key.len()).any(|w| w == key));
        assert!(stored.starts_with("$argon2id$"));
    }

    /// Two hashes of the same key must differ, or the salt is not per-hash and
    /// identical keys would be visible as identical rows.
    #[test]
    fn the_same_key_hashes_differently_each_time() {
        let key = [7u8; 32];
        assert_ne!(hash_auth_key(&key).unwrap(), hash_auth_key(&key).unwrap());
    }

    /// Section 9.5: the same address must always produce the same fake values.
    #[test]
    fn a_fake_salt_is_stable_for_an_address() {
        let server_key = b"server-held-key";

        assert_eq!(
            fake_client_salt(server_key, "rupsa@example.com"),
            fake_client_salt(server_key, "rupsa@example.com"),
        );
        // Case and whitespace must not change it: the account table compares
        // addresses case-insensitively, so these are one address.
        assert_eq!(
            fake_client_salt(server_key, "rupsa@example.com"),
            fake_client_salt(server_key, "  Rupsa@Example.COM  "),
        );
    }

    #[test]
    fn different_addresses_get_different_fake_salts() {
        let server_key = b"server-held-key";
        assert_ne!(
            fake_client_salt(server_key, "rupsa@example.com"),
            fake_client_salt(server_key, "someone@example.com"),
        );
    }

    /// A fake salt must be indistinguishable from a real one by length. A
    /// different length would announce itself.
    #[test]
    fn a_fake_salt_is_the_same_length_as_a_real_one() {
        assert_eq!(fake_client_salt(b"k", "rupsa@example.com").len(), 16);
    }

    /// Without the server key an attacker could compute the expected fake and
    /// recognise it. Different keys must give different answers.
    #[test]
    fn the_server_key_changes_the_fake_salt() {
        assert_ne!(
            fake_client_salt(b"one-server-key", "rupsa@example.com"),
            fake_client_salt(b"another-server-key", "rupsa@example.com"),
        );
    }

    #[test]
    fn tokens_are_random_and_url_safe() {
        let first = random_token();
        assert_ne!(first, random_token());
        assert!(!first.contains('+') && !first.contains('/') && !first.contains('='));
    }
}
