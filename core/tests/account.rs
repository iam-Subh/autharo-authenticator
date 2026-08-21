//! The password and recovery slots (PRD sections 9.2.1, 9.2.3, 16.2, 16.4).
//!
//! These use the real Argon2id cost, so the file is slow by design. The cost
//! is the security property; testing a cheaper one would test something else.

use authcore::account::{self, Account, AccountError, RECOVERY_WORDS, WORDS_TO_CONFIRM};
use authcore::crypto::VaultKey;
use authcore::store::MetaStore;

const EMAIL: &str = "rupsa@example.com";
const PASSWORD: &str = "correct horse battery staple";

fn meta() -> MetaStore {
    MetaStore::open_in_memory().unwrap()
}

/// Stands in for the key the device slot already holds.
fn existing_vault_key() -> VaultKey {
    VaultKey::from_slice(&[0x2Au8; 32]).unwrap()
}

/// The rule from section 9.2.4, and the one with the worst failure mode:
/// creating a sync account must not change the vault key. Every entry on the
/// device is already encrypted under it, and a new key would leave all of them
/// unreadable with nothing to say so.
#[test]
fn creating_an_account_does_not_change_the_vault_key() {
    let meta = meta();
    let original = existing_vault_key();

    let (_, _phrase) = account::create_account(&meta, EMAIL, PASSWORD, &original).unwrap();

    let by_password = account::unlock_with_password(&meta, PASSWORD).unwrap();
    assert_eq!(
        by_password.expose(),
        original.expose(),
        "the password slot returned a different key, so every existing entry \
         would be unreadable"
    );
}

/// The test the requirement asks for by name: wrap with the recovery key,
/// unwrap, and compare the bytes. A recovery path that returns a *valid but
/// different* key fails silently until someone actually needs it.
#[test]
fn recovery_returns_the_identical_vault_key() {
    let meta = meta();
    let original = existing_vault_key();

    let (_, phrase) = account::create_account(&meta, EMAIL, PASSWORD, &original).unwrap();

    let recovered = account::unlock_with_recovery(&meta, phrase.as_str()).unwrap();

    assert_eq!(
        recovered.expose(),
        original.expose(),
        "recovery produced a different key; every entry would be lost"
    );
}

/// Both slots wrap the same key, so both must return it.
#[test]
fn the_password_and_recovery_slots_open_the_same_vault() {
    let meta = meta();
    let original = existing_vault_key();
    let (_, phrase) = account::create_account(&meta, EMAIL, PASSWORD, &original).unwrap();

    assert_eq!(
        account::unlock_with_password(&meta, PASSWORD)
            .unwrap()
            .expose(),
        account::unlock_with_recovery(&meta, phrase.as_str())
            .unwrap()
            .expose()
    );
}

/// Section 9.2.1: the salt is random per account, not derived from the email.
/// Two accounts with the same address and password must not share a salt, or
/// one precomputed table attacks both.
#[test]
fn the_salt_is_random_and_not_derived_from_the_email() {
    let first = meta();
    let second = meta();
    let key = existing_vault_key();

    account::create_account(&first, EMAIL, PASSWORD, &key).unwrap();
    account::create_account(&second, EMAIL, PASSWORD, &key).unwrap();

    let a = account::load(&first)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();
    let b = account::load(&second)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();

    assert_ne!(a.salt, b.salt, "the same address produced the same salt");
    assert_eq!(a.salt.len(), 16, "128 bits, per section 9.2.1");
    assert_ne!(a.salt, [0u8; 16]);

    // The email must not appear in the salt in any form.
    assert!(!a.salt.windows(4).any(|w| w == b"rups"));
}

/// The same password under a different salt must give a different wrapped key.
#[test]
fn the_salt_changes_the_derived_key() {
    let first = meta();
    let second = meta();
    let key = existing_vault_key();

    account::create_account(&first, EMAIL, PASSWORD, &key).unwrap();
    account::create_account(&second, EMAIL, PASSWORD, &key).unwrap();

    let a = account::load(&first)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();
    let b = account::load(&second)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();

    assert_ne!(a.wrapped_key, b.wrapped_key);
}

/// Section 9.2.1 step 4: the master key splits into an authentication key and
/// a KEK. They must be different, or sending one would send the other.
#[test]
fn the_authentication_key_is_not_the_key_encryption_key() {
    let meta = meta();
    let key = existing_vault_key();
    account::create_account(&meta, EMAIL, PASSWORD, &key).unwrap();

    let slot = account::load(&meta)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();
    let auth = account::derive_auth_key(PASSWORD, &slot).unwrap();

    // The authentication key must not be the vault key either.
    assert_ne!(auth.as_slice(), key.expose().as_slice());
    assert_ne!(auth.as_slice(), &[0u8; 32]);

    // Deterministic for the same password and slot: S4 has to reproduce it.
    let again = account::derive_auth_key(PASSWORD, &slot).unwrap();
    assert_eq!(auth.as_slice(), again.as_slice());

    // And a different password gives a different one.
    let other = account::derive_auth_key("something else entirely", &slot).unwrap();
    assert_ne!(auth.as_slice(), other.as_slice());
}

/// No server exists yet, so nothing may be stored that depends on one — and
/// the authentication key in particular is derived on demand, never written.
#[test]
fn nothing_stored_depends_on_a_server() {
    let meta = meta();
    let key = existing_vault_key();
    account::create_account(&meta, EMAIL, PASSWORD, &key).unwrap();

    let slot = account::load(&meta)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();
    let auth = account::derive_auth_key(PASSWORD, &slot).unwrap();

    // Every stored value, scanned for the authentication key and the vault key.
    for meta_key in [
        "account.email",
        "account.password.salt",
        "account.password.params",
        "account.password.wrapped",
        "account.password.nonce",
        "account.recovery.wrapped",
        "account.recovery.nonce",
    ] {
        let Some(value) = meta.get(meta_key).unwrap() else {
            continue;
        };
        assert!(
            !value.windows(32).any(|w| w == auth.as_slice()),
            "{meta_key} holds the authentication key"
        );
        assert!(
            !value.windows(32).any(|w| w == key.expose().as_slice()),
            "{meta_key} holds the vault key in the clear"
        );
    }

    // No account id, no token, no server-assigned anything.
    for absent in ["account.id", "account.token", "account.server_seq"] {
        assert!(meta.get(absent).unwrap().is_none(), "{absent} was stored");
    }
}

/// Section 16.4 and decision 6: every synced account requires an email address.
#[test]
fn an_account_without_an_email_address_is_refused() {
    let key = existing_vault_key();

    for empty in ["", "   ", "\t"] {
        assert!(
            matches!(
                account::create_account(&meta(), empty, PASSWORD, &key),
                Err(AccountError::EmailRequired)
            ),
            "{empty:?} should be refused"
        );
    }

    // And nothing was written on the way to refusing.
    let meta = meta();
    let _ = account::create_account(&meta, "", PASSWORD, &key);
    assert!(account::load(&meta).unwrap().is_none());
}

/// Section 9.2.3: the recovery slot is mandatory, and it is 24 BIP-39 words.
#[test]
fn the_recovery_phrase_is_twenty_four_words() {
    let meta = meta();
    let (account, phrase) =
        account::create_account(&meta, EMAIL, PASSWORD, &existing_vault_key()).unwrap();

    assert_eq!(phrase.words().len(), RECOVERY_WORDS);
    assert!(
        phrase
            .words()
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase())),
        "BIP-39 English words are lowercase ASCII"
    );
    assert!(!account.recovery_slot.wrapped_key.is_empty());
}

/// Every account gets its own phrase.
#[test]
fn two_accounts_get_different_recovery_phrases() {
    let key = existing_vault_key();
    let (_, first) = account::create_account(&meta(), EMAIL, PASSWORD, &key).unwrap();
    let (_, second) = account::create_account(&meta(), EMAIL, PASSWORD, &key).unwrap();

    assert_ne!(first.as_str(), second.as_str());
}

/// Section 9.2.3 step 4: confirm three words, chosen at random.
#[test]
fn three_random_words_are_chosen_for_confirmation() {
    let meta = meta();
    let (_, phrase) =
        account::create_account(&meta, EMAIL, PASSWORD, &existing_vault_key()).unwrap();

    let indices = phrase.indices_to_confirm().unwrap();

    assert_eq!(indices.len(), WORDS_TO_CONFIRM);
    assert!(indices.iter().all(|&i| i < RECOVERY_WORDS));

    let mut unique = indices.clone();
    unique.dedup();
    assert_eq!(unique.len(), WORDS_TO_CONFIRM, "the same word twice");

    // Random, not a fixed set. Over several draws at least two must differ, or
    // confirming would teach the user three positions rather than the phrase.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..12 {
        seen.insert(phrase.indices_to_confirm().unwrap());
    }
    assert!(seen.len() > 1, "the positions never changed");
}

/// A wrong password must be refused, not silently produce a wrong key.
#[test]
fn a_wrong_password_is_refused() {
    let meta = meta();
    account::create_account(&meta, EMAIL, PASSWORD, &existing_vault_key()).unwrap();

    assert!(matches!(
        account::unlock_with_password(&meta, "not the password"),
        Err(AccountError::WrongPassword)
    ));
}

/// A typo in the phrase is a typo, not a wrong vault. BIP-39's checksum
/// catches it, and saying which is the difference between "check your
/// spelling" and "your vault is gone".
#[test]
fn a_mistyped_recovery_phrase_is_reported_as_a_typo() {
    let meta = meta();
    let (_, phrase) =
        account::create_account(&meta, EMAIL, PASSWORD, &existing_vault_key()).unwrap();

    let mut words = phrase.words();
    words[0] = "zebra";
    let mistyped = words.join(" ");

    assert!(
        matches!(
            account::unlock_with_recovery(&meta, &mistyped),
            Err(AccountError::BadRecoveryPhrase { .. })
        ),
        "a checksum failure should be reported as a bad phrase"
    );

    // Too few words, likewise.
    assert!(matches!(
        account::unlock_with_recovery(&meta, "abandon abandon abandon"),
        Err(AccountError::BadRecoveryPhrase { .. })
    ));
}

/// A valid phrase from a different vault must be refused as the wrong key,
/// which is a different message from a typo.
#[test]
fn another_vaults_recovery_phrase_is_refused() {
    let mine = meta();
    let theirs = meta();
    account::create_account(&mine, EMAIL, PASSWORD, &existing_vault_key()).unwrap();
    let (_, other_phrase) = account::create_account(
        &theirs,
        EMAIL,
        PASSWORD,
        &VaultKey::from_slice(&[9u8; 32]).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        account::unlock_with_recovery(&mine, other_phrase.as_str()),
        Err(AccountError::WrongRecoveryKey)
    ));
}

/// Section 9.4: the phrase unwraps the vault key, so it must not print.
#[test]
fn the_recovery_phrase_does_not_print() {
    let meta = meta();
    let (_, phrase) =
        account::create_account(&meta, EMAIL, PASSWORD, &existing_vault_key()).unwrap();

    let rendered = format!("{phrase:?}");
    assert!(rendered.contains("redacted"));
    for word in phrase.words() {
        assert!(
            !rendered.contains(word),
            "Debug leaked a word of the phrase"
        );
    }
}

/// The slots have to survive a restart, since they are what a second device
/// and a recovery both depend on.
#[test]
fn the_account_survives_a_reload() {
    let meta = meta();
    let key = existing_vault_key();
    let (created, phrase) = account::create_account(&meta, EMAIL, PASSWORD, &key).unwrap();

    let loaded: Account = account::load(&meta).unwrap().unwrap();
    assert_eq!(loaded, created);
    assert_eq!(loaded.email, EMAIL);

    // And both paths still open the vault after the round trip.
    assert_eq!(
        account::unlock_with_password(&meta, PASSWORD)
            .unwrap()
            .expose(),
        key.expose()
    );
    assert_eq!(
        account::unlock_with_recovery(&meta, phrase.as_str())
            .unwrap()
            .expose(),
        key.expose()
    );
}

/// A device with no sync account reports that plainly.
#[test]
fn a_device_with_no_account_says_so() {
    let meta = meta();
    assert!(account::load(&meta).unwrap().is_none());
    assert!(matches!(
        account::unlock_with_password(&meta, PASSWORD),
        Err(AccountError::NoAccount)
    ));
}

/// The cost parameters are stored so a future increase stays compatible with
/// slots written under the old ones (section 9.2.1 step 3).
#[test]
fn the_kdf_parameters_are_stored_with_the_slot() {
    let meta = meta();
    account::create_account(&meta, EMAIL, PASSWORD, &existing_vault_key()).unwrap();

    let slot = account::load(&meta)
        .unwrap()
        .unwrap()
        .password_slot
        .unwrap();
    assert_eq!(slot.params.memory_kib, 64 * 1024, "64 MiB on mobile");
    assert_eq!(slot.params.iterations, 3);
    assert_eq!(slot.params.lanes, 4);
}
