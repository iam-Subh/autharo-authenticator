//! The importers, against files the real applications actually produced.
//!
//! # Why this exists separately from the unit tests
//!
//! The tests inside `import::encrypted` build their fixtures with the same
//! primitives that read them. That proves the reader round-trips with the
//! writer, and nothing more. Whether it reads what Aegis and 2FAS *write* is a
//! different question, and one those tests cannot answer: if a detail was
//! guessed wrong, the writer and the reader agree on the wrong thing, every
//! test passes, and every real import fails.
//!
//! This file closes that. The fixtures are Aegis's own test vaults and 2FAS
//! backups, downloaded rather than committed — they come from a GPLv3 project,
//! and copying test data across that line is a question nobody here needs to
//! answer.
//!
//! It found a defect the moment it ran. The single refused entry in Aegis's
//! vault is a Steam code, and it was being refused with "it asks for 5-digit
//! codes" — true, useless, and about the wrong thing, because the digit count
//! was checked before the kind. No self-built fixture had a Steam entry in it,
//! because I did not think to write one.
//!
//! That entry now imports rather than being refused (FR-06), and it is still
//! the most valuable row in either file: it is the only Steam code in this
//! project that came out of a real exporter rather than out of a fixture
//! written by the same hand that wrote the reader.
//!
//! # Running it
//!
//! ```text
//! sh scripts/fetch_import_fixtures.sh
//! cd core && AUTHCORE_IMPORT_FIXTURES=../.fixtures cargo test --test real_exports
//! ```
//!
//! Marked `#[ignore]`, so a plain `cargo test` reports them as ignored rather
//! than failing on a machine that has not fetched the files. That is a visible
//! skip, not a silent pass — cargo prints the count, and `check_all.sh` runs
//! them for real whenever `.fixtures` is present and names the fetch script
//! when it is not.
//!
//! When they do run and the files are missing, they panic with the command to
//! fetch them. A test that quietly passed on absent input would be
//! indistinguishable from one that works.

use authcore::import::{Report, aegis, encrypted, twofas};

/// The password Aegis uses for its own encrypted test fixtures.
const PASSWORD: &str = "test";

fn fixture(name: &str) -> String {
    let dir = std::env::var("AUTHCORE_IMPORT_FIXTURES").unwrap_or_else(|_| {
        panic!(
            "set AUTHCORE_IMPORT_FIXTURES to the fixture directory.\n\
             Get the files with: sh scripts/fetch_import_fixtures.sh\n\
             Then: AUTHCORE_IMPORT_FIXTURES=../.fixtures cargo test --test real_exports"
        )
    });

    std::fs::read_to_string(format!("{dir}/{name}")).unwrap_or_else(|error| {
        panic!(
            "could not read {name} from {dir}: {error}\n\
             Fetch the fixtures with: sh scripts/fetch_import_fixtures.sh"
        )
    })
}

/// Every entry either imported or refused with a reason, and none lost.
fn assert_accounted_for(report: &Report, expected_total: usize, what: &str) {
    assert_eq!(
        report.total(),
        expected_total,
        "{what}: {} entries were read, but the file holds {expected_total}. \
         An entry that is neither imported nor refused has vanished, which is \
         the one outcome FR-15d forbids.",
        report.total()
    );
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn a_real_plain_aegis_vault_imports() {
    let report = aegis::parse(&fixture("aegis_plain.json")).expect("Aegis's own test vault");

    assert_eq!(report.entries.len(), 7);
    assert_accounted_for(&report, 7, "aegis plain");
    assert!(report.refused.is_empty(), "{:?}", report.refused);

    // FR-06, against a file Aegis wrote. Until this feature existed the entry
    // was refused here, and this assertion was its mirror image: that the
    // refusal named the kind rather than complaining about the digit count.
    //
    // What matters now is that it arrives as a *Steam* entry. Imported as an
    // ordinary five-digit code it would look completely successful and produce
    // numbers Steam rejects every time.
    let steam: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry.is_steam())
        .collect();
    assert_eq!(
        steam.len(),
        1,
        "Aegis's vault holds exactly one Steam entry, and it must survive as one"
    );

    // A real secret, read out of a real file.
    let entry = report.entries[0].as_otp().unwrap();
    assert_eq!(entry.secret.expose(), "4SJHB4GSD43FZBAI7C2HLRJGPQ");
    assert_eq!(entry.issuer.as_deref(), Some("Deno"));
    assert_eq!(entry.account, "Mason");
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn a_real_encrypted_aegis_vault_opens() {
    // The assertion the self-built fixtures could not make: scrypt with the
    // header's own parameters, AES-256-GCM with a detached tag, against a file
    // this project did not write.
    let report =
        encrypted::aegis(&fixture("aegis_encrypted.json"), PASSWORD).expect("password is 'test'");

    assert_eq!(report.entries.len(), 7);
    assert_accounted_for(&report, 7, "aegis encrypted");
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn an_encrypted_and_a_plain_aegis_vault_agree() {
    // The two fixtures hold the same accounts. If the decrypted path produced
    // anything different, one of the two readers is wrong — and comparing them
    // says so without needing to know which entries to expect.
    let plain = aegis::parse(&fixture("aegis_plain.json")).unwrap();
    let opened = encrypted::aegis(&fixture("aegis_encrypted.json"), PASSWORD).unwrap();

    let names = |report: &Report| {
        let mut names: Vec<String> = report
            .entries
            .iter()
            .filter_map(|payload| payload.as_otp())
            .map(|entry| format!("{:?}/{}", entry.issuer, entry.account))
            .collect();
        names.sort();
        names
    };

    assert_eq!(
        names(&plain),
        names(&opened),
        "the encrypted vault decrypted to different accounts than the plain one"
    );
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn a_wrong_password_on_a_real_vault_is_refused() {
    assert!(
        encrypted::aegis(&fixture("aegis_encrypted.json"), "not the password").is_err(),
        "a wrong password must not open a real vault"
    );
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn a_real_plain_2fas_backup_imports() {
    let report =
        twofas::parse(&fixture("2fas_authenticator_plain_v4.2fas")).expect("a real 2FAS backup");

    assert_eq!(report.entries.len(), 5);
    assert_accounted_for(&report, 5, "2fas plain");
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    assert_eq!(
        report
            .entries
            .iter()
            .filter(|entry| entry.is_steam())
            .count(),
        1,
        "2FAS's backup holds one Steam entry and it must survive as one"
    );

    let entry = report.entries[0].as_otp().unwrap();
    assert_eq!(entry.secret.expose(), "4SJHB4GSD43FZBAI7C2HLRJGPQ");
    assert_eq!(entry.issuer.as_deref(), Some("Deno"));
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn a_real_encrypted_2fas_backup_opens() {
    // PBKDF2-HMAC-SHA256 at 2FAS's own round count, AES-256-GCM with the tag
    // appended, and the three-field colon-separated block — none of which this
    // project chose, and all of which had to match exactly.
    let report = encrypted::twofas(&fixture("2fas_authenticator_encrypted_v4.2fas"), PASSWORD)
        .expect("password is 'test'");

    assert_eq!(report.entries.len(), 5);
    assert_accounted_for(&report, 5, "2fas encrypted");
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn an_encrypted_and_a_plain_2fas_backup_agree() {
    let plain = twofas::parse(&fixture("2fas_authenticator_plain_v4.2fas")).unwrap();
    let opened =
        encrypted::twofas(&fixture("2fas_authenticator_encrypted_v4.2fas"), PASSWORD).unwrap();

    let secrets = |report: &Report| {
        let mut values: Vec<String> = report
            .entries
            .iter()
            .filter_map(|payload| payload.as_otp())
            .map(|entry| entry.secret.expose().to_string())
            .collect();
        values.sort();
        values
    };

    assert_eq!(secrets(&plain), secrets(&opened));
}

#[test]
#[ignore = "needs downloaded fixtures: sh scripts/fetch_import_fixtures.sh"]
fn the_two_applications_export_the_same_accounts() {
    // Aegis and 2FAS made these fixtures from the same set of accounts, so the
    // secrets 2FAS exports must all appear in what Aegis exports. A reader that
    // mangled a secret in one format only would pass every test above and fail
    // here.
    let aegis_report = aegis::parse(&fixture("aegis_plain.json")).unwrap();
    let twofas_report = twofas::parse(&fixture("2fas_authenticator_plain_v4.2fas")).unwrap();

    let aegis_secrets: Vec<String> = aegis_report
        .entries
        .iter()
        .filter_map(|payload| payload.as_otp())
        .map(|entry| entry.secret.expose().to_string())
        .collect();

    for entry in twofas_report.entries.iter().filter_map(|p| p.as_otp()) {
        assert!(
            aegis_secrets.contains(&entry.secret.expose().to_string()),
            "{} is in the 2FAS export but not the Aegis one, so one reader \
             changed a secret",
            entry.account
        );
    }
}
