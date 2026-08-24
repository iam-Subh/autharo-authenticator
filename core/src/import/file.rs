//! One reader for every export file this app understands (PRD FR-15, FR-15a).
//!
//! # Why the user is not asked which app the file came from
//!
//! Every export here is JSON with a distinctive shape, so the file can say what
//! it is. Making the user pick "Aegis" or "2FAS" from a menu first adds a step
//! whose only possible outcomes are correct — in which case it was not needed —
//! or wrong, in which case a perfectly good file is reported as unreadable and
//! the user concludes the import does not work.
//!
//! The person doing this has usually just installed the app and is deciding
//! whether to keep it. A wrong error message at that moment is the end of it.
//!
//! # The one thing worth telling them apart for
//!
//! Whether a password is needed, and for which application. "This Aegis export
//! is encrypted" is actionable; "enter a password" leaves someone wondering
//! which of their passwords is being asked for.
//!
//! # Backups from this app are read here too
//!
//! FR-28's restore has its own screen, and this reader still accepts its files.
//! A user who picks their own backup from the wrong menu should succeed rather
//! than be told it is not a recognised export — the alternative is a correct
//! error nobody can act on.

use serde_json::Value;

use crate::backup::{self, BackupError};
use crate::import::{Report, aegis, encrypted, generic, twofas};

use core::fmt;

/// The application a file came from, for the messages that need to name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Aegis,
    TwoFas,
    Ente,
    Proton,
    Bitwarden,
    StandardNotes,
    /// A backup written by this app.
    Own,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Aegis => "Aegis",
            Self::TwoFas => "2FAS",
            Self::Ente => "Ente Authenticator",
            Self::Proton => "Proton Authenticator",
            Self::Bitwarden => "Bitwarden",
            Self::StandardNotes => "Standard Notes",
            Self::Own => "backup",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    /// Recognised, encrypted, and no password was supplied.
    NeedsPassword {
        source: Source,
    },
    /// The password did not open it. Indistinguishable from a damaged file:
    /// that is what an authenticated cipher gives you, and pretending
    /// otherwise would mean claiming a certainty this does not have.
    WrongPasswordOrDamaged {
        source: Source,
    },
    /// Not an export this app knows how to read.
    Unrecognised,
    Malformed {
        source: Source,
        detail: String,
    },
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsPassword { source } => match source {
                Source::Own => {
                    f.write_str("This backup is encrypted. Enter the passphrase you set for it.")
                }
                other => write!(
                    f,
                    "This {} export is encrypted. Enter the password you set when \
                     you exported it.",
                    other.label()
                ),
            },
            Self::WrongPasswordOrDamaged { .. } => f.write_str(
                "That password did not open the file. Check it and try again — if \
                 the password is definitely right, the file may be damaged or \
                 incomplete.",
            ),
            // Names what it does read, because the commonest cause is a user
            // who exported the wrong thing — a `.json` of app settings, an
            // Authy database, a screenshot renamed.
            Self::Unrecognised => f.write_str(
                "This is not an export file this app can read. It reads Aegis, \
                 2FAS, Ente URI lists, Proton Authenticator, Bitwarden, Standard \
                 Notes, and backups made by this app. Google Authenticator moves \
                 across by QR code instead.",
            ),
            Self::Malformed { source, detail } => {
                write!(
                    f,
                    "This {} file could not be read: {detail}",
                    source.label()
                )
            }
        }
    }
}

impl std::error::Error for FileError {}

/// What a file is, without reading its contents.
///
/// Lets a screen ask for a password before spending a second in scrypt, and —
/// more importantly — lets it *not* ask when the file is plain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detected {
    pub source: Source,
    pub encrypted: bool,
}

/// Identifies a file by shape.
///
/// Shape, not extension: Aegis writes `.json`, 2FAS writes `.2fas`, and both
/// arrive as `.json.txt` or with no extension at all once a messaging app or a
/// cloud drive has been through them.
pub fn detect(text: &str) -> Result<Detected, FileError> {
    if text
        .lines()
        .map(str::trim)
        .any(|line| line.to_ascii_lowercase().starts_with("otpauth://"))
    {
        return Ok(Detected {
            source: Source::Ente,
            encrypted: false,
        });
    }

    let root: Value = serde_json::from_str(text).map_err(|_| FileError::Unrecognised)?;

    // This app's own backup names itself, so it is checked first and cannot be
    // confused with anything else.
    if root.get("format").and_then(Value::as_str) == Some(backup::FORMAT) {
        return Ok(Detected {
            source: Source::Own,
            encrypted: root
                .get("encrypted")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }

    // Ente password exports name both their Argon2 parameters and their
    // secret-stream fields. Check this before other generic JSON shapes.
    if root.get("kdfParams").is_some()
        && root.get("encryptedData").and_then(Value::as_str).is_some()
        && root
            .get("encryptionNonce")
            .and_then(Value::as_str)
            .is_some()
    {
        return Ok(Detected {
            source: Source::Ente,
            encrypted: true,
        });
    }

    // Proton password exports are a versioned salt and encrypted content.
    // Plain Proton exports carry an `entries` array instead.
    if root.get("salt").and_then(Value::as_str).is_some()
        && root.get("content").and_then(Value::as_str).is_some()
        && root.get("version").and_then(Value::as_u64).is_some()
    {
        return Ok(Detected {
            source: Source::Proton,
            encrypted: true,
        });
    }

    // Aegis: `db` is an object in a plain export and a base64 string in an
    // encrypted one. That is the format's own signal, and the only one it has.
    if let Some(db) = root.get("db") {
        return Ok(Detected {
            source: Source::Aegis,
            encrypted: db.is_string(),
        });
    }

    // 2FAS: a protected backup carries a *populated* `servicesEncrypted` beside
    // an empty `services`. Deciding on `services` alone is how a reader reports
    // importing nothing from a file holding forty accounts.
    let protected = root
        .get("servicesEncrypted")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if protected || root.get("services").is_some() {
        return Ok(Detected {
            source: Source::TwoFas,
            encrypted: protected,
        });
    }

    if root
        .get("entries")
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(|entry| entry.get("content").is_some()))
    {
        return Ok(Detected {
            source: Source::Proton,
            encrypted: false,
        });
    }

    if root.get("items").and_then(Value::as_array).is_some() {
        if root
            .get("encrypted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FileError::Malformed {
                source: Source::Bitwarden,
                detail: "export an unencrypted JSON file from Bitwarden and try again".to_string(),
            });
        }
        return Ok(Detected {
            source: Source::Bitwarden,
            encrypted: false,
        });
    }

    if root.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item.get("service").is_some()
                && item.get("account").is_some()
                && item.get("secret").is_some()
        })
    }) {
        return Ok(Detected {
            source: Source::StandardNotes,
            encrypted: false,
        });
    }

    Err(FileError::Unrecognised)
}

/// Reads any supported export.
///
/// `password` is ignored for a plain file rather than refused. Users do not
/// remember which kind they made, and turning that into an error would be
/// pedantry standing between someone and their accounts.
pub fn read(text: &str, password: Option<&str>) -> Result<Report, FileError> {
    let detected = detect(text)?;
    let source = detected.source;

    if detected.encrypted && password.is_none() {
        return Err(FileError::NeedsPassword { source });
    }

    match (source, detected.encrypted) {
        (Source::Own, _) => backup::read(text, password)
            .map(|opened| Report {
                entries: opened.entries,
                refused: Vec::new(),
            })
            .map_err(|error| match error {
                BackupError::NeedsPassphrase => FileError::NeedsPassword { source },
                BackupError::WrongPassphraseOrDamaged => {
                    FileError::WrongPasswordOrDamaged { source }
                }
                other => FileError::Malformed {
                    source,
                    detail: other.to_string(),
                },
            }),

        (Source::Aegis, false) => aegis::parse(text).map_err(|error| match error {
            // Unreachable through `detect`, which already told the two apart —
            // but mapped rather than unwrapped, because a panic here would be
            // triggered by a file, and files come from outside.
            aegis::AegisError::Encrypted => FileError::NeedsPassword { source },
            other => FileError::Malformed {
                source,
                detail: other.to_string(),
            },
        }),

        (Source::TwoFas, false) => twofas::parse(text).map_err(|error| match error {
            twofas::TwoFasError::Encrypted => FileError::NeedsPassword { source },
            other => FileError::Malformed {
                source,
                detail: other.to_string(),
            },
        }),

        (Source::Ente, false) => Ok(generic::uri_lines(text)),
        (Source::Proton, false) => serde_json::from_str(text)
            .map(|root| generic::proton(&root))
            .map_err(|error| FileError::Malformed {
                source,
                detail: error.to_string(),
            }),
        (Source::Bitwarden, false) => serde_json::from_str(text)
            .map(|root| generic::bitwarden(&root))
            .map_err(|error| FileError::Malformed {
                source,
                detail: error.to_string(),
            }),
        (Source::StandardNotes, false) => serde_json::from_str(text)
            .map(|root| generic::standard_notes(&root))
            .map_err(|error| FileError::Malformed {
                source,
                detail: error.to_string(),
            }),

        (Source::Aegis, true) => open(encrypted::aegis(text, password.unwrap_or_default()), source),
        (Source::TwoFas, true) => open(
            encrypted::twofas(text, password.unwrap_or_default()),
            source,
        ),
        (Source::Ente, true) => open(encrypted::ente(text, password.unwrap_or_default()), source),
        (Source::Proton, true) => open(
            encrypted::proton(text, password.unwrap_or_default()),
            source,
        ),
        (Source::Bitwarden | Source::StandardNotes, true) => Err(FileError::Malformed {
            source,
            detail: "this encrypted export variant is not supported".to_string(),
        }),
    }
}

/// Keeps a structural failure from being reported as a wrong password.
///
/// The distinction matters more than it looks. Told "wrong password", a user
/// retypes it, retypes it again, and concludes they have lost their accounts.
/// Told the file is damaged, they go and export it again — which is the thing
/// that actually works.
fn open(
    result: Result<Report, encrypted::DecryptError>,
    source: Source,
) -> Result<Report, FileError> {
    result.map_err(|error| match error {
        encrypted::DecryptError::WrongPasswordOrDamaged => {
            FileError::WrongPasswordOrDamaged { source }
        }
        other => FileError::Malformed {
            source,
            detail: other.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AEGIS: &str = r#"{"version":1,"header":{"slots":null,"params":null},
        "db":{"version":3,"entries":[
            {"type":"totp","uuid":"a","name":"alice","issuer":"Example","info":
             {"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}]}}"#;

    const TWOFAS: &str = r#"{"services":[
        {"name":"Example","secret":"JBSWY3DPEHPK3PXP",
         "otp":{"account":"alice","tokenType":"TOTP"}}],"schemaVersion":4}"#;
    const URI: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    const PROTON: &str = r#"{"entries":[{"content":{"name":"Example",
        "uri":"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"}}]}"#;
    const BITWARDEN: &str = r#"{"encrypted":false,"items":[{"name":"Example",
        "login":{"username":"alice","totp":"JBSWY3DPEHPK3PXP"}}]}"#;
    const STANDARD_NOTES: &str = r#"[{"service":"Example","account":"alice",
        "secret":"JBSWY3DPEHPK3PXP","notes":"keep"}]"#;
    const ENTE_ENCRYPTED_HEADER: &str = r#"{"version":1,"kdfParams":{"memLimit":10240,
        "opsLimit":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"encryptedData":"AA==",
        "encryptionNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    const PROTON_ENCRYPTED_HEADER: &str = r#"{"version":1,
        "salt":"AAAAAAAAAAAAAAAAAAAAAA==","content":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#;

    #[test]
    fn each_format_identifies_itself() {
        assert_eq!(detect(AEGIS).unwrap().source, Source::Aegis);
        assert_eq!(detect(TWOFAS).unwrap().source, Source::TwoFas);
        assert!(!detect(AEGIS).unwrap().encrypted);
        assert!(!detect(TWOFAS).unwrap().encrypted);
        assert_eq!(detect(URI).unwrap().source, Source::Ente);
        assert_eq!(detect(PROTON).unwrap().source, Source::Proton);
        assert_eq!(detect(BITWARDEN).unwrap().source, Source::Bitwarden);
        assert_eq!(
            detect(STANDARD_NOTES).unwrap().source,
            Source::StandardNotes
        );
        assert_eq!(
            detect(ENTE_ENCRYPTED_HEADER).unwrap(),
            Detected {
                source: Source::Ente,
                encrypted: true
            }
        );
        assert_eq!(
            detect(PROTON_ENCRYPTED_HEADER).unwrap(),
            Detected {
                source: Source::Proton,
                encrypted: true
            }
        );
    }

    #[test]
    fn a_plain_file_of_either_kind_reads_without_being_named() {
        // The point of the module: the user picks a file, not an application.
        for text in [AEGIS, TWOFAS] {
            let report = read(text, None).unwrap();
            assert_eq!(report.entries.len(), 1, "{text}");
            assert_eq!(
                report.entries[0].as_otp().unwrap().secret.expose(),
                "JBSWY3DPEHPK3PXP"
            );
        }
    }

    #[test]
    fn broader_plain_formats_use_the_same_partial_import_report() {
        for text in [URI, PROTON, BITWARDEN, STANDARD_NOTES] {
            let report = read(text, None).unwrap();
            assert_eq!(report.entries.len(), 1, "{text}");
            assert!(report.refused.is_empty(), "{text}");
        }
    }

    #[test]
    fn encrypted_bitwarden_names_the_required_export_type() {
        let error = detect(r#"{"encrypted":true,"items":[]}"#).unwrap_err();
        assert!(error.to_string().contains("unencrypted JSON"));
    }

    #[test]
    fn an_encrypted_file_names_the_app_it_came_from() {
        // "Enter a password" leaves a user wondering which of their passwords
        // is wanted. Naming the app answers it.
        let aegis = r#"{"version":1,
            "header":{"slots":[{"type":1}],"params":{"nonce":"aa","tag":"bb"}},
            "db":"YmFzZTY0"}"#;
        assert_eq!(
            read(aegis, None),
            Err(FileError::NeedsPassword {
                source: Source::Aegis
            })
        );

        let twofas = r#"{"services":[],
            "servicesEncrypted":"ZW5jcnlwdGVk:c2FsdA==:aXY=","schemaVersion":4}"#;
        assert_eq!(
            read(twofas, None),
            Err(FileError::NeedsPassword {
                source: Source::TwoFas
            })
        );

        assert_eq!(
            read(ENTE_ENCRYPTED_HEADER, None),
            Err(FileError::NeedsPassword {
                source: Source::Ente
            })
        );
        assert_eq!(
            read(PROTON_ENCRYPTED_HEADER, None),
            Err(FileError::NeedsPassword {
                source: Source::Proton
            })
        );
    }

    #[test]
    fn an_empty_2fas_backup_is_not_mistaken_for_an_encrypted_one() {
        // The other half of the rule 2FAS forced. A genuinely empty export must
        // read as empty, or someone checking that the export works is told to
        // enter a password that does not exist.
        let empty = r#"{"services":[],"schemaVersion":4}"#;
        let detected = detect(empty).unwrap();
        assert_eq!(detected.source, Source::TwoFas);
        assert!(!detected.encrypted);
        assert!(read(empty, None).unwrap().is_empty());
    }

    #[test]
    fn a_password_on_a_plain_file_is_ignored_rather_than_refused() {
        // Users do not remember which kind they made.
        assert!(read(AEGIS, Some("unnecessary")).is_ok());
        assert!(read(TWOFAS, Some("unnecessary")).is_ok());
    }

    #[test]
    fn this_apps_own_backup_reads_here_too() {
        // So that picking a backup from the import menu works rather than
        // producing a correct error nobody can act on.
        use crate::backup;
        let entries = read(AEGIS, None).unwrap().entries;
        let own = backup::export_plain(&entries).unwrap();

        let detected = detect(&own).unwrap();
        assert_eq!(detected.source, Source::Own);
        assert_eq!(read(&own, None).unwrap().entries, entries);
    }

    #[test]
    fn an_encrypted_backup_of_ours_is_recognised_before_it_is_opened() {
        use crate::backup;
        let entries = read(AEGIS, None).unwrap().entries;
        let own = backup::export_encrypted(&entries, "a passphrase").unwrap();

        assert!(detect(&own).unwrap().encrypted);
        assert_eq!(
            read(&own, None),
            Err(FileError::NeedsPassword {
                source: Source::Own
            })
        );
        assert_eq!(read(&own, Some("a passphrase")).unwrap().entries, entries);
        assert_eq!(
            read(&own, Some("wrong")),
            Err(FileError::WrongPasswordOrDamaged {
                source: Source::Own
            })
        );
    }

    #[test]
    fn something_else_entirely_says_what_this_does_read() {
        // The commonest cause is a user who exported the wrong file, so the
        // message lists what would work instead of only saying no.
        for text in ["", "not json", "{}", r#"{"foo":1}"#, "[]"] {
            let error = read(text, None).unwrap_err();
            assert_eq!(error, FileError::Unrecognised, "{text:?}");
            assert!(error.to_string().contains("Aegis"));
            assert!(error.to_string().contains("2FAS"));
        }
    }

    #[test]
    fn one_bad_entry_still_does_not_fail_the_file() {
        // FR-15d survives the extra layer. Easy to lose when a dispatcher is
        // added on top of parsers that each got it right.
        let mixed = r#"{"version":1,"header":{"slots":null,"params":null},
            "db":{"version":3,"entries":[
              {"type":"totp","uuid":"a","name":"alice","issuer":"Example","info":
               {"secret":"JBSWY3DPEHPK3PXP"}},
              {"type":"totp","uuid":"b","name":"broken","issuer":"X","info":
               {"secret":"!!!!"}}]}}"#;

        let report = read(mixed, None).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].label, "X (broken)");
    }

    #[test]
    fn a_damaged_file_is_not_reported_as_a_wrong_password() {
        // Told "wrong password", a user retypes it until they conclude their
        // accounts are gone. Told the file is damaged, they export it again —
        // which is the thing that actually works.
        let structurally_broken = r#"{"version":1,
            "header":{"slots":[{"type":1,"key":"zz"}],"params":{}},
            "db":"YmFzZTY0"}"#;
        match read(structurally_broken, Some("anything")) {
            Err(FileError::Malformed { source, .. }) => {
                assert_eq!(source, Source::Aegis);
            }
            other => panic!("a malformed file was reported as {other:?}"),
        }
    }
}
