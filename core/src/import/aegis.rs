//! Aegis Authenticator exports (PRD FR-15).
//!
//! # Why this format matters more than its user count
//!
//! Aegis imports from about ten other applications, including Authy and
//! Microsoft Authenticator on a rooted Android device. Supporting it is
//! therefore an indirect path out of applications that have no export of their
//! own — section 8.2.1 makes this the reason it ranks above its own install
//! base.
//!
//! # The shape
//!
//! ```json
//! {
//!   "version": 1,
//!   "header": { "slots": null, "params": null },
//!   "db": { "version": 3, "entries": [ … ] }
//! }
//! ```
//!
//! In an encrypted export `header.slots` and `header.params` are populated and
//! `db` is a base64 string instead of an object. This module reads the plain
//! form and says precisely which it was given, because "this file is encrypted,
//! enter its password" and "this file is not an Aegis export" are different
//! problems and a user can only act on the first.

use serde_json::Value;

use crate::entry::{OtpEntry, Payload};
use crate::import::Report;
use crate::otp::Algorithm;
use crate::secret::SecretString;

use core::fmt;

/// Why a file could not be read as an Aegis export at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AegisError {
    NotAegis,
    /// The vault is encrypted and needs the password it was exported with.
    Encrypted,
    Malformed {
        detail: String,
    },
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAegis => f.write_str("This is not an Aegis export file."),
            Self::Encrypted => f.write_str(
                "This Aegis export is encrypted. Enter the password you set when \
                 you exported it.",
            ),
            Self::Malformed { detail } => {
                write!(f, "This Aegis export could not be read: {detail}")
            }
        }
    }
}

impl std::error::Error for AegisError {}

/// Reads a plain Aegis export.
///
/// FR-15d: one unreadable entry never fails the file. Anything that cannot be
/// understood joins the report with a reason a user can act on.
pub fn parse(text: &str) -> Result<Report, AegisError> {
    let root: Value = serde_json::from_str(text).map_err(|_| AegisError::NotAegis)?;

    // Told apart by shape, not by a flag: `db` is an object in a plain export
    // and a base64 string in an encrypted one.
    let db = root.get("db").ok_or(AegisError::NotAegis)?;
    if db.is_string() {
        return Err(AegisError::Encrypted);
    }

    let entries = db
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(AegisError::Malformed {
            detail: "it has no list of entries".to_string(),
        })?;

    let mut report = Report::default();
    for entry in entries {
        read_entry(entry, &mut report);
    }
    Ok(report)
}

/// Turns one Aegis entry into a payload, or a refusal.
pub(crate) fn read_entry(entry: &Value, report: &mut Report) {
    let issuer = entry.get("issuer").and_then(Value::as_str).unwrap_or("");
    let account = entry.get("name").and_then(Value::as_str).unwrap_or("");
    let label = if issuer.is_empty() {
        account.to_string()
    } else {
        format!("{issuer} ({account})")
    };

    let kind = entry.get("type").and_then(Value::as_str).unwrap_or("totp");
    let Some(info) = entry.get("info") else {
        report.refuse(&label, "it carries no code settings");
        return;
    };

    let Some(secret) = info.get("secret").and_then(Value::as_str) else {
        report.refuse(&label, "it carries no secret");
        return;
    };

    // Aegis stores the secret already Base32-encoded, which is what an entry
    // wants. Checked here rather than trusted: a secret that is not valid
    // Base32 produces an entry that looks imported and fails at the moment the
    // user needs a code.
    if crate::base32::decode(secret).is_err() {
        report.refuse(&label, "its secret is not valid Base32");
        return;
    }

    let algorithm = match info
        .get("algo")
        .and_then(Value::as_str)
        .unwrap_or("SHA1")
        .to_ascii_uppercase()
        .as_str()
    {
        "SHA1" => Algorithm::Sha1,
        "SHA256" => Algorithm::Sha256,
        "SHA512" => Algorithm::Sha512,
        other => {
            // Never substituted. A code produced with the wrong hash is wrong
            // every time, and an entry that imports and never works is worse
            // than one the user was told about.
            report.refuse(
                &label,
                format!("it uses {other}, which this app does not support"),
            );
            return;
        }
    };

    // The kind is checked before the digit count, and the order is the whole
    // of the message quality. A Steam entry has five digits, so checking digits
    // first refuses it with "it asks for 5-digit codes" — true, useless, and
    // about the wrong thing. Against Aegis's own test vault that was the only
    // refusal, and it named the wrong reason.
    //
    // It is now imported rather than refused (FR-06), and the ordering still
    // matters: five digits is out of range for everything else, so a Steam
    // entry must be recognised before the range check ever sees it.
    let kind = kind.to_ascii_lowercase();
    if kind != "totp" && kind != "hotp" && kind != "steam" {
        report.refuse(&label, format!("it is an unknown kind of code ({kind})"));
        return;
    }

    let digits = info
        .get("digits")
        .and_then(Value::as_u64)
        .unwrap_or(if kind == "steam" { 5 } else { 6 });
    if kind != "steam" && !(6..=8).contains(&digits) {
        report.refuse(&label, format!("it asks for {digits}-digit codes"));
        return;
    }

    let period = info.get("period").and_then(Value::as_u64).unwrap_or(30);
    if !(10..=300).contains(&period) && kind != "hotp" {
        report.refuse(
            &label,
            format!("its {period}-second period is out of range"),
        );
        return;
    }

    let base = OtpEntry {
        v: 1,
        issuer: if issuer.is_empty() {
            None
        } else {
            Some(issuer.to_string())
        },
        account: account.to_string(),
        secret: SecretString::new(secret),
        algorithm,
        digits: digits as u8,
        period: period as u32,
        counter: None,
        folder_id: None,
        icon: None,
        // Aegis has favourites; carrying it across means the list looks the way
        // the user arranged it rather than reset.
        favourite: entry
            .get("favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        order: String::new(),
        created_at: 0,
        note: entry
            .get("note")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        tags: Vec::new(),
        trashed_at: None,
        extra: Default::default(),
    };

    match kind.as_str() {
        "totp" => report.entries.push(Payload::Totp(base)),
        // FR-06. The digit count and period travel with it so the entry
        // round-trips unchanged, but neither is consulted when the code is
        // produced: both are fixed by the format.
        "steam" => report.entries.push(Payload::Steam(base)),
        "hotp" => {
            // FR-15d names this as the common refusal: the Key URI
            // specification marks the counter as required and several exporters
            // omit it. The user can supply it by hand, but only if they are
            // told which account needs one.
            let Some(counter) = info.get("counter").and_then(Value::as_u64) else {
                report.refuse(
                    &label,
                    "it is a counter-based code with no counter. Add it by hand \
                     and enter the counter from the app you are leaving.",
                );
                return;
            };
            report.entries.push(Payload::Hotp(OtpEntry {
                counter: Some(counter),
                ..base
            }));
        }
        // Unreachable: the kind was checked above, before the digit count, so
        // that a Steam entry is named as one rather than refused for having
        // five digits.
        other => report.refuse(&label, format!("it is an unknown kind of code ({other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain export in the shape Aegis writes.
    fn vault(entries: &str) -> String {
        format!(
            r#"{{"version":1,"header":{{"slots":null,"params":null}},
                 "db":{{"version":3,"entries":[{entries}]}}}}"#
        )
    }

    const TOTP: &str = r#"{
        "type":"totp","uuid":"a","name":"alice@example.com","issuer":"Example",
        "note":"","favorite":true,
        "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}
    }"#;

    #[test]
    fn a_plain_export_imports() {
        let report = parse(&vault(TOTP)).unwrap();
        assert!(report.refused.is_empty(), "{:?}", report.refused);

        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.secret.expose(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.issuer.as_deref(), Some("Example"));
        assert_eq!(entry.account, "alice@example.com");
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
        assert!(entry.favourite, "favourites should survive the move");
    }

    #[test]
    fn an_encrypted_export_says_so_rather_than_failing() {
        // "Enter its password" and "this is not an Aegis file" are different
        // problems, and a user can only act on the first.
        let encrypted = r#"{"version":1,
            "header":{"slots":[{"type":1}],"params":{"nonce":"aa","tag":"bb"}},
            "db":"YmFzZTY0"}"#;
        assert_eq!(parse(encrypted), Err(AegisError::Encrypted));
    }

    #[test]
    fn something_that_is_not_aegis_says_so() {
        for text in ["", "{}", "not json", r#"{"services":[]}"#] {
            assert_eq!(parse(text), Err(AegisError::NotAegis), "{text:?}");
        }
    }

    #[test]
    fn one_bad_entry_does_not_lose_the_others() {
        // FR-15d, the rule that shapes the whole module. A user moving forty
        // accounts with one malformed entry must end with thirty-nine and a
        // list, not with nothing and an error.
        let bad = r#"{"type":"totp","name":"broken","issuer":"X","info":{"secret":"!!!!"}}"#;
        let report = parse(&vault(&format!("{TOTP},{bad}"))).unwrap();

        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].label, "X (broken)");
        assert!(report.refused[0].reason.contains("Base32"));
    }

    #[test]
    fn a_counter_code_with_no_counter_is_named_not_dropped() {
        // The refusal FR-15d calls out by name. The user can supply the value,
        // but only if they know which account needs it.
        let hotp = r#"{"type":"hotp","name":"h","issuer":"Y",
                       "info":{"secret":"JBSWY3DPEHPK3PXP"}}"#;
        let report = parse(&vault(hotp)).unwrap();

        assert!(report.entries.is_empty());
        assert_eq!(report.refused[0].label, "Y (h)");
        assert!(report.refused[0].reason.contains("counter"));
    }

    #[test]
    fn a_counter_code_with_a_counter_imports() {
        let hotp = r#"{"type":"hotp","name":"h","issuer":"Y",
                       "info":{"secret":"JBSWY3DPEHPK3PXP","counter":42}}"#;
        let report = parse(&vault(hotp)).unwrap();
        assert_eq!(
            report.entries[0].as_otp().unwrap().counter,
            Some(42),
            "the counter must survive, or the first code is rejected"
        );
    }

    #[test]
    fn an_unsupported_algorithm_is_refused_rather_than_downgraded() {
        let md5 = r#"{"type":"totp","name":"m","issuer":"Z",
                      "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"MD5"}}"#;
        let report = parse(&vault(md5)).unwrap();
        assert!(report.entries.is_empty());
        assert!(report.refused[0].reason.contains("MD5"));
    }

    /// FR-06. This test used to assert the opposite — that a Steam entry was
    /// refused — and it was right to, until the feature existed. It is kept
    /// pointed at the same fixture because that fixture is the one Aegis's own
    /// test vault contains, and it was the entry that exposed the refusal
    /// naming the wrong reason.
    #[test]
    fn a_steam_entry_imports_as_a_steam_entry() {
        let steam = r#"{"type":"steam","name":"s","issuer":"Steam",
                        "info":{"secret":"JBSWY3DPEHPK3PXP","digits":5}}"#;
        let report = parse(&vault(steam)).unwrap();

        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(report.entries.len(), 1);

        // The kind has to survive, not just the secret. A Steam entry imported
        // as an ordinary five-digit TOTP produces numbers that look like codes
        // and are refused every time — the failure is silent at import and
        // total at use.
        assert!(
            report.entries[0].is_steam(),
            "a Steam entry imported as an ordinary code"
        );

        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.secret.expose(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.issuer.as_deref(), Some("Steam"));
    }

    /// The five-digit count must not open a door for anything else.
    ///
    /// Steam is admitted by *kind*, and the range check it skips still has to
    /// apply to every other kind — otherwise supporting Steam would quietly
    /// let a malformed TOTP entry through as well.
    #[test]
    fn five_digits_is_still_refused_for_a_normal_code() {
        let odd = r#"{"type":"totp","name":"o","issuer":"Z",
                      "info":{"secret":"JBSWY3DPEHPK3PXP","digits":5}}"#;
        let report = parse(&vault(odd)).unwrap();

        assert!(report.entries.is_empty());
        assert!(report.refused[0].reason.contains("5-digit"));
    }

    #[test]
    fn an_empty_vault_is_not_an_error() {
        // Exporting an empty vault is a thing people do to check the export
        // works. It should say "nothing to import", not "this file is broken".
        let report = parse(&vault("")).unwrap();
        assert!(report.is_empty());
    }

    #[test]
    fn defaults_are_applied_where_aegis_omits_them() {
        let sparse = r#"{"type":"totp","name":"a","issuer":"B",
                         "info":{"secret":"JBSWY3DPEHPK3PXP"}}"#;
        let report = parse(&vault(sparse)).unwrap();
        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }
}
