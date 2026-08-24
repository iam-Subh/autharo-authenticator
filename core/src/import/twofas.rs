//! 2FAS backup files (PRD FR-15a).
//!
//! `.2fas` is JSON. The plain form carries `services`; the password-protected
//! form carries `servicesEncrypted` instead and `services` is an empty array —
//! which matters, because a reader that only looks at `services` finds a valid
//! empty list and reports a successful import of nothing.
//!
//! That is the failure this module is shaped around. "Imported 0 accounts" on a
//! file containing forty is indistinguishable, to the user, from an app that
//! does not work — and it is worse than an error, because they have no reason
//! to try again with a password.
//!
//! # The shape
//!
//! ```json
//! {
//!   "services": [
//!     { "name": "Example",
//!       "secret": "JBSWY3DPEHPK3PXP",
//!       "otp": { "account": "alice", "issuer": "Example",
//!                "digits": 6, "period": 30,
//!                "algorithm": "SHA1", "tokenType": "TOTP" } }
//!   ],
//!   "schemaVersion": 4
//! }
//! ```

use serde_json::Value;

use crate::entry::{OtpEntry, Payload};
use crate::import::Report;
use crate::otp::Algorithm;
use crate::secret::SecretString;

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoFasError {
    NotTwoFas,
    /// Password-protected. Not "empty".
    Encrypted,
    Malformed {
        detail: String,
    },
}

impl fmt::Display for TwoFasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTwoFas => f.write_str("This is not a 2FAS backup file."),
            Self::Encrypted => f.write_str(
                "This 2FAS backup is password-protected. Enter the password you \
                 set when you made it.",
            ),
            Self::Malformed { detail } => {
                write!(f, "This 2FAS backup could not be read: {detail}")
            }
        }
    }
}

impl std::error::Error for TwoFasError {}

/// Reads a plain `.2fas` backup.
pub fn parse(text: &str) -> Result<Report, TwoFasError> {
    let root: Value = serde_json::from_str(text).map_err(|_| TwoFasError::NotTwoFas)?;

    // A protected backup carries an *empty* `services` array alongside
    // `servicesEncrypted`. A reader that looks only at `services` therefore
    // finds a valid empty list and reports importing nothing — from a file
    // with forty accounts in it. That is worse than an error, because nothing
    // tells the user to try again with a password.
    //
    // What matters is that this check exists at all, not that it comes first:
    // either order gives the same answer, since neither reads entries until
    // afterwards. It is written first only because it reads as the question
    // being asked — is this file readable without a password.
    if root
        .get("servicesEncrypted")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return Err(TwoFasError::Encrypted);
    }

    let services = root
        .get("services")
        .and_then(Value::as_array)
        .ok_or(TwoFasError::NotTwoFas)?;

    let mut report = Report::default();
    for service in services {
        read_service(service, &mut report);
    }
    Ok(report)
}

pub(crate) fn read_service(service: &Value, report: &mut Report) {
    let otp = service.get("otp");

    // 2FAS keeps the display name at the top level and the account inside
    // `otp`. Either can be missing, and falling back keeps an entry
    // identifiable rather than blank.
    let issuer = otp
        .and_then(|otp| otp.get("issuer"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| service.get("name").and_then(Value::as_str))
        .unwrap_or("");
    let account = otp
        .and_then(|otp| otp.get("account"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| service.get("name").and_then(Value::as_str))
        .unwrap_or("");

    let label = if issuer.is_empty() {
        account.to_string()
    } else {
        format!("{issuer} ({account})")
    };

    let Some(secret) = service.get("secret").and_then(Value::as_str) else {
        report.refuse(&label, "it carries no secret");
        return;
    };
    if crate::base32::decode(secret).is_err() {
        report.refuse(&label, "its secret is not valid Base32");
        return;
    }

    let algorithm = match otp
        .and_then(|otp| otp.get("algorithm"))
        .and_then(Value::as_str)
        .unwrap_or("SHA1")
        .to_ascii_uppercase()
        .as_str()
    {
        "SHA1" => Algorithm::Sha1,
        "SHA256" => Algorithm::Sha256,
        "SHA512" => Algorithm::Sha512,
        other => {
            report.refuse(
                &label,
                format!("it uses {other}, which this app does not support"),
            );
            return;
        }
    };

    let kind = otp
        .and_then(|otp| otp.get("tokenType"))
        .and_then(Value::as_str)
        .unwrap_or("TOTP")
        .to_ascii_uppercase();

    // Recognised before the digit count, for the same reason as in the Aegis
    // reader: a Steam entry has five digits, which is out of range for
    // everything else, so checking the range first refuses it for the wrong
    // reason. Imported rather than refused since FR-06.
    let steam = kind == "STEAM";

    let digits = otp
        .and_then(|otp| otp.get("digits"))
        .and_then(Value::as_u64)
        .unwrap_or(if steam { 5 } else { 6 });
    if !steam && !(6..=8).contains(&digits) {
        report.refuse(&label, format!("it asks for {digits}-digit codes"));
        return;
    }

    let period = otp
        .and_then(|otp| otp.get("period"))
        .and_then(Value::as_u64)
        .unwrap_or(30);

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
        favourite: false,
        order: String::new(),
        created_at: 0,
        note: String::new(),
        tags: Vec::new(),
        trashed_at: None,
        extra: Default::default(),
    };

    match kind.as_str() {
        "TOTP" => report.entries.push(Payload::Totp(base)),
        "STEAM" => report.entries.push(Payload::Steam(base)),
        "HOTP" => {
            let Some(counter) = otp
                .and_then(|otp| otp.get("counter"))
                .and_then(Value::as_u64)
            else {
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
        other => report.refuse(&label, format!("it is an unknown kind of code ({other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup(services: &str) -> String {
        format!(r#"{{"services":[{services}],"schemaVersion":4,"appVersionCode":5000000}}"#)
    }

    const SERVICE: &str = r#"{
        "name":"Example",
        "secret":"JBSWY3DPEHPK3PXP",
        "otp":{"account":"alice","issuer":"Example","digits":6,"period":30,
               "algorithm":"SHA1","tokenType":"TOTP"}
    }"#;

    #[test]
    fn a_plain_backup_imports() {
        let report = parse(&backup(SERVICE)).unwrap();
        assert!(report.refused.is_empty(), "{:?}", report.refused);

        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.secret.expose(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.issuer.as_deref(), Some("Example"));
        assert_eq!(entry.account, "alice");
    }

    /// The failure this module is shaped around.
    #[test]
    fn a_protected_backup_is_not_read_as_an_empty_one() {
        // A protected backup carries an empty `services` next to
        // `servicesEncrypted`. A reader that checks `services` first finds a
        // valid empty list and reports importing nothing — from a file with
        // forty accounts in it. The user has no reason to try again with a
        // password, because nothing said one was needed.
        let protected = r#"{"services":[],
            "servicesEncrypted":"ZW5jcnlwdGVk:c2FsdA==:aXY=",
            "schemaVersion":4}"#;

        assert_eq!(
            parse(protected),
            Err(TwoFasError::Encrypted),
            "an encrypted backup must not import as zero accounts"
        );
    }

    #[test]
    fn an_empty_backup_is_still_an_empty_backup() {
        // The other half: a genuinely empty file must not claim to be
        // encrypted. People export an empty vault to check the export works.
        let report = parse(&backup("")).unwrap();
        assert!(report.is_empty());
    }

    #[test]
    fn an_empty_encrypted_field_is_not_treated_as_encryption() {
        let text = r#"{"services":[],"servicesEncrypted":"","schemaVersion":4}"#;
        assert!(parse(text).is_ok(), "an empty field means no encryption");
    }

    #[test]
    fn something_that_is_not_a_2fas_backup_says_so() {
        for text in ["", "not json", "{}", r#"{"db":{"entries":[]}}"#] {
            assert_eq!(parse(text), Err(TwoFasError::NotTwoFas), "{text:?}");
        }
    }

    #[test]
    fn one_bad_service_does_not_lose_the_others() {
        let bad = r#"{"name":"broken","secret":"!!!","otp":{"account":"x"}}"#;
        let report = parse(&backup(&format!("{SERVICE},{bad}"))).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0].reason.contains("Base32"));
    }

    #[test]
    fn a_missing_account_falls_back_to_the_name() {
        // Otherwise the entry arrives blank and the user cannot tell which of
        // their forty accounts it is.
        let sparse = r#"{"name":"GitHub","secret":"JBSWY3DPEHPK3PXP","otp":{}}"#;
        let report = parse(&backup(sparse)).unwrap();
        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.account, "GitHub");
        assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
    }

    #[test]
    fn a_counter_code_without_a_counter_is_named() {
        let hotp = r#"{"name":"H","secret":"JBSWY3DPEHPK3PXP",
                       "otp":{"account":"h","tokenType":"HOTP"}}"#;
        let report = parse(&backup(hotp)).unwrap();
        assert!(report.entries.is_empty());
        assert!(report.refused[0].reason.contains("counter"));
    }

    #[test]
    fn a_counter_code_with_a_counter_imports() {
        let hotp = r#"{"name":"H","secret":"JBSWY3DPEHPK3PXP",
                       "otp":{"account":"h","tokenType":"HOTP","counter":7}}"#;
        let report = parse(&backup(hotp)).unwrap();
        assert_eq!(report.entries[0].as_otp().unwrap().counter, Some(7));
    }

    #[test]
    fn eight_digit_and_sha256_entries_survive() {
        // 2FAS supports both, and silently normalising either produces codes
        // the service rejects with nothing to explain it.
        let odd = r#"{"name":"O","secret":"JBSWY3DPEHPK3PXP",
                      "otp":{"account":"o","digits":8,"algorithm":"SHA256","period":60}}"#;
        let report = parse(&backup(odd)).unwrap();
        let entry = report.entries[0].as_otp().unwrap();
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.algorithm, Algorithm::Sha256);
        assert_eq!(entry.period, 60);
    }
}
