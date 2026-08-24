//! Plain export readers for URI lists and JSON formats used by other apps.

use serde_json::Value;

use crate::entry::{OtpEntry, Payload};
use crate::import::Report;
use crate::otp::{Algorithm, DEFAULT_DIGITS, DEFAULT_PERIOD, OtpKind};
use crate::otpauth::OtpAuthUri;
use crate::secret::SecretString;

pub fn uri_lines(text: &str) -> Report {
    let mut report = Report::default();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        add_value(
            &mut report,
            line,
            None,
            format!("line {}", index + 1),
            "",
            Vec::new(),
            false,
        );
    }
    report
}

pub fn proton(root: &Value) -> Report {
    let mut report = Report::default();
    let Some(entries) = root.get("entries").and_then(Value::as_array) else {
        return report;
    };
    for (index, entry) in entries.iter().enumerate() {
        let content = entry.get("content").unwrap_or(entry);
        let label = content
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Proton entry");
        let Some(value) = content.get("uri").and_then(Value::as_str) else {
            report.refuse(label, "it contains no OTP URI");
            continue;
        };
        add_value(
            &mut report,
            value,
            Some(label),
            format!("Proton entry {}", index + 1),
            entry
                .get("note")
                .or_else(|| content.get("note"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            Vec::new(),
            false,
        );
    }
    report
}

pub fn bitwarden(root: &Value) -> Report {
    let mut report = Report::default();
    let Some(items) = root.get("items").and_then(Value::as_array) else {
        return report;
    };
    for item in items {
        let label = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Bitwarden item");
        let Some(login) = item.get("login") else {
            continue;
        };
        let Some(value) = login.get("totp").and_then(Value::as_str) else {
            continue;
        };
        let account = login
            .get("username")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(label);
        add_value(
            &mut report,
            value,
            Some(label),
            account.to_string(),
            item.get("notes").and_then(Value::as_str).unwrap_or(""),
            Vec::new(),
            item.get("favorite")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        );
    }
    report
}

pub fn standard_notes(root: &Value) -> Report {
    let mut report = Report::default();
    let Some(items) = root.as_array() else {
        return report;
    };
    for item in items {
        let issuer = item
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or("Authenticator");
        let account = item
            .get("account")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(issuer);
        let Some(secret) = item.get("secret").and_then(Value::as_str) else {
            report.refuse(account, "it contains no OTP secret");
            continue;
        };
        add_value(
            &mut report,
            secret,
            Some(issuer),
            account.to_string(),
            item.get("notes").and_then(Value::as_str).unwrap_or(""),
            Vec::new(),
            false,
        );
    }
    report
}

#[allow(clippy::too_many_arguments)]
fn add_value(
    report: &mut Report,
    value: &str,
    fallback_issuer: Option<&str>,
    fallback_account: String,
    note: &str,
    tags: Vec<String>,
    favourite: bool,
) {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    let parsed = if lower.starts_with("otpauth://") {
        OtpAuthUri::parse(trimmed)
    } else if lower.starts_with("steam://") {
        let raw_secret = &trimmed["steam://".len()..];
        match crate::base32::normalize(raw_secret) {
            Ok(secret) => Ok(OtpAuthUri {
                kind: OtpKind::Steam,
                issuer: fallback_issuer.map(str::to_string),
                account: fallback_account.clone(),
                secret: SecretString::new(secret.as_str()),
                algorithm: Algorithm::Sha1,
                digits: 5,
                period: DEFAULT_PERIOD,
                counter: None,
            }),
            Err(error) => {
                report.refuse(fallback_account, error.to_string());
                return;
            }
        }
    } else {
        match crate::base32::normalize(trimmed) {
            Ok(secret) => Ok(OtpAuthUri {
                kind: OtpKind::Totp,
                issuer: fallback_issuer.map(str::to_string),
                account: fallback_account.clone(),
                secret: SecretString::new(secret.as_str()),
                algorithm: Algorithm::Sha1,
                digits: DEFAULT_DIGITS,
                period: DEFAULT_PERIOD,
                counter: None,
            }),
            Err(error) => {
                report.refuse(fallback_account, error.to_string());
                return;
            }
        }
    };

    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            report.refuse(fallback_account, error.to_string());
            return;
        }
    };
    let mut payload = OtpEntry::from_uri(&parsed, 0);
    if let Payload::Totp(entry) | Payload::Hotp(entry) | Payload::Steam(entry) = &mut payload {
        entry.note = note.trim().to_string();
        entry.tags = tags;
        entry.favourite = favourite;
    }
    report.entries.push(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    #[test]
    fn ente_plain_lines_import_independently() {
        let report = uri_lines(&format!("{URI}\n!!!!"));
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.refused.len(), 1);
    }

    #[test]
    fn proton_plain_json_reads_content_uri() {
        let root: Value = serde_json::from_str(&format!(
            r#"{{"entries":[{{"content":{{"name":"Example","uri":"{URI}"}}}}]}}"#
        ))
        .unwrap();
        assert_eq!(proton(&root).entries.len(), 1);
    }

    #[test]
    fn bitwarden_accepts_uri_and_secret_only_totp_values() {
        let root: Value = serde_json::from_str(&format!(
            r#"{{"encrypted":false,"items":[
                {{"name":"one","login":{{"totp":"{URI}"}}}},
                {{"name":"two","login":{{"username":"bob","totp":"JBSWY3DPEHPK3PXP"}}}}
            ]}}"#
        ))
        .unwrap();
        assert_eq!(bitwarden(&root).entries.len(), 2);
    }

    #[test]
    fn standard_notes_preserves_notes() {
        let root: Value = serde_json::from_str(
            r#"[{"service":"Example","account":"alice","secret":"JBSWY3DPEHPK3PXP","notes":"keep"}]"#,
        )
        .unwrap();
        let report = standard_notes(&root);
        assert_eq!(report.entries[0].as_otp().unwrap().note, "keep");
    }
}
