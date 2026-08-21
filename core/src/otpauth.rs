//! The `otpauth://` URI parser (FR-10, FR-13, and the first row of 8.2.1).
//!
//! Format: `otpauth://TYPE/LABEL?PARAMETERS`, where `TYPE` is `totp` or `hotp`
//! and `LABEL` is either `Account` or `Issuer:Account`, percent-encoded.
//!
//! This parser is deliberately strict about anything that would produce a
//! wrong code — an unreadable secret, a missing HOTP counter, an out-of-range
//! digit count — and lenient about presentation, because exports in the wild
//! vary in spacing, case, and which optional parameters they include.

use core::fmt;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use zeroize::Zeroizing;

use crate::base32::{self, Base32Error};
use crate::otp::{
    Algorithm, DEFAULT_DIGITS, DEFAULT_PERIOD, OtpError, OtpKind, check_digits, check_period, hotp,
    totp_at,
};
use crate::secret::SecretString;

const SCHEME: &str = "otpauth://";

/// Percent-encode everything outside the RFC 3986 unreserved set. Erring
/// towards more encoding keeps the output readable by strict parsers.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Why a URI could not be turned into an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpAuthError {
    /// The text is not an `otpauth://` URI at all.
    NotOtpAuth,
    /// The type segment was neither `totp` nor `hotp`.
    UnknownType { found: String },
    /// The label held no account name.
    MissingAccount,
    /// No `secret` parameter.
    MissingSecret,
    /// The `secret` parameter is not valid Base32.
    InvalidSecret(Base32Error),
    /// An HOTP entry with no `counter`. Guessing a counter would desynchronize
    /// the entry from the issuer, so this is refused instead.
    MissingCounter,
    /// A parameter that is present but unusable.
    InvalidParameter { name: &'static str, value: String },
    /// A parameter the OTP engine will not accept.
    Otp(OtpError),
}

impl fmt::Display for OtpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOtpAuth => write!(
                f,
                "This is not an otpauth:// link, so it holds no account to add."
            ),
            Self::UnknownType { found } => write!(
                f,
                "This link is of type '{found}'. Only 'totp' and 'hotp' are supported."
            ),
            Self::MissingAccount => write!(f, "This link carries no account name."),
            Self::MissingSecret => write!(f, "This link carries no secret, so it cannot be added."),
            Self::InvalidSecret(inner) => write!(f, "{inner}"),
            Self::MissingCounter => write!(
                f,
                "This is an HOTP link with no counter. Add the entry by hand and enter the \
                 counter that the service shows."
            ),
            Self::InvalidParameter { name, value } => {
                write!(f, "The '{name}' value '{value}' is not a number.")
            }
            Self::Otp(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for OtpAuthError {}

impl From<OtpError> for OtpAuthError {
    fn from(value: OtpError) -> Self {
        Self::Otp(value)
    }
}

/// One account, as carried by an `otpauth://` URI.
///
/// The secret is kept in its canonical Base32 form because that is what
/// `EntryPayload.secret` stores. Call [`OtpAuthUri::secret_bytes`] to get the
/// key the OTP engine needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuthUri {
    pub kind: OtpKind,
    pub issuer: Option<String>,
    pub account: String,
    pub secret: SecretString,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    /// Present for HOTP entries, absent for TOTP entries.
    pub counter: Option<u64>,
}

impl OtpAuthUri {
    /// Parses one URI.
    pub fn parse(input: &str) -> Result<Self, OtpAuthError> {
        let input = input.trim();
        if input.len() < SCHEME.len() || !input[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
            return Err(OtpAuthError::NotOtpAuth);
        }
        let rest = &input[SCHEME.len()..];

        let (path, query) = match rest.find('?') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => (rest, ""),
        };

        let (type_segment, label) = match path.find('/') {
            Some(at) => (&path[..at], &path[at + 1..]),
            None => (path, ""),
        };

        let kind = match type_segment.to_ascii_lowercase().as_str() {
            "totp" => OtpKind::Totp,
            "hotp" => OtpKind::Hotp,
            other => {
                return Err(OtpAuthError::UnknownType {
                    found: other.to_string(),
                });
            }
        };

        let (label_issuer, account) = split_label(&decode(label));
        let parameters = parse_query(query);

        // The Key URI format carries the issuer twice. When the parameter and
        // the label prefix disagree, the parameter is the authoritative one.
        let issuer = parameters
            .iter()
            .find(|(name, _)| name == "issuer")
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
            .or(label_issuer);

        if account.is_empty() {
            return Err(OtpAuthError::MissingAccount);
        }

        let raw_secret = parameters
            .iter()
            .find(|(name, _)| name == "secret")
            .map(|(_, value)| value.clone())
            .ok_or(OtpAuthError::MissingSecret)?;
        let secret = SecretString::from(
            base32::normalize(&raw_secret).map_err(OtpAuthError::InvalidSecret)?,
        );

        let algorithm = match parameters.iter().find(|(name, _)| name == "algorithm") {
            Some((_, value)) => {
                Algorithm::parse(value).ok_or_else(|| OtpAuthError::InvalidParameter {
                    name: "algorithm",
                    value: value.clone(),
                })?
            }
            None => Algorithm::default(),
        };

        let digits = number(&parameters, "digits")?.unwrap_or(u64::from(DEFAULT_DIGITS));
        let digits =
            u8::try_from(digits).map_err(|_| OtpError::UnsupportedDigits { digits: 255 })?;
        check_digits(digits)?;

        let period = number(&parameters, "period")?.unwrap_or(u64::from(DEFAULT_PERIOD));
        let period = u32::try_from(period).unwrap_or(u32::MAX);
        check_period(period)?;

        let counter = match kind {
            OtpKind::Totp => None,
            OtpKind::Hotp => {
                Some(number(&parameters, "counter")?.ok_or(OtpAuthError::MissingCounter)?)
            }
        };

        Ok(Self {
            kind,
            issuer,
            account,
            secret,
            algorithm,
            digits,
            period,
            counter,
        })
    }

    /// The decoded key for the OTP engine.
    pub fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
        self.secret.decode()
    }

    /// Generates the code this entry shows at a moment in time. For an HOTP
    /// entry the moment is ignored and the stored counter is used.
    pub fn code_at(&self, unix_seconds: i64) -> Result<String, OtpAuthError> {
        let secret = self.secret_bytes().map_err(OtpAuthError::InvalidSecret)?;
        let code = match self.kind {
            OtpKind::Totp => totp_at(
                &secret,
                unix_seconds,
                self.period,
                self.digits,
                self.algorithm,
            ),
            OtpKind::Hotp => hotp(
                &secret,
                self.counter.unwrap_or(0),
                self.digits,
                self.algorithm,
            ),
        };
        code.map_err(OtpAuthError::Otp)
    }

    /// Rebuilds the URI. Used by the QR export (FR-30) and by round-trip tests.
    ///
    /// Every optional parameter is written out rather than left to the reader's
    /// default, because a reader that defaults differently would produce codes
    /// that do not match.
    pub fn to_uri(&self) -> Zeroizing<String> {
        let label = match &self.issuer {
            Some(issuer) => format!("{issuer}:{}", self.account),
            None => self.account.clone(),
        };

        let mut uri = format!("{SCHEME}{}/{}", self.kind, encode(&label));
        uri.push_str("?secret=");
        uri.push_str(self.secret.expose());
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&encode(issuer));
        }
        uri.push_str("&algorithm=");
        uri.push_str(self.algorithm.as_str());
        uri.push_str(&format!("&digits={}", self.digits));
        match self.kind {
            OtpKind::Totp => uri.push_str(&format!("&period={}", self.period)),
            OtpKind::Hotp => uri.push_str(&format!("&counter={}", self.counter.unwrap_or(0))),
        }
        Zeroizing::new(uri)
    }
}

/// Parses a text file that holds one `otpauth://` URI per line.
///
/// Blank lines and lines that start with `#` are skipped. Every other line must
/// parse, and the line number travels with the error so the user interface can
/// point at the offending line.
pub fn parse_lines(input: &str) -> Vec<(usize, Result<OtpAuthUri, OtpAuthError>)> {
    input
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(number, line)| (number, OtpAuthUri::parse(line)))
        .collect()
}

fn decode(input: &str) -> String {
    percent_decode_str(input).decode_utf8_lossy().into_owned()
}

fn encode(input: &str) -> String {
    utf8_percent_encode(input, UNRESERVED).to_string()
}

/// Splits `Issuer:Account` into its two halves. A label with no colon is all
/// account name. Exports vary on whether a space follows the colon.
fn split_label(label: &str) -> (Option<String>, String) {
    let label = label.trim_start_matches('/').trim();
    match label.split_once(':') {
        Some((issuer, account)) => {
            let issuer = issuer.trim();
            let account = account.trim().to_string();
            if issuer.is_empty() {
                (None, account)
            } else {
                (Some(issuer.to_string()), account)
            }
        }
        None => (None, label.to_string()),
    }
}

/// Splits a query string into decoded name and value pairs. The first
/// occurrence of a name wins, so a malformed duplicate cannot override a good
/// value later in the string.
fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (name, value) = match part.split_once('=') {
            Some((name, value)) => (name, value),
            None => (part, ""),
        };
        let name = decode(name).to_ascii_lowercase();
        if pairs.iter().any(|(existing, _)| existing == &name) {
            continue;
        }
        pairs.push((name, decode(value)));
    }
    pairs
}

fn number(
    parameters: &[(String, String)],
    name: &'static str,
) -> Result<Option<u64>, OtpAuthError> {
    match parameters.iter().find(|(key, _)| key == name) {
        Some((_, value)) => {
            value
                .trim()
                .parse::<u64>()
                .map(Some)
                .map_err(|_| OtpAuthError::InvalidParameter {
                    name,
                    value: value.clone(),
                })
        }
        None => Ok(None),
    }
}
