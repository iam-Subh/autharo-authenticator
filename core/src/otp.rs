//! The TOTP and HOTP engines (FR-01 to FR-05).
//!
//! RFC 4226 defines HOTP over a counter. RFC 6238 defines TOTP as HOTP over a
//! counter derived from the clock. Both live here, and both take the key as
//! raw bytes so that the caller controls where the secret came from.

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Shortest period the application accepts (FR-05).
pub const MIN_PERIOD: u32 = 10;
/// Longest period the application accepts (FR-05).
pub const MAX_PERIOD: u32 = 300;
/// The period assumed when an `otpauth://` URI omits it (FR-05).
pub const DEFAULT_PERIOD: u32 = 30;
/// Fewest digits the application accepts (FR-04).
pub const MIN_DIGITS: u8 = 6;
/// Most digits the application accepts (FR-04).
pub const MAX_DIGITS: u8 = 8;
/// The digit count assumed when an `otpauth://` URI omits it (FR-04).
pub const DEFAULT_DIGITS: u8 = 6;

/// The hash inside the HMAC (FR-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Default for Algorithm {
    /// RFC 6238 leaves SHA-1 as the default, and almost every issuer relies on
    /// that. A different default would break most imported entries.
    fn default() -> Self {
        Self::Sha1
    }
}

impl Algorithm {
    /// Parses the `algorithm` parameter of an `otpauth://` URI. Issuers write
    /// this several ways, so both `SHA256` and `SHA-256` are accepted.
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The spelling used in an `otpauth://` URI and in `EntryPayload`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which of the two schemes an entry uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    Totp,
    Hotp,
}

impl OtpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
        }
    }
}

impl fmt::Display for OtpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parameter that the engine cannot honour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpError {
    /// A digit count outside FR-04.
    UnsupportedDigits { digits: u8 },
    /// A period outside FR-05.
    UnsupportedPeriod { period: u32 },
    /// A zero-length key. RFC 4226 requires at least 128 bits and recommends
    /// 160, but real issuers ship shorter keys, so only the empty key is
    /// refused outright.
    EmptySecret,
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDigits { digits } => write!(
                f,
                "This entry asks for {digits} digits. This application supports \
                 {MIN_DIGITS} to {MAX_DIGITS}."
            ),
            Self::UnsupportedPeriod { period } => write!(
                f,
                "This entry asks for a period of {period} seconds. This application \
                 supports {MIN_PERIOD} to {MAX_PERIOD}."
            ),
            Self::EmptySecret => {
                write!(f, "This entry has no secret, so no code can be generated.")
            }
        }
    }
}

impl std::error::Error for OtpError {}

/// Rejects digit counts outside FR-04.
pub fn check_digits(digits: u8) -> Result<(), OtpError> {
    if (MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        Ok(())
    } else {
        Err(OtpError::UnsupportedDigits { digits })
    }
}

/// Rejects periods outside FR-05.
pub fn check_period(period: u32) -> Result<(), OtpError> {
    if (MIN_PERIOD..=MAX_PERIOD).contains(&period) {
        Ok(())
    } else {
        Err(OtpError::UnsupportedPeriod { period })
    }
}

/// Runs the HMAC and keeps the result in memory that is wiped on drop.
fn mac(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    macro_rules! run {
        ($hash:ty) => {{
            // HMAC accepts a key of any length, so this cannot fail.
            let mut engine = <Hmac<$hash> as KeyInit>::new_from_slice(key)
                .expect("HMAC accepts a key of any length");
            Mac::update(&mut engine, message);
            Zeroizing::new(Mac::finalize(engine).into_bytes().as_slice().to_vec())
        }};
    }
    match algorithm {
        Algorithm::Sha1 => run!(Sha1),
        Algorithm::Sha256 => run!(Sha256),
        Algorithm::Sha512 => run!(Sha512),
    }
}

/// Generates an HOTP code (FR-02).
///
/// `secret` is the decoded key, not the Base32 text.
pub fn hotp(
    secret: &[u8],
    counter: u64,
    digits: u8,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    if secret.is_empty() {
        return Err(OtpError::EmptySecret);
    }
    check_digits(digits)?;

    let digest = mac(algorithm, secret, &counter.to_be_bytes());

    // RFC 4226 section 5.3, dynamic truncation. The low nibble of the last
    // byte selects a 4-byte window, and the top bit of that window is cleared
    // so the value is positive in a signed 32-bit reading.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    let code = binary % 10u32.pow(u32::from(digits));
    Ok(format!("{code:0width$}", width = usize::from(digits)))
}

/// The RFC 6238 time step for a moment in time.
///
/// `unix_seconds` is the reference time, which is the device clock plus the
/// stored offset from FR-38. Times before the epoch clamp to step zero.
pub fn totp_counter(unix_seconds: i64, period: u32) -> u64 {
    if unix_seconds <= 0 {
        return 0;
    }
    unix_seconds as u64 / u64::from(period)
}

/// Generates a TOTP code for a moment in time (FR-01).
pub fn totp_at(
    secret: &[u8],
    unix_seconds: i64,
    period: u32,
    digits: u8,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    check_period(period)?;
    hotp(
        secret,
        totp_counter(unix_seconds, period),
        digits,
        algorithm,
    )
}

/// Seconds until the current code expires. Drives the countdown in FR-07.
pub fn totp_remaining_seconds(unix_seconds: i64, period: u32) -> u32 {
    if period == 0 {
        return 0;
    }
    let elapsed = unix_seconds.rem_euclid(i64::from(period)) as u32;
    period - elapsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_parses_both_spellings() {
        assert_eq!(Algorithm::parse("sha256"), Some(Algorithm::Sha256));
        assert_eq!(Algorithm::parse("SHA-512"), Some(Algorithm::Sha512));
        assert_eq!(Algorithm::parse("md5"), None);
    }

    #[test]
    fn rejects_parameters_outside_the_supported_range() {
        let secret = b"12345678901234567890";
        assert_eq!(
            hotp(secret, 0, 9, Algorithm::Sha1).unwrap_err(),
            OtpError::UnsupportedDigits { digits: 9 }
        );
        assert_eq!(
            totp_at(secret, 59, 5, 6, Algorithm::Sha1).unwrap_err(),
            OtpError::UnsupportedPeriod { period: 5 }
        );
        assert_eq!(
            hotp(b"", 0, 6, Algorithm::Sha1).unwrap_err(),
            OtpError::EmptySecret
        );
    }

    #[test]
    fn accepts_the_whole_supported_range() {
        let secret = b"12345678901234567890";
        for digits in MIN_DIGITS..=MAX_DIGITS {
            let code = hotp(secret, 1, digits, Algorithm::Sha1).unwrap();
            assert_eq!(code.len(), usize::from(digits));
        }
        for period in [MIN_PERIOD, DEFAULT_PERIOD, 60, MAX_PERIOD] {
            assert!(totp_at(secret, 1_234_567_890, period, 6, Algorithm::Sha1).is_ok());
        }
    }

    #[test]
    fn countdown_counts_down_within_the_period() {
        assert_eq!(totp_remaining_seconds(0, 30), 30);
        assert_eq!(totp_remaining_seconds(1, 30), 29);
        assert_eq!(totp_remaining_seconds(29, 30), 1);
        assert_eq!(totp_remaining_seconds(30, 30), 30);
    }

    #[test]
    fn counter_advances_once_per_period() {
        assert_eq!(totp_counter(0, 30), 0);
        assert_eq!(totp_counter(29, 30), 0);
        assert_eq!(totp_counter(30, 30), 1);
        assert_eq!(totp_counter(-5, 30), 0);
    }
}
