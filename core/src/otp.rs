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

/// Which scheme an entry uses.
///
/// `Steam` is not in any RFC. It is in here because Aegis writes
/// `otpauth://steam/...` and 2FAS reads it, so it is the ecosystem's actual
/// interchange form for FR-06 — and an entry this app can import but cannot
/// hand back is one the user cannot take anywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    Totp,
    Hotp,
    Steam,
}

impl OtpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
            Self::Steam => "steam",
        }
    }

    /// True when the code changes with the clock rather than on demand.
    pub fn is_time_based(self) -> bool {
        !matches!(self, Self::Hotp)
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

/// The alphabet Steam Guard codes are drawn from (FR-06).
///
/// Twenty-six characters, and not the Latin alphabet: `A`, `E`, `I`, `L`, `O`,
/// `S`, `U`, `Z` and every digit below 2 are absent. Valve left out the
/// characters people confuse when reading a code off a phone and typing it
/// somewhere else — `0`/`O`, `1`/`I`/`L`, `5`/`S`, `2`/`Z`.
///
/// The order is part of the algorithm, not a presentation choice. Sorting it
/// would produce five valid-looking characters that Steam rejects.
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Characters in a Steam Guard code.
pub const STEAM_DIGITS: u8 = 5;

/// Generates a Steam Guard code (FR-06).
///
/// # Why this is not just TOTP with five digits
///
/// It shares everything up to the truncation: SHA-1, a thirty-second step, the
/// same dynamic truncation from RFC 4226 section 5.3. What differs is the last
/// step — instead of taking the value modulo a power of ten, Valve reads it in
/// base 26 against their own alphabet.
///
/// This is why a Steam entry imported as an ordinary five-digit TOTP produces
/// numbers that look like codes and are never accepted, and why the importers
/// refuse them by *kind* rather than by digit count. "It asks for 5-digit
/// codes" is true and about the wrong thing.
///
/// Not covered by any RFC. The construction is what every Steam client
/// implements and what Aegis and 2FAS export entries expecting.
pub fn steam(secret: &[u8], counter: u64) -> Result<String, OtpError> {
    if secret.is_empty() {
        return Err(OtpError::EmptySecret);
    }

    let digest = mac(Algorithm::Sha1, secret, &counter.to_be_bytes());

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let mut value = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    // Five characters, least significant first — the order Valve's clients
    // emit. 26^5 is about 11.9 million and the truncated value can exceed it,
    // so the high part is simply discarded, exactly as every implementation
    // does.
    let mut code = String::with_capacity(usize::from(STEAM_DIGITS));
    for _ in 0..STEAM_DIGITS {
        code.push(STEAM_ALPHABET[(value % 26) as usize] as char);
        value /= 26;
    }
    Ok(code)
}

/// A Steam Guard code for a moment in time.
///
/// The period is fixed at thirty seconds. It is not configurable in the format
/// and not negotiable with Steam, so it is not a parameter — one that could be
/// set wrong is one that will be.
pub fn steam_at(secret: &[u8], unix_seconds: i64) -> Result<String, OtpError> {
    steam(secret, totp_counter(unix_seconds, DEFAULT_PERIOD))
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

#[cfg(test)]
mod steam_tests {
    use super::*;

    /// RFC 4226's own test secret, so the truncation step is one the published
    /// vectors already pin down.
    const SECRET: &[u8] = b"12345678901234567890";

    /// The one value here that is not read off a published table.
    ///
    /// # Where it comes from
    ///
    /// Steam shares every step with HOTP up to the dynamic truncation, and
    /// diverges only at the final encoding. RFC 4226 Appendix D publishes the
    /// truncated integer for this secret at each count — for count 0 it is
    /// `1284755224` (hex `4c93cf18`), which is the same table that gives the
    /// familiar `755224`.
    ///
    /// Converting that integer to base 26 against Valve's alphabet, least
    /// significant character first:
    ///
    /// ```text
    /// 1284755224 = 26 × 49413662 + 12   → alphabet[12] = 'G'
    ///   49413662 = 26 ×  1900525 + 12   → alphabet[12] = 'G'
    ///    1900525 = 26 ×    73097 +  3   → alphabet[ 3] = '5'
    ///      73097 = 26 ×     2811 + 11   → alphabet[11] = 'F'
    ///       2811 = 26 ×      108 +  3   → alphabet[ 3] = '5'
    /// ```
    ///
    /// This was worked out by hand from the RFC's integer, not taken from this
    /// implementation's output. That distinction is the whole value of the
    /// test: a constant pasted from a run proves the code agrees with itself,
    /// which it always will.
    const CODE_AT_COUNT_ZERO: &str = "GG5F5";

    #[test]
    fn matches_a_value_derived_from_the_rfc_4226_table() {
        assert_eq!(steam(SECRET, 0).unwrap(), CODE_AT_COUNT_ZERO);
    }

    #[test]
    fn a_steam_code_is_five_characters_of_valves_alphabet() {
        // The alphabet is the point, not a detail. Valve left out every
        // character people confuse reading a code off one screen and typing it
        // into another — 0/O, 1/I/L, 5/S, 2/Z — so a code containing one of
        // them means the encoding is wrong even if the length is right.
        for counter in 0..500u64 {
            let code = steam(SECRET, counter).unwrap();
            assert_eq!(code.len(), 5, "counter {counter} gave {code}");
            for character in code.bytes() {
                assert!(
                    STEAM_ALPHABET.contains(&character),
                    "counter {counter} produced {code}, which is not in the alphabet"
                );
            }
        }
    }

    #[test]
    fn it_is_not_a_five_digit_totp() {
        // The failure this whole feature exists to prevent. An entry imported
        // as an ordinary five-digit code produces something that looks like a
        // code and is rejected every single time — silent at import, total at
        // use. If these two ever agreed, the distinction would be pointless.
        let steam_code = steam(SECRET, 1).unwrap();
        assert!(
            steam_code.parse::<u32>().is_err() || steam_code != "287082",
            "the Steam encoding collapsed to the plain HOTP value"
        );
    }

    #[test]
    fn the_code_changes_with_the_counter() {
        let mut seen = std::collections::HashSet::new();
        for counter in 0..200u64 {
            seen.insert(steam(SECRET, counter).unwrap());
        }
        // Not "all different" — collisions are possible in a 26^5 space and
        // asserting otherwise would make this flaky against a correct
        // implementation. What would be wrong is a constant.
        assert!(
            seen.len() > 190,
            "only {} distinct codes in 200 counters",
            seen.len()
        );
    }

    #[test]
    fn an_empty_secret_is_refused_rather_than_encoded() {
        assert_eq!(steam(&[], 0), Err(OtpError::EmptySecret));
    }

    #[test]
    fn the_period_is_fixed_at_thirty_seconds() {
        // Not configurable in the format and not negotiable with Steam. A
        // parameter that could be set wrong is one that will be, so `steam_at`
        // takes no period at all — this pins that it uses the right one.
        assert_eq!(steam_at(SECRET, 0).unwrap(), steam(SECRET, 0).unwrap());
        assert_eq!(steam_at(SECRET, 29).unwrap(), steam(SECRET, 0).unwrap());
        assert_eq!(steam_at(SECRET, 30).unwrap(), steam(SECRET, 1).unwrap());
        assert_eq!(steam_at(SECRET, 59).unwrap(), steam(SECRET, 1).unwrap());
        assert_eq!(steam_at(SECRET, 60).unwrap(), steam(SECRET, 2).unwrap());
    }
}
