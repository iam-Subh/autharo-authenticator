//! Base32 decoding for OTP secrets (FR-09).
//!
//! RFC 4648 alphabet. Accepts input with and without padding, tolerates the
//! spacing and lowercasing that users produce when they retype a secret by
//! hand, and rejects anything else with a reason the user interface can show.

use core::fmt;
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Why a secret could not be decoded. Every variant carries enough detail to
/// build a message that names the problem, as FR-09 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base32Error {
    /// The secret held no Base32 symbols at all.
    Empty,
    /// A character outside the RFC 4648 alphabet.
    InvalidCharacter { character: char, position: usize },
    /// A `=` appeared before the end of the secret.
    MisplacedPadding { position: usize },
    /// Padding was used, but the padded length is not a multiple of 8.
    InvalidPadding { length: usize },
    /// A symbol count that no Base32 encoder can produce.
    InvalidLength { length: usize },
}

impl fmt::Display for Base32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "The secret is empty."),
            Self::InvalidCharacter {
                character,
                position,
            } => write!(
                f,
                "The secret contains '{character}' at position {}, which is not a Base32 \
                 character. Base32 uses the letters A to Z and the digits 2 to 7.",
                position + 1
            ),
            Self::MisplacedPadding { position } => write!(
                f,
                "The secret contains '=' at position {}, before the end. Padding may only \
                 appear last.",
                position + 1
            ),
            Self::InvalidPadding { length } => write!(
                f,
                "The secret is padded to {length} characters. A padded secret must be a \
                 multiple of 8 characters."
            ),
            Self::InvalidLength { length } => write!(
                f,
                "The secret holds {length} Base32 characters, which is not a length Base32 \
                 can produce."
            ),
        }
    }
}

impl std::error::Error for Base32Error {}

fn symbol_value(c: char) -> Option<u8> {
    match c {
        'A'..='Z' => Some(c as u8 - b'A'),
        'a'..='z' => Some(c as u8 - b'a'),
        '2'..='7' => Some(c as u8 - b'2' + 26),
        _ => None,
    }
}

/// Removes separators and padding and uppercases the remainder.
///
/// The result is the canonical form to store in `EntryPayload.secret`.
pub fn normalize(input: &str) -> Result<Zeroizing<String>, Base32Error> {
    let symbols = collect_symbols(input)?;
    let mut out = String::with_capacity(symbols.len());
    for value in symbols.iter() {
        out.push(ALPHABET[*value as usize] as char);
    }
    Ok(Zeroizing::new(out))
}

/// Decodes a Base32 secret into key bytes.
pub fn decode(input: &str) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
    let symbols = collect_symbols(input)?;

    let mut out = Vec::with_capacity(symbols.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for value in symbols.iter() {
        buffer = (buffer << 5) | u16::from(*value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // Any remaining bits are the encoder's zero padding. Real exports are not
    // always canonical here, so leftover bits are discarded rather than
    // rejected. Failing on this would reject secrets that work elsewhere.
    Ok(Zeroizing::new(out))
}

/// Encodes key bytes as unpadded Base32. Used by the QR export (FR-30).
pub fn encode(input: &[u8]) -> Zeroizing<String> {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for byte in input {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
            buffer &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    Zeroizing::new(out)
}

/// Validates the input and returns the 5-bit symbol values it holds.
fn collect_symbols(input: &str) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
    let mut symbols: Vec<u8> = Vec::with_capacity(input.len());
    let mut padded_length = 0usize;
    let mut first_padding: Option<usize> = None;

    for (position, c) in input.char_indices() {
        match c {
            ' ' | '\t' | '\r' | '\n' | '-' => continue,
            '=' => {
                first_padding.get_or_insert(position);
                padded_length += 1;
            }
            _ => {
                if let Some(position) = first_padding {
                    return Err(Base32Error::MisplacedPadding { position });
                }
                match symbol_value(c) {
                    Some(value) => {
                        symbols.push(value);
                        padded_length += 1;
                    }
                    None => {
                        return Err(Base32Error::InvalidCharacter {
                            character: c,
                            position,
                        });
                    }
                }
            }
        }
    }

    if symbols.is_empty() {
        return Err(Base32Error::Empty);
    }
    if first_padding.is_some() && !padded_length.is_multiple_of(8) {
        return Err(Base32Error::InvalidPadding {
            length: padded_length,
        });
    }
    if !matches!(symbols.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return Err(Base32Error::InvalidLength {
            length: symbols.len(),
        });
    }
    Ok(Zeroizing::new(symbols))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10 test vectors.
    #[test]
    fn rfc4648_vectors() {
        let cases: &[(&str, &str)] = &[
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(
                encode(plain.as_bytes()).as_str(),
                encoded.trim_end_matches('=')
            );
            assert_eq!(decode(encoded).unwrap().as_slice(), plain.as_bytes());
            assert_eq!(
                decode(encoded.trim_end_matches('=')).unwrap().as_slice(),
                plain.as_bytes(),
                "unpadded input must decode the same"
            );
        }
    }

    #[test]
    fn accepts_lowercase_and_separators() {
        let expected = b"12345678901234567890";
        assert_eq!(
            decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                .unwrap()
                .as_slice(),
            expected
        );
        assert_eq!(
            decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq")
                .unwrap()
                .as_slice(),
            expected
        );
        assert_eq!(
            decode("gezd gnbv gy3t qojq-gezd-gnbv-gy3t-qojq")
                .unwrap()
                .as_slice(),
            expected
        );
    }

    #[test]
    fn normalize_produces_canonical_form() {
        assert_eq!(normalize("mzxw 6yq=").unwrap().as_str(), "MZXW6YQ");
    }

    #[test]
    fn rejects_invalid_character_and_names_it() {
        let err = decode("MZXW6YT1").unwrap_err();
        assert_eq!(
            err,
            Base32Error::InvalidCharacter {
                character: '1',
                position: 7
            }
        );
        assert!(err.to_string().contains('1'));
    }

    #[test]
    fn rejects_misplaced_padding() {
        assert!(matches!(
            decode("MZ=XW6YQ").unwrap_err(),
            Base32Error::MisplacedPadding { .. }
        ));
    }

    #[test]
    fn rejects_impossible_length() {
        assert!(matches!(
            decode("MZX").unwrap_err(),
            Base32Error::InvalidLength { length: 3 }
        ));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(decode("   ").unwrap_err(), Base32Error::Empty);
    }
}
