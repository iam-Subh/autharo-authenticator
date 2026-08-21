//! RFC 4226 Appendix D test vectors (FR-02).
//!
//! The RFC publishes one key and the first ten counter values. Passing this
//! file is half of the S1 exit criterion in section 18 of the PRD.

use authcore::base32;
use authcore::otp::{Algorithm, hotp};

/// The Appendix D key, ASCII "12345678901234567890".
const SECRET: &[u8] = b"12345678901234567890";

/// The same key as a user would paste it, to prove the decoder and the engine
/// agree on the bytes between them.
const SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Appendix D, the "HOTP" column, for counters 0 through 9.
const EXPECTED: [&str; 10] = [
    "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
    "520489",
];

#[test]
fn appendix_d_vectors() {
    for (counter, expected) in EXPECTED.iter().enumerate() {
        let code = hotp(SECRET, counter as u64, 6, Algorithm::Sha1).unwrap();
        assert_eq!(&code, expected, "HOTP mismatch at counter {counter}");
    }
}

#[test]
fn appendix_d_vectors_through_the_base32_decoder() {
    let decoded = base32::decode(SECRET_BASE32).unwrap();
    assert_eq!(decoded.as_slice(), SECRET);

    for (counter, expected) in EXPECTED.iter().enumerate() {
        let code = hotp(&decoded, counter as u64, 6, Algorithm::Sha1).unwrap();
        assert_eq!(&code, expected, "HOTP mismatch at counter {counter}");
    }
}

/// The truncation in RFC 4226 section 5.3 keeps the low-order digits, so a
/// wider code shares its tail with a narrower one at the same counter.
#[test]
fn wider_codes_extend_the_same_value() {
    for counter in 0..10u64 {
        let six = hotp(SECRET, counter, 6, Algorithm::Sha1).unwrap();
        let eight = hotp(SECRET, counter, 8, Algorithm::Sha1).unwrap();
        assert_eq!(eight.len(), 8);
        assert!(
            eight.ends_with(&six),
            "8-digit code {eight} should end with the 6-digit code {six}"
        );
    }
}

/// A counter is 8 bytes big-endian, so values above 32 bits must still work.
#[test]
fn accepts_a_large_counter() {
    let code = hotp(SECRET, u64::from(u32::MAX) + 1, 6, Algorithm::Sha1).unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}
