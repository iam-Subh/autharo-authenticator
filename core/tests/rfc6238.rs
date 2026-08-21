//! RFC 6238 Appendix B test vectors (FR-01, FR-03, FR-04).
//!
//! The RFC publishes six moments in time against three hash algorithms, all at
//! 8 digits with a 30 second period. Passing this file is the other half of the
//! S1 exit criterion in section 18 of the PRD.

use authcore::base32;
use authcore::otp::{Algorithm, totp_at, totp_counter, totp_remaining_seconds};

/// Appendix B uses one seed per algorithm, each the ASCII digits repeated to
/// the block size of that hash.
const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

fn seed_for(algorithm: Algorithm) -> &'static [u8] {
    match algorithm {
        Algorithm::Sha1 => SEED_SHA1,
        Algorithm::Sha256 => SEED_SHA256,
        Algorithm::Sha512 => SEED_SHA512,
    }
}

/// Appendix B, in order: the time in seconds, then the SHA-1, SHA-256, and
/// SHA-512 codes for that time.
const VECTORS: [(i64, &str, &str, &str); 6] = [
    (59, "94287082", "46119246", "90693936"),
    (1_111_111_109, "07081804", "68084774", "25091201"),
    (1_111_111_111, "14050471", "67062674", "99943326"),
    (1_234_567_890, "89005924", "91819424", "93441116"),
    (2_000_000_000, "69279037", "90698825", "38618901"),
    (20_000_000_000, "65353130", "77737706", "47863826"),
];

#[test]
fn appendix_b_vectors() {
    for (time, sha1, sha256, sha512) in VECTORS {
        for (algorithm, expected) in [
            (Algorithm::Sha1, sha1),
            (Algorithm::Sha256, sha256),
            (Algorithm::Sha512, sha512),
        ] {
            let code = totp_at(seed_for(algorithm), time, 30, 8, algorithm).unwrap();
            assert_eq!(code, expected, "TOTP mismatch for {algorithm} at T={time}");
        }
    }
}

#[test]
fn appendix_b_vectors_through_the_base32_decoder() {
    for (time, sha1, sha256, sha512) in VECTORS {
        for (algorithm, expected) in [
            (Algorithm::Sha1, sha1),
            (Algorithm::Sha256, sha256),
            (Algorithm::Sha512, sha512),
        ] {
            let encoded = base32::encode(seed_for(algorithm));
            let decoded = base32::decode(&encoded).unwrap();
            assert_eq!(decoded.as_slice(), seed_for(algorithm));

            let code = totp_at(&decoded, time, 30, 8, algorithm).unwrap();
            assert_eq!(code, expected, "TOTP mismatch for {algorithm} at T={time}");
        }
    }
}

/// Appendix B lists the time step alongside each moment. T=59 is step 1, and
/// T=20000000000 is step 0x27BC86AA.
#[test]
fn appendix_b_time_steps() {
    assert_eq!(totp_counter(59, 30), 0x0000_0000_0000_0001);
    assert_eq!(totp_counter(1_111_111_109, 30), 0x0000_0000_0235_23EC);
    assert_eq!(totp_counter(1_111_111_111, 30), 0x0000_0000_0235_23ED);
    assert_eq!(totp_counter(1_234_567_890, 30), 0x0000_0000_0273_EF07);
    assert_eq!(totp_counter(2_000_000_000, 30), 0x0000_0000_03F9_40AA);
    assert_eq!(totp_counter(20_000_000_000, 30), 0x0000_0000_27BC_86AA);
}

/// The code must hold still for the whole period and change on the boundary.
#[test]
fn the_code_changes_once_per_period() {
    let seed = SEED_SHA1;
    let at_start = totp_at(seed, 1_111_111_080, 30, 8, Algorithm::Sha1).unwrap();
    let at_end = totp_at(seed, 1_111_111_109, 30, 8, Algorithm::Sha1).unwrap();
    let after = totp_at(seed, 1_111_111_110, 30, 8, Algorithm::Sha1).unwrap();

    assert_eq!(at_start, at_end, "the code must not change inside a period");
    assert_ne!(at_end, after, "the code must change on a period boundary");
    assert_eq!(totp_remaining_seconds(1_111_111_109, 30), 1);
    assert_eq!(totp_remaining_seconds(1_111_111_110, 30), 30);
}

/// FR-38: the stored offset is applied by shifting the reference time, and it
/// must produce the code the server expects rather than the one the wrong
/// device clock would produce.
#[test]
fn a_time_offset_recovers_the_correct_code() {
    let seed = SEED_SHA1;
    let correct = totp_at(seed, 1_111_111_111, 30, 8, Algorithm::Sha1).unwrap();

    // The device clock runs 45 seconds slow, so the stored offset is +45.
    let device_clock = 1_111_111_111 - 45;
    let offset = 45;

    assert_ne!(
        totp_at(seed, device_clock, 30, 8, Algorithm::Sha1).unwrap(),
        correct,
        "the uncorrected clock should land in a different period"
    );
    assert_eq!(
        totp_at(seed, device_clock + offset, 30, 8, Algorithm::Sha1).unwrap(),
        correct
    );
}
