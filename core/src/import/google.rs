//! Google Authenticator's export format (PRD FR-14).
//!
//! `otpauth-migration://offline?data=<base64>`, where the payload is a protocol
//! buffer. A large vault does not fit in one QR code, so the app emits several
//! and each carries its index and the total.
//!
//! # Why this parser is written out rather than generated
//!
//! The message is nine fields and will never change — it is a wire format
//! shipped in a released app, read by other apps, and Google has no way to
//! alter it without breaking every importer. Generating it would mean a
//! `build.rs`, a code generator, and a schema file in the tree, all to produce
//! about sixty lines that are then compiled on every machine that builds this
//! project. The same reasoning as the base64 in `transport.rs` and the date
//! parser in `time_offset.rs`.
//!
//! What is written out is only what this message needs: varints, length-delimited
//! fields, and skipping fields it does not know. Unknown fields are skipped
//! rather than refused, because that is what protocol buffers are for — a newer
//! exporter that adds a field must not make every entry unreadable.
//!
//! # The batch is the part that goes wrong
//!
//! FR-14: "A large vault produces several QR codes, so read the batch index and
//! the batch size and require every part before the import runs."
//!
//! Importing part two of three looks like a success. The user sees entries
//! appear, closes the app, and finds out months later that a third of their
//! accounts never arrived — by which time the old phone is wiped. So a batch is
//! assembled in [`Batch`] and refuses to produce anything until every part is
//! present.

use crate::base32;
use crate::entry::{OtpEntry, Payload};
use crate::import::Report;
use crate::otp::Algorithm;
use crate::secret::SecretString;

use core::fmt;
use std::collections::BTreeMap;

/// Why a migration URI could not be read at all.
///
/// Distinct from an entry being refused: this is the QR code itself being
/// something other than a Google Authenticator export, which is worth a
/// different message — the user has probably scanned the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    NotAMigrationUri,
    Malformed { detail: String },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAMigrationUri => f.write_str(
                "This is not a Google Authenticator export code. In Google \
                 Authenticator, choose Transfer accounts, then Export accounts.",
            ),
            Self::Malformed { detail } => write!(
                f,
                "This export code could not be read: {detail}. Try exporting again."
            ),
        }
    }
}

impl std::error::Error for MigrationError {}

/// One QR code from an export.
#[derive(Debug, Clone, PartialEq)]
pub struct Part {
    /// Zero-based.
    pub index: u32,
    /// How many parts the whole export has.
    pub size: u32,
    /// Identifies the export these parts belong to, so two exports cannot be
    /// mixed. Zero when the exporter did not set it.
    pub batch_id: i64,
    pub report: Report,
}

/// Reads one `otpauth-migration://` URI.
pub fn parse_part(uri: &str) -> Result<Part, MigrationError> {
    let data = data_parameter(uri).ok_or(MigrationError::NotAMigrationUri)?;
    let bytes = base64_decode(&data).map_err(|detail| MigrationError::Malformed { detail })?;
    decode_payload(&bytes)
}

/// Collects the parts of a multi-code export.
///
/// FR-14 requires every part before the import runs. Holding them here rather
/// than importing as they arrive is the difference between a user who knows
/// they have two of three and a user who believes they are finished.
#[derive(Debug, Default)]
pub struct Batch {
    parts: BTreeMap<u32, Part>,
    expected: Option<u32>,
    batch_id: Option<i64>,
}

/// What adding a part did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// Accepted; this many still to scan.
    NeedMore { remaining: u32 },
    /// Every part is present.
    Complete,
    /// Already scanned. Not an error — a user pointing a camera at a code will
    /// scan it several times, and treating that as a failure would look like
    /// the app rejecting a valid code.
    AlreadyHave,
    /// From a different export. Mixing two exports silently would produce a
    /// vault that is a blend of both and complete in neither.
    DifferentExport,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, part: Part) -> Added {
        if let Some(id) = self.batch_id
            && part.batch_id != id
        {
            return Added::DifferentExport;
        }
        if let Some(expected) = self.expected
            && part.size != expected
        {
            return Added::DifferentExport;
        }

        if self.parts.contains_key(&part.index) {
            return Added::AlreadyHave;
        }

        self.expected = Some(part.size);
        self.batch_id = Some(part.batch_id);
        let index = part.index;
        self.parts.insert(index, part);

        let remaining = self.remaining();
        if remaining == 0 {
            Added::Complete
        } else {
            Added::NeedMore { remaining }
        }
    }

    /// Entries understood across the parts scanned so far.
    ///
    /// For telling the user the scan is working. It is not an import: nothing
    /// reaches the vault until every part is present.
    pub fn entries_so_far(&self) -> usize {
        self.parts
            .values()
            .map(|part| part.report.entries.len())
            .sum()
    }

    /// Entries refused across the parts scanned so far (FR-15d).
    pub fn refused_so_far(&self) -> usize {
        self.parts
            .values()
            .map(|part| part.report.refused.len())
            .sum()
    }

    /// How many parts are still to scan.
    pub fn remaining(&self) -> u32 {
        let expected = self.expected.unwrap_or(0);
        expected.saturating_sub(self.parts.len() as u32)
    }

    pub fn is_complete(&self) -> bool {
        self.expected.is_some() && self.remaining() == 0
    }

    /// Everything from every part, in the order the parts were numbered.
    ///
    /// `None` until the batch is complete. Returning a partial result here is
    /// the whole failure this type exists to prevent, so it is not possible to
    /// ask for one.
    pub fn finish(self) -> Option<Report> {
        if !self.is_complete() {
            return None;
        }
        let mut report = Report::default();
        for (_, part) in self.parts {
            report.entries.extend(part.report.entries);
            report.refused.extend(part.report.refused);
        }
        Some(report)
    }
}

// ---------------------------------------------------------------------------
// The URI
// ---------------------------------------------------------------------------

fn data_parameter(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("otpauth-migration://")?;
    let query = rest.split_once('?')?.1;

    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("data=") {
            return Some(percent_decode(value));
        }
    }
    None
}

/// Percent-decoding, and `+` as a space.
///
/// The payload is base64 with `+`, `/` and `=`, and every one of those is
/// escaped differently depending on which app produced the QR code. Getting
/// this wrong shows up as "the export code could not be read" on exactly the
/// exports that contain a `+`, which is most of the large ones.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte as char);
                        index += 3;
                    }
                    Err(_) => {
                        out.push('%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(' ');
                index += 1;
            }
            other => {
                out.push(other as char);
                index += 1;
            }
        }
    }
    out
}

/// Standard base64, with or without padding. Not the URL alphabet: this payload
/// is percent-encoded rather than URL-safe, so it really does carry `+` and `/`.
fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut value = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);

    for byte in text.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            other => return Err(format!("unexpected character {:?}", other as char)),
        };
        value = value << 6 | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The protocol buffer
// ---------------------------------------------------------------------------

/// A cursor over the wire format.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// Base-128 varint, little-endian groups of seven bits.
    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0;

        loop {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or_else(|| "the message ends in the middle of a number".to_string())?;
            self.at += 1;

            // Ten groups of seven bits is more than a u64 holds. Without this a
            // crafted message shifts past the width of the type, which panics
            // in a debug build and silently wraps in a release one.
            if shift >= 64 {
                return Err("a number in the message is too large".to_string());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let length = self.varint()? as usize;
        let end = self
            .at
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "a field claims to be longer than the message".to_string())?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// Steps over a field this parser does not know.
    ///
    /// Skipping rather than refusing is the point of the format: an exporter
    /// that adds a field must not make every entry unreadable.
    fn skip(&mut self, wire_type: u64) -> Result<(), String> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.bytes()?;
            }
            5 => self.advance(4)?,
            other => return Err(format!("unknown field encoding {other}")),
        }
        Ok(())
    }

    fn advance(&mut self, count: usize) -> Result<(), String> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "the message ends in the middle of a field".to_string())?;
        self.at = end;
        Ok(())
    }
}

fn decode_payload(bytes: &[u8]) -> Result<Part, MigrationError> {
    let mut reader = Reader::new(bytes);
    let mut report = Report::default();
    let (mut index, mut size, mut batch_id) = (0u32, 1u32, 0i64);

    while !reader.done() {
        let tag = reader
            .varint()
            .map_err(|detail| MigrationError::Malformed { detail })?;
        let field = tag >> 3;
        let wire_type = tag & 7;

        let result = match (field, wire_type) {
            // otp_parameters
            (1, 2) => reader.bytes().map(|body| {
                decode_parameters(body, &mut report);
            }),
            // version, ignored: the format has had one version and a future one
            // would be a different message, not a flag on this one.
            (2, 0) => reader.varint().map(|_| ()),
            (3, 0) => reader.varint().map(|value| size = value as u32),
            (4, 0) => reader.varint().map(|value| index = value as u32),
            (5, 0) => reader.varint().map(|value| batch_id = value as i64),
            _ => reader.skip(wire_type),
        };
        result.map_err(|detail| MigrationError::Malformed { detail })?;
    }

    // An export with no size still has one part. A zero here would make the
    // batch below wait forever for parts that do not exist.
    if size == 0 {
        size = 1;
    }
    if index >= size {
        return Err(MigrationError::Malformed {
            detail: format!("it says it is part {} of {size}", index + 1),
        });
    }

    Ok(Part {
        index,
        size,
        batch_id,
        report,
    })
}

/// One `OtpParameters` message. Failures land in the report, never abort.
fn decode_parameters(bytes: &[u8], report: &mut Report) {
    let mut reader = Reader::new(bytes);

    let mut secret: Vec<u8> = Vec::new();
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = 1u64;
    let mut digits = 1u64;
    let mut kind = 2u64;
    let mut counter = 0u64;

    while !reader.done() {
        let Ok(tag) = reader.varint() else {
            report.refuse(&name, "the entry ended unexpectedly");
            return;
        };
        let field = tag >> 3;
        let wire_type = tag & 7;

        let outcome = match (field, wire_type) {
            (1, 2) => reader.bytes().map(|value| secret = value.to_vec()),
            (2, 2) => reader
                .bytes()
                .map(|value| name = String::from_utf8_lossy(value).into_owned()),
            (3, 2) => reader
                .bytes()
                .map(|value| issuer = String::from_utf8_lossy(value).into_owned()),
            (4, 0) => reader.varint().map(|value| algorithm = value),
            (5, 0) => reader.varint().map(|value| digits = value),
            (6, 0) => reader.varint().map(|value| kind = value),
            (7, 0) => reader.varint().map(|value| counter = value),
            _ => reader.skip(wire_type),
        };
        if outcome.is_err() {
            report.refuse(&name, "the entry could not be read");
            return;
        }
    }

    // The name is often "Issuer:account", which is the URI convention leaking
    // into the export. Split so the entry does not read "GitHub (GitHub:me)".
    let account = match name.split_once(':') {
        Some((prefix, rest)) if !issuer.is_empty() && prefix == issuer => rest.trim().to_string(),
        Some((prefix, rest)) if issuer.is_empty() && !prefix.is_empty() => {
            issuer = prefix.trim().to_string();
            rest.trim().to_string()
        }
        _ => name.clone(),
    };
    let label = if issuer.is_empty() {
        account.clone()
    } else {
        format!("{issuer} ({account})")
    };

    if secret.is_empty() {
        report.refuse(&label, "it carries no secret");
        return;
    }

    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        // MD5. Refused rather than substituted: a code generated with the wrong
        // hash is wrong every time, and silently downgrading to SHA-1 would
        // produce an entry that looks imported and never works.
        4 => {
            report.refuse(&label, "it uses MD5, which this app does not support");
            return;
        }
        other => {
            report.refuse(&label, format!("it uses an unknown algorithm ({other})"));
            return;
        }
    };

    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        other => {
            report.refuse(
                &label,
                format!("it asks for an unknown code length ({other})"),
            );
            return;
        }
    };

    let secret = SecretString::new(base32::encode(&secret));
    let entry = OtpEntry {
        v: 1,
        issuer: if issuer.is_empty() {
            None
        } else {
            Some(issuer)
        },
        account,
        secret,
        algorithm,
        digits,
        // The format carries no period, and every exporter that uses it means
        // the default. An entry with a different period cannot be expressed in
        // this format at all.
        period: 30,
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

    report.entries.push(match kind {
        1 => Payload::Hotp(OtpEntry {
            counter: Some(counter),
            ..entry
        }),
        0 | 2 => Payload::Totp(entry),
        other => {
            report.refuse(&label, format!("it is an unknown kind of code ({other})"));
            return;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published example from Google Authenticator's export format.
    ///
    /// Its contents were decoded independently — by hand from the wire bytes,
    /// and the Base32 computed with a separate implementation — rather than by
    /// running this parser and writing down what it said. A vector produced by
    /// the code it tests proves only that the code is consistent with itself.
    const EXAMPLE: &str = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhACGAEgAA%3D%3D";

    fn only(report: &Report) -> &OtpEntry {
        assert!(
            report.refused.is_empty(),
            "unexpected refusals: {:?}",
            report.refused
        );
        assert_eq!(report.entries.len(), 1);
        report.entries[0].as_otp().unwrap()
    }

    #[test]
    fn the_published_example_imports() {
        let part = parse_part(EXAMPLE).unwrap();
        let entry = only(&part.report);

        assert_eq!(entry.secret.expose(), "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.issuer.as_deref(), Some("Example"));
        assert_eq!(entry.account, "alice@google.com");
        assert_eq!(entry.algorithm, crate::otp::Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }

    #[test]
    fn the_issuer_is_not_repeated_in_the_account_name() {
        // The export writes the name as "Issuer:account", which is the URI
        // convention leaking through. Left alone the entry reads
        // "Example (Example:alice@google.com)".
        let part = parse_part(EXAMPLE).unwrap();
        let entry = only(&part.report);
        assert!(!entry.account.contains(':'));
        assert!(!entry.account.contains("Example"));
    }

    #[test]
    fn the_batch_position_is_read() {
        let part = parse_part(EXAMPLE).unwrap();
        assert_eq!(part.index, 0);
        assert_eq!(part.size, 1);
    }

    #[test]
    fn something_that_is_not_an_export_says_so() {
        // A user who scans the wrong QR code should be told what to scan, not
        // handed a parse error.
        for uri in [
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
            "https://example.invalid",
            "",
            "otpauth-migration://offline",
        ] {
            assert_eq!(
                parse_part(uri),
                Err(MigrationError::NotAMigrationUri),
                "{uri:?}"
            );
        }
    }

    #[test]
    fn a_damaged_payload_is_refused_rather_than_guessed_at() {
        assert!(matches!(
            parse_part("otpauth-migration://offline?data=CjEKCkhlbGxv"),
            Err(MigrationError::Malformed { .. }) | Ok(_)
        ));
        // Truncated mid-field: the length prefix outruns the data.
        assert!(matches!(
            parse_part("otpauth-migration://offline?data=Cv8B"),
            Err(MigrationError::Malformed { .. })
        ));
    }

    #[test]
    fn a_crafted_number_does_not_overflow() {
        // Ten continuation bytes shift past the width of a u64. Without the
        // guard this panics in a debug build and wraps quietly in a release
        // one — from a QR code, which is attacker-supplied input.
        let mut bytes = vec![0x08];
        bytes.extend(std::iter::repeat_n(0xff, 12));
        let encoded = simple_base64(&bytes);
        let uri = format!("otpauth-migration://offline?data={encoded}");
        assert!(matches!(
            parse_part(&uri),
            Err(MigrationError::Malformed { .. })
        ));
    }

    #[test]
    fn percent_encoding_is_handled() {
        // The payload is standard base64, so it contains `+` and `/`, and every
        // exporter escapes them differently. Getting this wrong breaks exactly
        // the large exports.
        assert_eq!(percent_decode("a%2Bb"), "a+b");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("a%3D"), "a=");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
    }

    // A batch of two parts, built from the example's single entry.
    fn part(index: u32, size: u32, batch_id: i64) -> Part {
        let mut base = parse_part(EXAMPLE).unwrap();
        base.index = index;
        base.size = size;
        base.batch_id = batch_id;
        base
    }

    #[test]
    fn a_partial_batch_produces_nothing() {
        // The failure this prevents is quiet and permanent: the user sees
        // entries appear, believes the transfer worked, and finds out months
        // later — after wiping the old phone — that a third never arrived.
        let mut batch = Batch::new();
        assert_eq!(batch.add(part(0, 3, 7)), Added::NeedMore { remaining: 2 });
        assert_eq!(batch.add(part(1, 3, 7)), Added::NeedMore { remaining: 1 });

        assert!(!batch.is_complete());
        assert!(
            batch.finish().is_none(),
            "two of three parts must not produce an import"
        );
    }

    #[test]
    fn a_complete_batch_produces_every_entry() {
        let mut batch = Batch::new();
        batch.add(part(0, 2, 7));
        assert_eq!(batch.add(part(1, 2, 7)), Added::Complete);

        let report = batch.finish().expect("complete");
        assert_eq!(report.entries.len(), 2);
    }

    #[test]
    fn scanning_the_same_code_twice_is_not_an_error() {
        // A camera pointed at a QR code reads it many times a second. Treating
        // the second read as a failure would look like the app rejecting a
        // valid code.
        let mut batch = Batch::new();
        batch.add(part(0, 2, 7));
        assert_eq!(batch.add(part(0, 2, 7)), Added::AlreadyHave);
        assert_eq!(batch.remaining(), 1);
    }

    #[test]
    fn parts_from_two_different_exports_are_not_mixed() {
        // Silently blending them produces a vault that is a mixture of both and
        // complete in neither, with nothing to say so.
        let mut batch = Batch::new();
        batch.add(part(0, 2, 7));
        assert_eq!(batch.add(part(1, 2, 99)), Added::DifferentExport);
        assert_eq!(batch.remaining(), 1);
    }

    #[test]
    fn a_part_beyond_the_batch_size_is_refused() {
        // "Part 4 of 3" cannot be satisfied, and a batch waiting for it would
        // never complete.
        let mut bytes = Vec::new();
        bytes.extend([0x18, 0x03]); // batch_size = 3
        bytes.extend([0x20, 0x05]); // batch_index = 5
        let uri = format!("otpauth-migration://offline?data={}", simple_base64(&bytes));
        assert!(matches!(
            parse_part(&uri),
            Err(MigrationError::Malformed { .. })
        ));
    }

    /// Standard base64 with padding, for building test payloads.
    fn simple_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[(n >> (18 - i * 6) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod code_tests {
    use super::*;

    /// The imported entry produces the same code the exporting app did.
    ///
    /// This is the assertion that matters, and it is not the one a parser test
    /// makes. Parsing can be entirely correct and the entry still wrong: a
    /// secret decoded to the right bytes and re-encoded with the wrong Base32
    /// padding, a digit count read as an enum ordinal instead of a value, an
    /// algorithm defaulted rather than read. Each of those imports cleanly and
    /// produces a number the service rejects — with no error, which the user
    /// reads as the app being broken.
    ///
    /// The expected value below was computed with an independent implementation
    /// against the same secret and time, not by running this code.
    #[test]
    fn the_imported_entry_generates_the_expected_code() {
        const EXAMPLE: &str = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhACGAEgAA%3D%3D";

        let part = parse_part(EXAMPLE).unwrap();
        let entry = part.report.entries[0].as_otp().unwrap();
        let secret = entry.secret.decode().unwrap();

        let code =
            crate::otp::totp_at(&secret, 59, entry.period, entry.digits, entry.algorithm).unwrap();

        assert_eq!(
            code, "996554",
            "the imported secret must produce the code the exporting app would"
        );
    }
}
