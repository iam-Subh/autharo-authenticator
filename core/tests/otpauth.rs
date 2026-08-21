//! Parser tests for the `otpauth://` URI format (FR-10, FR-13).
//!
//! The happy-path cases are taken from what Google Authenticator, Aegis, and
//! 2FAS actually emit. The failure cases check that the reason reaches the
//! caller, which is what FR-09 and FR-13 need in order to show it.

use authcore::otp::{Algorithm, OtpKind};
use authcore::otpauth::{OtpAuthError, OtpAuthUri, parse_lines};

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn parses_the_common_google_form() {
    let uri = OtpAuthUri::parse(&format!(
        "otpauth://totp/GitHub:rupsa%40example.com?secret={SECRET}&issuer=GitHub"
    ))
    .unwrap();

    assert_eq!(uri.kind, OtpKind::Totp);
    assert_eq!(uri.issuer.as_deref(), Some("GitHub"));
    assert_eq!(uri.account, "rupsa@example.com");
    assert_eq!(uri.secret.expose(), SECRET);
    assert_eq!(uri.algorithm, Algorithm::Sha1);
    assert_eq!(uri.digits, 6);
    assert_eq!(uri.period, 30);
    assert_eq!(uri.counter, None);
}

#[test]
fn applies_the_documented_defaults() {
    let uri = OtpAuthUri::parse(&format!("otpauth://totp/Example?secret={SECRET}")).unwrap();
    assert_eq!(uri.issuer, None);
    assert_eq!(uri.account, "Example");
    assert_eq!(uri.algorithm, Algorithm::Sha1);
    assert_eq!(uri.digits, 6);
    assert_eq!(uri.period, 30);
}

#[test]
fn reads_every_optional_parameter() {
    let uri = OtpAuthUri::parse(&format!(
        "otpauth://totp/ACME%20Co:john?secret={SECRET}&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"
    ))
    .unwrap();

    assert_eq!(uri.issuer.as_deref(), Some("ACME Co"));
    assert_eq!(uri.account, "john");
    assert_eq!(uri.algorithm, Algorithm::Sha256);
    assert_eq!(uri.digits, 8);
    assert_eq!(uri.period, 60);
}

#[test]
fn parses_hotp_with_a_counter() {
    let uri = OtpAuthUri::parse(&format!(
        "otpauth://hotp/Bank:acct?secret={SECRET}&counter=7"
    ))
    .unwrap();
    assert_eq!(uri.kind, OtpKind::Hotp);
    assert_eq!(uri.counter, Some(7));
}

/// An HOTP entry with a guessed counter would be out of step with the issuer
/// from the first code, so the parser refuses rather than defaulting to zero.
#[test]
fn rejects_hotp_without_a_counter() {
    let err = OtpAuthUri::parse(&format!("otpauth://hotp/Bank:acct?secret={SECRET}")).unwrap_err();
    assert_eq!(err, OtpAuthError::MissingCounter);
    assert!(err.to_string().contains("counter"));
}

#[test]
fn tolerates_scheme_case_and_surrounding_space() {
    let uri = OtpAuthUri::parse(&format!("  OTPAUTH://TOTP/Example?secret={SECRET}  ")).unwrap();
    assert_eq!(uri.account, "Example");
    assert_eq!(uri.kind, OtpKind::Totp);
}

/// Some exports encode the colon, some do not, and some leave a space after it.
#[test]
fn tolerates_label_variations() {
    for label in [
        "GitHub:rupsa",
        "GitHub%3Arupsa",
        "GitHub:%20rupsa",
        "/GitHub:rupsa",
    ] {
        let uri = OtpAuthUri::parse(&format!("otpauth://totp/{label}?secret={SECRET}")).unwrap();
        assert_eq!(uri.issuer.as_deref(), Some("GitHub"), "label {label}");
        assert_eq!(uri.account, "rupsa", "label {label}");
    }
}

/// The Key URI format carries the issuer in two places. When they disagree the
/// parameter is authoritative.
#[test]
fn the_issuer_parameter_beats_the_label_prefix() {
    let uri = OtpAuthUri::parse(&format!(
        "otpauth://totp/Old%20Name:acct?secret={SECRET}&issuer=New%20Name"
    ))
    .unwrap();
    assert_eq!(uri.issuer.as_deref(), Some("New Name"));
}

#[test]
fn accepts_a_secret_with_padding_and_spaces() {
    let uri = OtpAuthUri::parse("otpauth://totp/Example?secret=mzxw%206yq%3D").unwrap();
    assert_eq!(uri.secret.expose(), "MZXW6YQ");
}

#[test]
fn reports_the_reason_a_uri_is_unusable() {
    assert_eq!(
        OtpAuthUri::parse("https://example.com").unwrap_err(),
        OtpAuthError::NotOtpAuth
    );
    assert!(matches!(
        OtpAuthUri::parse(&format!("otpauth://motp/Example?secret={SECRET}")).unwrap_err(),
        OtpAuthError::UnknownType { .. }
    ));
    assert_eq!(
        OtpAuthUri::parse("otpauth://totp/Example").unwrap_err(),
        OtpAuthError::MissingSecret
    );
    assert!(matches!(
        OtpAuthUri::parse("otpauth://totp/Example?secret=NOT!VALID").unwrap_err(),
        OtpAuthError::InvalidSecret(_)
    ));
    assert_eq!(
        OtpAuthUri::parse(&format!("otpauth://totp/?secret={SECRET}")).unwrap_err(),
        OtpAuthError::MissingAccount
    );
    assert!(matches!(
        OtpAuthUri::parse(&format!("otpauth://totp/Example?secret={SECRET}&digits=x")).unwrap_err(),
        OtpAuthError::InvalidParameter { name: "digits", .. }
    ));
}

/// FR-04 and FR-05 bound what the application will store, and a URI outside
/// those bounds must be refused at import rather than at code generation.
#[test]
fn rejects_parameters_outside_the_supported_range() {
    for (query, needle) in [("digits=10", "digits"), ("period=600", "period")] {
        let err = OtpAuthUri::parse(&format!("otpauth://totp/Example?secret={SECRET}&{query}"))
            .unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "message for {query} should name the problem: {err}"
        );
    }
}

/// The URI produced by `to_uri` must parse back to the same entry, since the
/// QR export in FR-30 relies on other applications reading it.
#[test]
fn round_trips_through_to_uri() {
    let originals = [
        format!(
            "otpauth://totp/ACME%20Co:john%40acme.test?secret={SECRET}&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60"
        ),
        format!("otpauth://hotp/Bank:acct?secret={SECRET}&issuer=Bank&counter=42"),
        format!("otpauth://totp/plain?secret={SECRET}"),
    ];
    for original in originals {
        let parsed = OtpAuthUri::parse(&original).unwrap();
        let rebuilt = OtpAuthUri::parse(&parsed.to_uri()).unwrap();
        assert_eq!(parsed, rebuilt, "round trip changed the entry: {original}");
    }
}

/// A parsed URI must produce the same code as the RFC 6238 vector for the same
/// key, which proves the parser hands the engine the bytes it expects.
#[test]
fn generates_the_rfc_code_after_parsing() {
    let uri = OtpAuthUri::parse(&format!(
        "otpauth://totp/Example?secret={SECRET}&digits=8&period=30"
    ))
    .unwrap();
    assert_eq!(uri.code_at(59).unwrap(), "94287082");
}

/// One URI per line is the plain-text half of the first row of section 8.2.1.
#[test]
fn parses_a_file_of_one_uri_per_line() {
    let file = format!(
        "# exported list\n\
         otpauth://totp/One?secret={SECRET}\n\
         \n\
         not a uri\n\
         otpauth://totp/Two?secret={SECRET}\n"
    );
    let results = parse_lines(&file);

    assert_eq!(results.len(), 3, "the comment and blank line are skipped");
    assert_eq!(results[0].0, 2);
    assert_eq!(results[0].1.as_ref().unwrap().account, "One");
    assert_eq!(results[1].0, 4);
    assert!(results[1].1.is_err(), "line 4 is not a URI");
    assert_eq!(results[2].0, 5);
    assert_eq!(results[2].1.as_ref().unwrap().account, "Two");
}
