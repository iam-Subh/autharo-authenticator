//! Measuring how wrong this device's clock is (PRD FR-37 to FR-40, OFF-07).
//!
//! # Why this matters more than it looks
//!
//! A TOTP code is a function of the time. A device thirty seconds fast produces
//! codes the service rejects, and the failure carries no explanation: the user
//! sees "invalid code", tries again, sees it again, and concludes the
//! application is broken or their account is compromised. Nothing in the app
//! says "your clock is wrong", because nothing has measured it.
//!
//! That is the one defect in this project that is invisible from inside. Every
//! test passes, every code is generated correctly *for the time the device
//! believes it is*, and the answer is still wrong.
//!
//! # Where the reference comes from
//!
//! FR-37 allows an SNTP server or the sync server's response header. Section 13
//! requires the second: "Include an accurate `Date` header on every response.
//! The client uses it for the time offset."
//!
//! The header is preferred because it is free. Every sync cycle already makes
//! requests, so the measurement costs nothing extra, needs no second protocol,
//! and works anywhere HTTPS works — including behind the proxies and captive
//! portals that block UDP port 123.
//!
//! A device with no sync account (OFF-04) has no such request to piggyback on,
//! and no reference. That is a real gap and it is stated in the user interface
//! rather than papered over: [`Measurement::None`] is not the same as an offset
//! of zero, and the two must not be displayed the same way.
//!
//! # The clock is never set
//!
//! FR-39. Nothing here writes a system clock, and on the two platforms in scope
//! an application cannot. The offset is stored and added at the point a code is
//! generated.

use core::fmt;

/// Seconds of round trip beyond which a measurement is not worth having.
///
/// The `Date` header names the moment the *server* built the response. By the
/// time the client reads it, half a round trip has passed, which the midpoint
/// below corrects for on average. What it cannot correct for is an asymmetric
/// path — a slow uplink and a fast downlink — and the error there is bounded by
/// the round trip.
///
/// Five seconds keeps the residual error well inside FR-40's ten-second
/// warning threshold. A measurement taken over a worse link is discarded
/// rather than averaged in: a wrong offset is worse than none, because none is
/// visible and wrong is not.
pub const MAX_ROUND_TRIP_SECONDS: i64 = 5;

/// How far the offset must move before it is worth rewriting.
///
/// Without this, every response rewrites the stored value, which is a database
/// write per request for a number that changes by fractions of a second. It
/// also makes the displayed offset flicker.
pub const UPDATE_THRESHOLD_SECONDS: i64 = 2;

/// One reading of a reference clock against this device's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// The reference time the server reported, in epoch milliseconds.
    pub reference_ms: i64,
    /// This device's clock when the request went out.
    pub sent_ms: i64,
    /// This device's clock when the response came back.
    pub received_ms: i64,
}

/// What a sample amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measurement {
    /// A usable reading. The offset is in seconds, to be added to the device
    /// clock.
    Offset { seconds: i64, round_trip_ms: i64 },
    /// The round trip was too long for the reading to mean anything.
    TooSlow { round_trip_ms: i64 },
    /// The clocks disagree by so much that the reading is more likely to be
    /// wrong than the clock.
    Implausible { seconds: i64 },
    /// Nothing has been measured. Distinct from an offset of zero, which means
    /// the clock has been checked and is right.
    None,
}

/// A year in seconds, near enough. Past this the reading is not a clock error.
///
/// A device really can be a year out — a phone with a dead battery comes up in
/// 1970 or 2016 — but a *reading* that far from the device clock is far more
/// likely to be a misparsed header or a proxy serving a cached response. The
/// TOTP window is thirty seconds, so nothing in that range is recoverable by
/// correction anyway, and pretending otherwise would let one bad response make
/// every code wrong.
const IMPLAUSIBLE_SECONDS: i64 = 365 * 24 * 60 * 60;

/// Turns one reading into an offset, correcting for the round trip.
///
/// The reference time is taken to describe the midpoint of the request, which
/// is the standard assumption and is exactly right when the path is
/// symmetric. It is the same correction NTP makes, minus the parts that need
/// two timestamps from the server.
pub fn measure(sample: Sample) -> Measurement {
    let round_trip_ms = sample.received_ms.saturating_sub(sample.sent_ms);

    // A negative round trip means the device clock moved backwards mid-request
    // — a manual change, or a time-zone service correcting it. The reading
    // describes two different clocks and is not usable.
    if round_trip_ms < 0 {
        return Measurement::TooSlow { round_trip_ms };
    }
    if round_trip_ms > MAX_ROUND_TRIP_SECONDS * 1000 {
        return Measurement::TooSlow { round_trip_ms };
    }

    let midpoint_ms = sample.sent_ms + round_trip_ms / 2;
    let difference_ms = sample.reference_ms.saturating_sub(midpoint_ms);

    // Rounded to the nearest second rather than truncated. Truncation biases
    // every measurement toward zero, and toward zero is toward "your clock is
    // fine".
    let seconds = (difference_ms as f64 / 1000.0).round() as i64;

    if seconds.abs() > IMPLAUSIBLE_SECONDS {
        return Measurement::Implausible { seconds };
    }

    Measurement::Offset {
        seconds,
        round_trip_ms,
    }
}

/// Whether a new offset is different enough from the stored one to write.
pub fn worth_storing(stored_seconds: i64, measured_seconds: i64) -> bool {
    (measured_seconds - stored_seconds).abs() >= UPDATE_THRESHOLD_SECONDS
}

/// Reads an HTTP `Date` header (RFC 9110 section 5.6.7, IMF-fixdate).
///
/// Only the fixed format is accepted: `Sun, 06 Nov 1994 08:49:37 GMT`. The two
/// obsolete formats in the specification are not, and that is deliberate —
/// every server this client talks to is required to send the fixed one, and a
/// parser that guesses between three formats is a parser that can guess wrong
/// about the time, which is the one thing here that must not happen quietly.
///
/// Returns epoch milliseconds.
pub fn parse_http_date(value: &str) -> Result<i64, DateParseError> {
    let value = value.trim();
    let fail = || DateParseError {
        input: value.to_string(),
    };

    // "Sun, 06 Nov 1994 08:49:37 GMT"
    //  0    1  2   3    4
    let rest = value.split_once(", ").ok_or_else(fail)?.1;
    let mut parts = rest.split(' ');
    let (day, month, year, time, zone) = (
        parts.next().ok_or_else(fail)?,
        parts.next().ok_or_else(fail)?,
        parts.next().ok_or_else(fail)?,
        parts.next().ok_or_else(fail)?,
        parts.next().ok_or_else(fail)?,
    );
    if parts.next().is_some() || zone != "GMT" {
        return Err(fail());
    }

    let day: i64 = day.parse().map_err(|_| fail())?;
    let year: i64 = year.parse().map_err(|_| fail())?;
    let month = match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return Err(fail()),
    };

    let mut clock = time.split(':');
    let hour: i64 = clock.next().ok_or_else(fail)?.parse().map_err(|_| fail())?;
    let minute: i64 = clock.next().ok_or_else(fail)?.parse().map_err(|_| fail())?;
    let second: i64 = clock.next().ok_or_else(fail)?.parse().map_err(|_| fail())?;
    if clock.next().is_some() {
        return Err(fail());
    }

    // A leap second arrives as :60. Accepted and clamped rather than refused:
    // refusing would discard the one measurement taken during it, and the
    // second of error it introduces is far inside the tolerance here.
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=60).contains(&second) {
        return Err(fail());
    }
    let second = second.min(59);
    if !(1..=31).contains(&day) {
        return Err(fail());
    }

    Ok((days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second) * 1000)
}

/// Days since 1970-01-01 for a civil date.
///
/// Howard Hinnant's algorithm, which is exact for the whole proleptic
/// Gregorian calendar and needs no table and no loop. Written out rather than
/// taken from a date library: this and the parser above are the only calendar
/// arithmetic in the project, and a dependency for forty lines that never
/// change is a dependency to keep updated forever.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateParseError {
    pub input: String,
}

impl fmt::Display for DateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}' is not an HTTP date", self.input)
    }
}

impl std::error::Error for DateParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-08-23 02:22:07 GMT, the header the development server sent while
    // this module was being written.
    const HEADER: &str = "Sun, 23 Aug 2026 02:22:07 GMT";
    // Verified against an independent implementation rather than by adjusting
    // until the test went green — the first value here was hand-computed and
    // wrong, and "fix the expectation" is exactly how a broken parser gets
    // blessed.
    const HEADER_MS: i64 = 1_787_451_727_000;

    #[test]
    fn the_epoch_is_where_it_should_be() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT").unwrap(), 0);
    }

    #[test]
    fn the_specifications_own_example_parses() {
        // RFC 9110 section 5.6.7 uses this date in all three formats.
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap(),
            784_111_777_000
        );
    }

    #[test]
    fn a_real_header_from_the_server_parses() {
        assert_eq!(parse_http_date(HEADER).unwrap(), HEADER_MS);
    }

    #[test]
    fn leap_years_are_counted() {
        // 2000 is a leap year, 1900 is not, and 2024 is. Getting the century
        // rule wrong shifts every date by a day, which is 86400 seconds of
        // offset and would make every code wrong rather than merely late.
        assert_eq!(
            parse_http_date("Tue, 29 Feb 2000 00:00:00 GMT").unwrap(),
            951_782_400_000
        );
        assert_eq!(
            parse_http_date("Thu, 29 Feb 2024 12:00:00 GMT").unwrap(),
            1_709_208_000_000
        );
    }

    #[test]
    fn a_day_apart_is_exactly_a_day() {
        let first = parse_http_date("Mon, 01 Jan 2029 00:00:00 GMT").unwrap();
        let second = parse_http_date("Tue, 02 Jan 2029 00:00:00 GMT").unwrap();
        assert_eq!(second - first, 86_400_000);
    }

    #[test]
    fn a_leap_second_is_accepted_rather_than_discarded() {
        // Refusing would throw away the one measurement taken during it, and
        // the second of error is far inside the tolerance here.
        let value = parse_http_date("Sun, 31 Dec 2016 23:59:60 GMT").unwrap();
        assert_eq!(
            value,
            parse_http_date("Sat, 31 Dec 2016 23:59:59 GMT").unwrap()
        );
    }

    #[test]
    fn nonsense_is_refused_rather_than_guessed_at() {
        // A parser that guesses can guess wrong about the time, which is the
        // one thing here that must not happen quietly.
        for bad in [
            "",
            "not a date",
            "Sun, 23 Aug 2026 02:22:07",      // no zone
            "Sun, 23 Aug 2026 02:22:07 UTC",  // wrong zone
            "Sun, 23 Foo 2026 02:22:07 GMT",  // no such month
            "Sun, 23 Aug 2026 25:00:00 GMT",  // no such hour
            "Sun, 23 Aug 2026 02:61:00 GMT",  // no such minute
            "Sun, 32 Aug 2026 02:22:07 GMT",  // no such day
            "Sunday, 06-Nov-94 08:49:37 GMT", // the obsolete RFC 850 form
            "Sun Nov  6 08:49:37 1994",       // the obsolete asctime form
            "Sun, 23 Aug 2026 02:22:07 GMT extra",
        ] {
            assert!(parse_http_date(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_clock_that_agrees_measures_no_offset() {
        let measurement = measure(Sample {
            reference_ms: 1_000_000,
            sent_ms: 1_000_000,
            received_ms: 1_000_000,
        });
        assert_eq!(
            measurement,
            Measurement::Offset {
                seconds: 0,
                round_trip_ms: 0
            }
        );
    }

    #[test]
    fn a_slow_clock_measures_a_positive_offset() {
        // The device is 30 seconds behind, so 30 must be *added* to it.
        let measurement = measure(Sample {
            reference_ms: 1_030_000,
            sent_ms: 1_000_000,
            received_ms: 1_000_000,
        });
        assert!(matches!(
            measurement,
            Measurement::Offset { seconds: 30, .. }
        ));
    }

    #[test]
    fn a_fast_clock_measures_a_negative_offset() {
        let measurement = measure(Sample {
            reference_ms: 970_000,
            sent_ms: 1_000_000,
            received_ms: 1_000_000,
        });
        assert!(matches!(
            measurement,
            Measurement::Offset { seconds: -30, .. }
        ));
    }

    #[test]
    fn the_round_trip_is_taken_from_the_middle() {
        // The header names when the server built the response, so by the time
        // it is read, roughly half the round trip has passed. Ignoring that
        // biases every measurement by half the latency — always in the same
        // direction, so it never averages out.
        let measurement = measure(Sample {
            reference_ms: 1_000_400,
            sent_ms: 1_000_000,
            received_ms: 1_000_800,
        });
        assert!(
            matches!(measurement, Measurement::Offset { seconds: 0, .. }),
            "a symmetric round trip around an accurate clock is no offset"
        );
    }

    #[test]
    fn a_slow_link_is_discarded_rather_than_averaged_in() {
        // A wrong offset is worse than no offset: none is visible in the
        // interface, and wrong is not.
        let measurement = measure(Sample {
            reference_ms: 1_000_000,
            sent_ms: 1_000_000,
            received_ms: 1_000_000 + (MAX_ROUND_TRIP_SECONDS + 1) * 1000,
        });
        assert!(matches!(measurement, Measurement::TooSlow { .. }));
    }

    #[test]
    fn a_clock_that_moved_mid_request_is_discarded() {
        // A negative round trip means the device clock changed during the
        // request. The two timestamps describe different clocks.
        let measurement = measure(Sample {
            reference_ms: 1_000_000,
            sent_ms: 1_000_000,
            received_ms: 900_000,
        });
        assert!(matches!(measurement, Measurement::TooSlow { .. }));
    }

    #[test]
    fn a_reading_years_away_is_refused() {
        // A phone with a dead battery really does come up in 1970. But a
        // *reading* that far out is more likely a cached response than a
        // clock, and nothing beyond a thirty-second window is recoverable by
        // correction anyway.
        let measurement = measure(Sample {
            reference_ms: 0,
            sent_ms: 1_787_797_327_000,
            received_ms: 1_787_797_327_000,
        });
        assert!(matches!(measurement, Measurement::Implausible { .. }));
    }

    #[test]
    fn rounding_does_not_lean_toward_saying_the_clock_is_fine() {
        // Truncation would report 10 for 10.6 seconds, which sits on the wrong
        // side of FR-40's threshold and would hide the warning.
        let measurement = measure(Sample {
            reference_ms: 1_010_600,
            sent_ms: 1_000_000,
            received_ms: 1_000_000,
        });
        assert!(matches!(
            measurement,
            Measurement::Offset { seconds: 11, .. }
        ));
    }

    #[test]
    fn a_small_change_is_not_written_back() {
        // Otherwise every response is a database write for a number that moved
        // by a fraction of a second, and the displayed value flickers.
        assert!(!worth_storing(30, 30));
        assert!(!worth_storing(30, 31));
        assert!(worth_storing(30, 32));
        assert!(worth_storing(30, 0));
        assert!(worth_storing(0, -5));
    }

    #[test]
    fn no_measurement_is_not_an_offset_of_zero() {
        // A device with no account has no reference and no way to get one.
        // "Unknown" and "checked, and correct" must not display the same.
        assert_ne!(
            Measurement::None,
            Measurement::Offset {
                seconds: 0,
                round_trip_ms: 0
            }
        );
    }
}
