//! Hybrid logical clock timestamps (PRD section 10.2).
//!
//! Every write carries an HLC so that two devices with different clocks still
//! agree on an order. The timestamp has three parts — wall-clock milliseconds,
//! a counter, and the device identifier — encoded as fixed-width lowercase hex
//! so that ordering the strings gives the same answer as ordering the values.
//!
//! The device identifier is what makes the section 10.4 tiebreak work. Two
//! writes to the same entry in the same millisecond cannot be separated by the
//! entry identifier, because both name the same entry.
//!
//! Stage S1 needs this type because the `entry` table stores an `hlc` column.
//! Wiring it into the sync cycle is stage S5.

use core::fmt;
use core::str::FromStr;

/// Milliseconds are stored in 48 bits, which runs out in the year 10889.
const WALL_BITS: u32 = 48;
const WALL_MASK: u64 = (1u64 << WALL_BITS) - 1;

/// One hybrid logical clock timestamp.
///
/// The field order matters: the derived ordering compares wall time first,
/// then the counter, then the device, which is exactly the order the encoded
/// string sorts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u16,
    pub device: u64,
}

/// Why an HLC string could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlcParseError {
    pub input: String,
}

impl fmt::Display for HlcParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' is not a timestamp. The expected form is 12-4-16 hexadecimal digits.",
            self.input
        )
    }
}

impl std::error::Error for HlcParseError {}

impl Hlc {
    pub fn new(wall_ms: u64, counter: u16, device: u64) -> Self {
        Self {
            wall_ms: wall_ms & WALL_MASK,
            counter,
            device,
        }
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:012x}-{:04x}-{:016x}",
            self.wall_ms & WALL_MASK,
            self.counter,
            self.device
        )
    }
}

impl FromStr for Hlc {
    type Err = HlcParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fail = || HlcParseError {
            input: input.to_string(),
        };
        let mut parts = input.split('-');
        let (wall, counter, device) = match (parts.next(), parts.next(), parts.next(), parts.next())
        {
            (Some(wall), Some(counter), Some(device), None) => (wall, counter, device),
            _ => return Err(fail()),
        };
        if wall.len() != 12 || counter.len() != 4 || device.len() != 16 {
            return Err(fail());
        }
        Ok(Self {
            wall_ms: u64::from_str_radix(wall, 16).map_err(|_| fail())?,
            counter: u16::from_str_radix(counter, 16).map_err(|_| fail())?,
            device: u64::from_str_radix(device, 16).map_err(|_| fail())?,
        })
    }
}

/// Issues timestamps for one device.
///
/// The clock never goes backwards, even when the device clock does. A device
/// whose clock jumps back keeps issuing timestamps ahead of its last one by
/// advancing the counter instead.
#[derive(Debug, Clone)]
pub struct HlcClock {
    device: u64,
    last: Hlc,
}

/// Section 10.2's forward drift bound: five minutes.
///
/// # What this is for
///
/// The HLC takes the maximum of the local and remote wall-clock components, so
/// a remote value propagates. One device with its clock set an hour ahead
/// therefore issues timestamps an hour ahead, every device that syncs with it
/// adopts that time, and **that device wins every conflict until real time
/// catches up** — no later write on a correct device can override it.
///
/// The bound is on the *incoming* value only. A local clock that is simply
/// wrong is the user's own problem and affects only their device; a value that
/// arrives over the network affects everyone.
///
/// Five minutes is large enough to absorb ordinary clock skew between devices
/// that are all roughly right, and small enough that a badly set clock costs
/// minutes rather than hours.
pub const MAX_FORWARD_DRIFT_MS: u64 = 5 * 60 * 1000;

/// What a clock did with a remote timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftOutcome {
    /// Within the bound and used as it was.
    Accepted,
    /// Beyond the bound. The wall-clock component was clamped to the local
    /// time plus [`MAX_FORWARD_DRIFT_MS`]; the timestamp is still ordered
    /// after the local one, so the write is not lost.
    Clamped { ahead_by_ms: u64 },
}

impl HlcClock {
    /// `device` is the random 64-bit identifier assigned at install and held
    /// in the `meta` table. It never changes.
    pub fn new(device: u64) -> Self {
        Self {
            device,
            last: Hlc::new(0, 0, device),
        }
    }

    /// Restores a clock from the last timestamp this device issued.
    pub fn resume(device: u64, last: Hlc) -> Self {
        Self { device, last }
    }

    pub fn last(&self) -> Hlc {
        self.last
    }

    /// Issues a timestamp for a local write.
    pub fn tick(&mut self, physical_ms: u64) -> Hlc {
        let physical_ms = physical_ms & WALL_MASK;
        self.last = if physical_ms > self.last.wall_ms {
            Hlc::new(physical_ms, 0, self.device)
        } else {
            advance(self.last.wall_ms, self.last.counter, self.device)
        };
        self.last
    }

    /// Folds a timestamp received from another device into this clock, then
    /// issues a timestamp for the write that observes it. The result is always
    /// greater than both the local and the remote timestamp.
    ///
    /// A remote value more than [`MAX_FORWARD_DRIFT_MS`] ahead of local time
    /// is clamped first — see [`Self::observe_checked`] if the caller wants to
    /// know that happened.
    pub fn observe(&mut self, remote: Hlc, physical_ms: u64) -> Hlc {
        self.observe_checked(remote, physical_ms).0
    }

    /// [`Self::observe`], reporting whether the remote timestamp was clamped.
    ///
    /// Clamping rather than rejecting: a rejected write would be lost, and the
    /// device that sent it is not necessarily wrong about the write — only
    /// about the time. Clamping keeps the change and takes away the unearned
    /// priority.
    pub fn observe_checked(&mut self, remote: Hlc, physical_ms: u64) -> (Hlc, DriftOutcome) {
        let physical_ms = physical_ms & WALL_MASK;
        let (remote, outcome) = clamp_drift(remote, physical_ms);

        let wall = physical_ms.max(self.last.wall_ms).max(remote.wall_ms);

        self.last = if wall == self.last.wall_ms && wall == remote.wall_ms {
            advance(wall, self.last.counter.max(remote.counter), self.device)
        } else if wall == self.last.wall_ms {
            advance(wall, self.last.counter, self.device)
        } else if wall == remote.wall_ms {
            advance(wall, remote.counter, self.device)
        } else {
            Hlc::new(wall, 0, self.device)
        };
        (self.last, outcome)
    }
}

/// Applies section 10.2's bound to a timestamp arriving from elsewhere.
///
/// Only the wall-clock component is touched. The counter and the device
/// identifier are kept, so the value stays unique and still orders against
/// other writes from the same device in the same millisecond.
pub fn clamp_drift(remote: Hlc, local_physical_ms: u64) -> (Hlc, DriftOutcome) {
    let ceiling = local_physical_ms.saturating_add(MAX_FORWARD_DRIFT_MS) & WALL_MASK;

    if remote.wall_ms <= ceiling {
        return (remote, DriftOutcome::Accepted);
    }

    (
        Hlc::new(ceiling, remote.counter, remote.device),
        DriftOutcome::Clamped {
            ahead_by_ms: remote.wall_ms - local_physical_ms,
        },
    )
}

/// Bumps the counter, rolling into the next millisecond if it would overflow.
///
/// Public because section 10.4 step 7 derives a corrected timestamp this way:
/// the largest candidate HLC, its counter increased by one, and the correcting
/// device's identifier. That is the whole derivation, and it uses no clock.
pub fn advance(wall_ms: u64, counter: u16, device: u64) -> Hlc {
    match counter.checked_add(1) {
        Some(counter) => Hlc::new(wall_ms, counter, device),
        None => Hlc::new(wall_ms + 1, 0, device),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_A: u64 = 0xa91b_7f0e_44d2_c318;
    const DEVICE_B: u64 = 0x0123_4567_89ab_cdef;

    #[test]
    fn renders_the_documented_shape() {
        let hlc = Hlc::new(0x0193_1f4a_2c10, 3, DEVICE_A);
        assert_eq!(hlc.to_string(), "01931f4a2c10-0003-a91b7f0e44d2c318");
        assert_eq!(hlc.to_string().parse::<Hlc>().unwrap(), hlc);
    }

    #[test]
    fn rejects_a_malformed_string() {
        for bad in ["", "abc", "01931f4a2c10-0003", "01931f4a2c10-0003-zz"] {
            assert!(bad.parse::<Hlc>().is_err(), "{bad} should not parse");
        }
    }

    /// The encoding is fixed-width hex, so sorting the strings must give the
    /// same order as comparing the values. The sync engine relies on this.
    #[test]
    fn string_order_matches_value_order() {
        let mut values = [
            Hlc::new(2, 0, DEVICE_A),
            Hlc::new(1, 5, DEVICE_A),
            Hlc::new(1, 5, DEVICE_B),
            Hlc::new(1, 0, DEVICE_A),
        ];
        let mut strings: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        values.sort();
        strings.sort();
        let from_values: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        assert_eq!(from_values, strings);
    }

    #[test]
    fn the_counter_separates_writes_in_one_millisecond() {
        let mut clock = HlcClock::new(DEVICE_A);
        let first = clock.tick(1000);
        let second = clock.tick(1000);
        let third = clock.tick(1001);

        assert_eq!((first.wall_ms, first.counter), (1000, 0));
        assert_eq!((second.wall_ms, second.counter), (1000, 1));
        assert_eq!((third.wall_ms, third.counter), (1001, 0));
        assert!(first < second && second < third);
    }

    #[test]
    fn the_clock_never_goes_backwards() {
        let mut clock = HlcClock::new(DEVICE_A);
        let before = clock.tick(10_000_000);
        // The device clock jumps back an hour.
        let after = clock.tick(10_000_000 - 3_600_000);
        assert!(
            after > before,
            "a backwards device clock must not rewind the HLC"
        );
    }

    #[test]
    fn observing_a_remote_timestamp_moves_past_it() {
        let mut clock = HlcClock::new(DEVICE_A);
        clock.tick(1000);
        let remote = Hlc::new(9000, 4, DEVICE_B);
        let issued = clock.observe(remote, 1001);

        assert!(issued > remote);
        assert_eq!(issued.device, DEVICE_A);
        assert_eq!((issued.wall_ms, issued.counter), (9000, 5));
    }

    /// Section 10.4: when the time and the counter match, the larger device
    /// identifier wins, and both devices reach the same answer.
    #[test]
    fn the_device_identifier_breaks_an_exact_tie() {
        let from_a = Hlc::new(1000, 0, DEVICE_A);
        let from_b = Hlc::new(1000, 0, DEVICE_B);

        assert_ne!(from_a, from_b);
        assert!(from_a > from_b, "0xa91b... is the larger device identifier");
        assert_eq!(from_a.max(from_b), from_b.max(from_a));
    }

    #[test]
    fn a_counter_overflow_rolls_into_the_next_millisecond() {
        let mut clock = HlcClock::resume(DEVICE_A, Hlc::new(1000, u16::MAX, DEVICE_A));
        let next = clock.tick(1000);
        assert_eq!((next.wall_ms, next.counter), (1001, 0));
        assert!(next > Hlc::new(1000, u16::MAX, DEVICE_A));
    }
}

#[cfg(test)]
mod drift_tests {
    use super::*;

    const LOCAL: u64 = 0xa91b_7f0e_44d2_c318;
    const REMOTE: u64 = 0x0123_4567_89ab_cdef;

    /// Section 10.2's whole reason: a device an hour ahead must not win every
    /// conflict for an hour.
    #[test]
    fn a_clock_an_hour_ahead_is_clamped() {
        let now = 1_755_734_400_000;
        let hour_ahead = Hlc::new(now + 60 * 60 * 1000, 0, REMOTE);

        let (clamped, outcome) = clamp_drift(hour_ahead, now);

        assert!(matches!(outcome, DriftOutcome::Clamped { .. }));
        assert_eq!(clamped.wall_ms, now + MAX_FORWARD_DRIFT_MS);
        assert!(
            clamped.wall_ms < hour_ahead.wall_ms,
            "the timestamp must lose its unearned lead"
        );
    }

    /// And the point of clamping rather than rejecting: the write survives.
    #[test]
    fn a_clamped_write_is_kept_and_still_ordered() {
        let now = 1_755_734_400_000;
        let mut clock = HlcClock::new(LOCAL);
        let local_write = clock.tick(now);

        let far_future = Hlc::new(now + 60 * 60 * 1000, 0, REMOTE);
        let (issued, outcome) = clock.observe_checked(far_future, now);

        assert!(matches!(outcome, DriftOutcome::Clamped { .. }));
        assert!(
            issued > local_write,
            "the observing write must still come after the local one"
        );
        assert!(
            issued.wall_ms <= now + MAX_FORWARD_DRIFT_MS,
            "and must not have adopted the remote device's hour"
        );
    }

    /// Ordinary skew between roughly-correct devices must pass untouched, or
    /// the bound would fire constantly and clamp honest writes.
    #[test]
    fn ordinary_skew_is_accepted() {
        let now = 1_755_734_400_000;

        for ahead_ms in [0, 1, 1_000, 30_000, MAX_FORWARD_DRIFT_MS] {
            let remote = Hlc::new(now + ahead_ms, 3, REMOTE);
            let (result, outcome) = clamp_drift(remote, now);

            assert_eq!(outcome, DriftOutcome::Accepted, "{ahead_ms}ms was clamped");
            assert_eq!(result, remote);
        }
    }

    /// A remote clock that is *behind* is not a problem: it loses conflicts on
    /// its own, and clamping it upward would hand it priority it did not earn.
    #[test]
    fn a_slow_remote_clock_is_left_alone() {
        let now = 1_755_734_400_000;
        let behind = Hlc::new(now - 60 * 60 * 1000, 0, REMOTE);

        let (result, outcome) = clamp_drift(behind, now);

        assert_eq!(outcome, DriftOutcome::Accepted);
        assert_eq!(result, behind);
    }

    /// The counter and device identifier survive clamping, or two clamped
    /// writes from one device in the same millisecond would collide.
    #[test]
    fn clamping_keeps_the_counter_and_the_device() {
        let now = 1_755_734_400_000;
        let remote = Hlc::new(now + 60 * 60 * 1000, 42, REMOTE);

        let (clamped, _) = clamp_drift(remote, now);

        assert_eq!(clamped.counter, 42);
        assert_eq!(clamped.device, REMOTE);
    }

    /// Two clamped writes from the same far-future device must still order
    /// against each other rather than becoming equal.
    #[test]
    fn two_clamped_writes_stay_distinct() {
        let now = 1_755_734_400_000;
        let far = now + 60 * 60 * 1000;

        let (first, _) = clamp_drift(Hlc::new(far, 1, REMOTE), now);
        let (second, _) = clamp_drift(Hlc::new(far, 2, REMOTE), now);

        assert_ne!(first, second);
        assert!(second > first);
    }

    /// The bound is on what arrives, not on the local clock. A device whose
    /// own clock is ahead affects only itself, and refusing its local writes
    /// would make the application unusable on a wrongly-set phone.
    #[test]
    fn a_local_clock_that_is_ahead_is_not_clamped() {
        let mut clock = HlcClock::new(LOCAL);
        let far_local = 1_755_734_400_000 + 60 * 60 * 1000;

        let issued = clock.tick(far_local);

        assert_eq!(issued.wall_ms, far_local);
    }

    /// Reported so a caller can surface it. A user whose device keeps clamping
    /// its peers has a clock problem worth telling them about.
    #[test]
    fn the_report_says_how_far_ahead_it_was() {
        let now = 1_755_734_400_000;
        let ahead = 60 * 60 * 1000;

        let (_, outcome) = clamp_drift(Hlc::new(now + ahead, 0, REMOTE), now);

        assert_eq!(outcome, DriftOutcome::Clamped { ahead_by_ms: ahead });
    }
}
