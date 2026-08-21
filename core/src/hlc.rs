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
    pub fn observe(&mut self, remote: Hlc, physical_ms: u64) -> Hlc {
        let physical_ms = physical_ms & WALL_MASK;
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
        self.last
    }
}

/// Bumps the counter, rolling into the next millisecond if it would overflow.
fn advance(wall_ms: u64, counter: u16, device: u64) -> Hlc {
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
