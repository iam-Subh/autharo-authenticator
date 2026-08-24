//! When to try syncing again after a failure (PRD OFF-06).
//!
//! "Retry a failed sync with exponential backoff. Start at 5 seconds. Stop at
//! 10 minutes."
//!
//! # Why this is its own module and reads no clock
//!
//! Backoff is arithmetic, and arithmetic that is wrong in the tail: the bugs
//! are an overflow after forty failures, a cap that is never reached because
//! the doubling skips past it, a delay that resets on the wrong event so a
//! device hammers a server that is already struggling. None of those show up
//! in a manual test, because reaching them takes hours of failure.
//!
//! So the decision is separated from the doing. Every function here takes the
//! time as a parameter, like the rest of the core, and a test can walk a
//! device through a day of outage in a millisecond.
//!
//! # Why the delay is jittered
//!
//! Without it, every device that lost the same server comes back at the same
//! second, and the retry storm is what stops the server recovering. The jitter
//! is a parameter rather than a random number drawn here, for the same reason
//! as the clock: a caller can pin it, and the shape of the schedule stays
//! testable.
//!
//! # What resets it
//!
//! A completed cycle, and a user asking. Nothing else. In particular a *new*
//! local change does not reset it — otherwise a device with an edit every few
//! seconds would retry every few seconds through an outage, which is precisely
//! the behaviour the requirement exists to prevent.

use crate::store::{MetaStore, StoreError};

/// The first delay, and the floor for every later one.
pub const FIRST_DELAY_MS: u64 = 5_000;
/// The ceiling. A device that has been failing for an hour still tries every
/// ten minutes, because the outage it is waiting out may end at any moment.
pub const MAX_DELAY_MS: u64 = 10 * 60 * 1000;

/// `meta`, not the vault: OFF-09 has the cycle running while locked, so the
/// schedule has to be readable and writable while locked too.
const META_FAILURES: &str = "sync.consecutive_failures";
const META_NEXT_DUE: &str = "sync.next_attempt_ms";

/// How long to wait after `failures` consecutive failures.
///
/// `failures` of 0 means the last attempt succeeded, and the answer is zero:
/// there is nothing to wait for.
///
/// The doubling saturates rather than wrapping. At 64 consecutive failures a
/// naive `5_000 << 63` is undefined behaviour in C and a panic in a debug Rust
/// build — and a device that has been offline for a week reaches numbers like
/// that without anything unusual happening.
pub fn delay_ms(failures: u32) -> u64 {
    if failures == 0 {
        return 0;
    }
    // Doubled by repeated multiplication, not by shifting.
    //
    // The shift version of this was wrong, and wrong in the direction that
    // matters: `checked_shl` checks the *shift amount*, not the value, so
    // `5_000u64 << 62` wraps quietly to zero. A device that had failed sixty-
    // three times would then retry with no delay at all — the exact opposite
    // of the requirement, reached only after a long outage, and invisible to
    // any test that stops at a handful of failures.
    //
    // The loop stops the moment it passes the ceiling, so it runs at most
    // eight times however large `failures` is.
    let mut delay = FIRST_DELAY_MS;
    for _ in 1..failures {
        delay = delay.saturating_mul(2);
        if delay >= MAX_DELAY_MS {
            return MAX_DELAY_MS;
        }
    }
    delay.min(MAX_DELAY_MS)
}

/// The same delay, spread over a window so devices do not return in lockstep.
///
/// `jitter` runs from 0.0 to 1.0 and scales the delay to between 50% and 100%
/// of it. Never longer: a device must not wait past the ceiling because of a
/// random number, and the requirement names the ceiling.
pub fn jittered_ms(failures: u32, jitter: f64) -> u64 {
    let base = delay_ms(failures);
    if base == 0 {
        return 0;
    }
    // A value that is not a number is treated as the middle of the range, not
    // clamped. `f64::clamp` propagates NaN, and `NaN as u64` saturates to
    // zero — so a misconfigured source would produce no delay whatever, which
    // is the failure this function exists to prevent.
    let jitter = if jitter.is_finite() { jitter } else { 0.5 };
    let factor = 0.5 + 0.5 * jitter.clamp(0.0, 1.0);
    ((base as f64) * factor).round() as u64
}

/// The retry schedule as it survives a restart.
///
/// Kept in `meta` so an application that is killed mid-outage does not come
/// back and immediately retry — which would turn every restart into a way
/// around the backoff, and users restart an app that looks stuck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    pub failures: u32,
    /// Epoch milliseconds. `None` when nothing is scheduled.
    pub next_due_ms: Option<u64>,
}

impl Schedule {
    /// Whether a cycle should run now.
    ///
    /// A caller that wants to try regardless — a user pressing **Sync now** —
    /// should not consult this. Making someone wait out a backoff they can see
    /// on screen is how an app earns a reputation for being broken.
    pub fn is_due(&self, now_ms: u64) -> bool {
        match self.next_due_ms {
            None => true,
            Some(due) => now_ms >= due,
        }
    }

    /// Milliseconds until the next attempt, for the interface.
    pub fn wait_ms(&self, now_ms: u64) -> u64 {
        self.next_due_ms.unwrap_or(0).saturating_sub(now_ms)
    }
}

pub fn load(meta: &MetaStore) -> Result<Schedule, StoreError> {
    Ok(Schedule {
        failures: number(meta, META_FAILURES)?.unwrap_or(0) as u32,
        next_due_ms: number(meta, META_NEXT_DUE)?,
    })
}

/// Records a failed cycle and schedules the next attempt.
pub fn record_failure(meta: &MetaStore, now_ms: u64, jitter: f64) -> Result<Schedule, StoreError> {
    let failures = load(meta)?.failures.saturating_add(1);
    let due = now_ms.saturating_add(jittered_ms(failures, jitter));

    meta.set(META_FAILURES, failures.to_string().as_bytes())?;
    meta.set(META_NEXT_DUE, due.to_string().as_bytes())?;

    Ok(Schedule {
        failures,
        next_due_ms: Some(due),
    })
}

/// Records a completed cycle, clearing the backoff.
pub fn record_success(meta: &MetaStore) -> Result<(), StoreError> {
    meta.remove(META_FAILURES)?;
    meta.remove(META_NEXT_DUE)?;
    Ok(())
}

fn number(meta: &MetaStore, key: &str) -> Result<Option<u64>, StoreError> {
    Ok(meta
        .get(key)?
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| text.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_success_waits_for_nothing() {
        assert_eq!(delay_ms(0), 0);
    }

    #[test]
    fn the_first_retry_waits_five_seconds() {
        assert_eq!(delay_ms(1), 5_000, "OFF-06 names the starting delay");
    }

    #[test]
    fn each_failure_doubles_the_wait() {
        assert_eq!(delay_ms(2), 10_000);
        assert_eq!(delay_ms(3), 20_000);
        assert_eq!(delay_ms(4), 40_000);
    }

    #[test]
    fn the_wait_stops_at_ten_minutes() {
        // The cap has to be *reached*, not skipped past. Doubling from five
        // seconds gives 320s then 640s, and 640 is over the ceiling — so the
        // clamp is what produces the named number, not the doubling.
        assert_eq!(delay_ms(7), 320_000);
        assert_eq!(delay_ms(8), MAX_DELAY_MS);
        assert_eq!(delay_ms(9), MAX_DELAY_MS);
    }

    #[test]
    fn a_week_of_failure_does_not_overflow() {
        // A device offline for a week reaches counts like these with nothing
        // unusual happening. `5_000 << 63` would panic in a debug build.
        for failures in [40, 63, 64, 100, u32::MAX] {
            assert_eq!(
                delay_ms(failures),
                MAX_DELAY_MS,
                "{failures} consecutive failures"
            );
        }
    }

    #[test]
    fn the_wait_never_shortens_as_failures_grow() {
        let mut previous = 0;
        for failures in 0..40 {
            let delay = delay_ms(failures);
            assert!(delay >= previous, "{failures} went backwards");
            previous = delay;
        }
    }

    #[test]
    fn jitter_spreads_devices_without_exceeding_the_ceiling() {
        // The point is that two devices with the same failure count do not
        // return in the same second. The bound matters as much: a random
        // number must not push a device past the ten minutes OFF-06 names.
        for failures in 1..20 {
            let base = delay_ms(failures);
            for jitter in [0.0, 0.25, 0.5, 0.75, 1.0] {
                let delay = jittered_ms(failures, jitter);
                assert!(delay <= base, "jitter lengthened the wait");
                assert!(delay >= base / 2, "jitter shortened it too far");
                assert!(delay <= MAX_DELAY_MS);
            }
        }
    }

    #[test]
    fn a_jitter_outside_the_range_is_clamped_rather_than_trusted() {
        // The caller supplies this. A value from a misconfigured source must
        // not produce a negative delay or a wait of several hours.
        for jitter in [-5.0, -0.001, 1.001, 42.0, f64::NAN] {
            let delay = jittered_ms(4, jitter);
            assert!(delay <= delay_ms(4));
            assert!(delay >= delay_ms(4) / 2);
        }
    }

    fn meta() -> MetaStore {
        MetaStore::open_in_memory().unwrap()
    }

    #[test]
    fn a_fresh_device_may_sync_immediately() {
        let meta = meta();
        assert!(load(&meta).unwrap().is_due(0));
    }

    #[test]
    fn a_failure_pushes_the_next_attempt_out() {
        let meta = meta();
        let schedule = record_failure(&meta, 1_000, 1.0).unwrap();

        assert_eq!(schedule.failures, 1);
        assert!(!schedule.is_due(1_000), "it must not retry immediately");
        assert!(!schedule.is_due(5_999));
        assert!(schedule.is_due(6_000), "five seconds later it may");
    }

    #[test]
    fn the_schedule_survives_a_restart() {
        // Otherwise restarting is a way around the backoff — and a user
        // restarts an app that looks stuck, which is exactly when a device is
        // failing repeatedly.
        let meta = meta();
        record_failure(&meta, 1_000, 1.0).unwrap();
        record_failure(&meta, 6_000, 1.0).unwrap();

        let reloaded = load(&meta).unwrap();
        assert_eq!(reloaded.failures, 2);
        assert!(!reloaded.is_due(6_000));
        assert!(reloaded.is_due(16_000));
    }

    #[test]
    fn a_completed_cycle_clears_the_backoff() {
        let meta = meta();
        record_failure(&meta, 1_000, 1.0).unwrap();
        record_success(&meta).unwrap();

        let schedule = load(&meta).unwrap();
        assert_eq!(schedule.failures, 0);
        assert!(schedule.is_due(1_000), "a success must not leave a wait");
    }

    #[test]
    fn the_interface_can_say_how_long_is_left() {
        let meta = meta();
        let schedule = record_failure(&meta, 1_000, 1.0).unwrap();
        assert_eq!(schedule.wait_ms(1_000), 5_000);
        assert_eq!(schedule.wait_ms(4_000), 2_000);
        assert_eq!(
            schedule.wait_ms(60_000),
            0,
            "a due attempt has nothing left to wait"
        );
    }
}
