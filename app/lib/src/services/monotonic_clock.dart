import 'package:flutter/services.dart';

/// A clock that counts across device sleep (PRD FR-33).
///
/// FR-33: "Read a monotonic clock that counts across device sleep, such as
/// `SystemClock.elapsedRealtime()` on Android."
///
/// The wall clock will not do. A user can set it backwards, and doing so would
/// hold the vault open. Dart's own `Stopwatch` will not do either: it reads
/// `CLOCK_MONOTONIC`, which stops while the device is in deep sleep, so a phone
/// left in a pocket overnight would come back as though no time had passed.
/// Only `elapsedRealtime` — `CLOCK_BOOTTIME` — keeps counting through both.
///
/// The value resets to zero on reboot. Callers must treat a reading lower than
/// one they stored as expired rather than as time travel; [LockController]
/// does.
abstract interface class MonotonicClock {
  /// Milliseconds since boot, including time spent asleep.
  Future<int> elapsedRealtime();
}

/// Reads `SystemClock.elapsedRealtime()` over a platform channel.
class PlatformMonotonicClock implements MonotonicClock {
  static const MethodChannel _channel =
      MethodChannel('app.autharo.authenticator/clock');

  @override
  Future<int> elapsedRealtime() async {
    final value = await _channel.invokeMethod<int>('elapsedRealtime');
    if (value == null) {
      // Refusing beats guessing. A fabricated reading here would either hold
      // the vault open or lock it at random, and both are worse than an error
      // the caller can decide about.
      throw StateError('The platform did not return a monotonic time.');
    }
    return value;
  }
}
