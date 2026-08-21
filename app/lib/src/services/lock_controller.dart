import 'package:flutter/widgets.dart';

import 'monotonic_clock.dart';

/// What the lock controller needs from the vault.
///
/// Narrower than `VaultSession` on purpose. The rules below are ordinary logic
/// with awkward edges — a clock that reset under us, a lifecycle event that
/// does not mean what it looks like — and they should be testable without a
/// device, a keystore, or a real vault key.
abstract interface class LockTarget {
  bool get isOpen;
  void lock();
}

/// Where the lock policy is kept between runs (FR-33a).
abstract interface class LockPolicyStore {
  Future<LockPolicy> loadPolicy();
  Future<void> savePolicy(LockPolicy policy);
}

/// When to lock (FR-33, FR-34).
@immutable
class LockPolicy {
  const LockPolicy({
    this.timeout = LockTimeout.after1Minute,
    this.lockOnBackground = false,
  });

  final LockTimeout timeout;
  final bool lockOnBackground;

  LockPolicy copyWith({LockTimeout? timeout, bool? lockOnBackground}) =>
      LockPolicy(
        timeout: timeout ?? this.timeout,
        lockOnBackground: lockOnBackground ?? this.lockOnBackground,
      );

  @override
  bool operator ==(Object other) =>
      other is LockPolicy &&
      other.timeout == timeout &&
      other.lockOnBackground == lockOnBackground;

  @override
  int get hashCode => Object.hash(timeout, lockOnBackground);
}

/// FR-33's list, exactly: immediate, 15 s, 1 min, 5 min, 15 min, and never.
///
/// An enum rather than a free-form duration so the interface and the stored
/// setting cannot drift apart.
enum LockTimeout {
  immediately(Duration.zero, 'Immediately'),
  after15Seconds(Duration(seconds: 15), 'After 15 seconds'),
  after1Minute(Duration(minutes: 1), 'After 1 minute'),
  after5Minutes(Duration(minutes: 5), 'After 5 minutes'),
  after15Minutes(Duration(minutes: 15), 'After 15 minutes'),
  never(null, 'Never');

  const LockTimeout(this.duration, this.label);

  /// Null means no automatic lock at all.
  final Duration? duration;
  final String label;

  /// Seconds for the core, which stores a number rather than a name. Null is
  /// "never".
  int? get seconds => duration?.inSeconds;

  /// The choice matching a stored value, falling back to one minute.
  ///
  /// A stored value that matches nothing means the setting was written by a
  /// version offering different choices. Falling back to the default keeps a
  /// working lock; falling back to "never" would silently switch it off.
  static LockTimeout fromSeconds(int? seconds) {
    if (seconds == null) return LockTimeout.never;
    for (final choice in LockTimeout.values) {
      if (choice.seconds == seconds) return choice;
    }
    return LockTimeout.after1Minute;
  }
}

/// Locks the vault when it should be locked.
///
/// FR-31 is what makes this worth having: locking drops the vault key, so this
/// is not a screen that hides content. Every path here ends in the same call,
/// and after it the records genuinely cannot be read.
///
/// Two triggers, and they are different questions:
///
/// - **Backgrounding** (FR-34) is a user action. It fires as soon as the
///   application leaves the foreground, if the option is on.
/// - **The timeout** (FR-33) measures time spent *away*, not time since the
///   last tap. A timer running in the foreground would lock the vault while
///   someone was reading a code off the screen.
///
/// # The clock
///
/// FR-33 requires a monotonic clock that counts across sleep. Three things
/// could go here and only one is right:
///
/// - The wall clock can be set backwards, which would hold the vault open.
/// - `CLOCK_MONOTONIC` stops during deep sleep, so a phone in a pocket
///   overnight returns as though no time passed.
/// - `elapsedRealtime` (`CLOCK_BOOTTIME`) counts through both, and resets on
///   reboot — which is why a reading *lower* than the stored one is treated as
///   expired. A reboot cannot mean less time passed; it means the vault should
///   not still be open.
class LockController with WidgetsBindingObserver {
  LockController({
    required LockTarget session,
    required MonotonicClock clock,
    LockPolicyStore? store,
    LockPolicy policy = const LockPolicy(),
    VoidCallback? onLocked,
  })  : _session = session,
        _clock = clock,
        _store = store,
        _policy = policy,
        _onLocked = onLocked;

  final LockTarget _session;
  final MonotonicClock _clock;
  final LockPolicyStore? _store;
  final VoidCallback? _onLocked;

  LockPolicy _policy;

  /// The monotonic reading when the application last left the foreground.
  /// Null while in the foreground.
  int? _leftForegroundAt;

  LockPolicy get policy => _policy;
  LockTimeout get timeout => _policy.timeout;
  bool get lockOnBackground => _policy.lockOnBackground;

  void start() => WidgetsBinding.instance.addObserver(this);

  void dispose() => WidgetsBinding.instance.removeObserver(this);

  /// Loads the stored policy (FR-33a). Call before [start].
  Future<void> loadPolicy() async {
    final store = _store;
    if (store == null) return;
    _policy = await store.loadPolicy();
  }

  /// Changes the policy and writes it through, so it survives a restart.
  Future<void> setPolicy(LockPolicy policy) async {
    _policy = policy;
    await _store?.savePolicy(policy);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        _onResumed();
      case AppLifecycleState.inactive:
        // Deliberately ignored. `inactive` fires for a notification shade pull
        // or an incoming call overlay, and locking on those would be constant.
        break;
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        _onBackgrounded();
    }
  }

  /// Visible for tests, which need to await what the lifecycle callback starts.
  @visibleForTesting
  Future<void> handleBackgrounded() => _onBackgrounded();

  @visibleForTesting
  Future<void> handleResumed() => _onResumed();

  Future<void> _onBackgrounded() async {
    if (!_session.isOpen) return;

    // FR-34, and FR-33's "immediately", which is the same instant. Done before
    // the clock read so that the strictest settings do not depend on a channel
    // call completing while the application is being suspended.
    if (_policy.lockOnBackground || _policy.timeout == LockTimeout.immediately) {
      _lock();
      return;
    }
    if (_policy.timeout == LockTimeout.never) return;

    try {
      _leftForegroundAt = await _clock.elapsedRealtime();
    } catch (_) {
      // No reading means no way to measure the absence. Locking is the safe
      // failure: the user re-enters a PIN, rather than the vault staying open
      // for an unmeasured length of time.
      _lock();
    }
  }

  Future<void> _onResumed() async {
    final left = _leftForegroundAt;
    _leftForegroundAt = null;

    if (left == null || !_session.isOpen) return;

    final limit = _policy.timeout.duration;
    if (limit == null) return; // Never.

    final int now;
    try {
      now = await _clock.elapsedRealtime();
    } catch (_) {
      _lock();
      return;
    }

    // FR-33: "Treat a value lower than the stored one as expired, because a
    // reboot resets the counter."
    if (now < left) {
      _lock();
      return;
    }

    if (Duration(milliseconds: now - left) >= limit) {
      _lock();
    }
  }

  /// Locks now, whatever the settings say. Used by an explicit **Lock**
  /// action, and by FR-36 before a security-relevant change.
  void lockNow() => _lock();

  void _lock() {
    _leftForegroundAt = null;
    if (!_session.isOpen) return;
    _session.lock();
    _onLocked?.call();
  }
}
