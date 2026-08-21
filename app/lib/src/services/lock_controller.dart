import 'package:flutter/widgets.dart';

/// What the lock controller needs from the vault.
///
/// Narrower than [VaultSession] on purpose. The timeout rules below are
/// ordinary logic with awkward edges — a clock that moved backwards, a
/// lifecycle event that does not mean what it looks like — and they should be
/// testable without a device, a keystore, or a real vault key.
abstract interface class LockTarget {
  bool get isOpen;
  void lock();
}

/// When the vault locks itself (FR-33, FR-34).
///
/// FR-33 lists the choices exactly: immediate, 15 s, 1 min, 5 min, 15 min, and
/// never. They are the enum rather than a free-form duration so that the
/// interface and the stored setting cannot drift apart.
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
///   last tap. A timer that ran in the foreground would lock the vault while
///   someone was reading a code off the screen.
///
/// Both are deliberately conservative about the clock. The elapsed time is
/// measured against the wall clock at the moment of backgrounding, because a
/// `Timer` does not reliably run while an Android application is suspended —
/// relying on one would mean a device that slept for an hour came back
/// unlocked.
class LockController with WidgetsBindingObserver {
  LockController({
    required LockTarget session,
    LockTimeout timeout = LockTimeout.after1Minute,
    bool lockOnBackground = false,
    VoidCallback? onLocked,
  })  : _session = session,
        _timeout = timeout,
        _lockOnBackground = lockOnBackground,
        _onLocked = onLocked;

  final LockTarget _session;
  final VoidCallback? _onLocked;

  LockTimeout _timeout;
  bool _lockOnBackground;

  /// When the application last left the foreground. Null while in it.
  DateTime? _leftForegroundAt;

  LockTimeout get timeout => _timeout;
  bool get lockOnBackground => _lockOnBackground;

  void start() => WidgetsBinding.instance.addObserver(this);

  void dispose() => WidgetsBinding.instance.removeObserver(this);

  set timeout(LockTimeout value) => _timeout = value;

  set lockOnBackground(bool value) => _lockOnBackground = value;

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

  void _onBackgrounded() {
    if (!_session.isOpen) return;

    _leftForegroundAt = DateTime.now();

    // FR-34, and FR-33's "immediately", which is the same instant.
    if (_lockOnBackground || _timeout == LockTimeout.immediately) {
      _lock();
    }
  }

  void _onResumed() {
    final left = _leftForegroundAt;
    _leftForegroundAt = null;

    if (left == null || !_session.isOpen) return;

    final limit = _timeout.duration;
    if (limit == null) return; // Never.

    // A clock that moved backwards while away — a manual change, or a time
    // zone shift — gives a negative difference. Treated as expired rather
    // than as no time having passed, because the alternative is a way to hold
    // the vault open indefinitely by winding the clock back.
    final away = DateTime.now().difference(left);
    if (away.isNegative || away >= limit) {
      _lock();
    }
  }

  /// Locks now, whatever the settings say. Used by an explicit **Lock**
  /// action, and by FR-36 before a security-relevant change.
  void lockNow() => _lock();

  void _lock() {
    if (!_session.isOpen) return;
    _session.lock();
    _onLocked?.call();
  }
}
