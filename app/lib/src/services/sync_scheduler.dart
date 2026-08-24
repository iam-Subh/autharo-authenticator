import 'dart:async';

import 'package:flutter/widgets.dart';

/// When a sync cycle runs (PRD section 10.3, OFF-05, OFF-06, OFF-08).
///
/// Section 10.3 names the triggers: "on application start, on a change, on a
/// push notification, and every 15 minutes in the foreground." Push signalling
/// is section 10.5 and is not built yet; the rest are here.
///
/// # Why this is separate from the controller
///
/// `SyncController` knows how to run a cycle. This knows *when*, and the when
/// is where the mistakes are: a timer that keeps firing in the background and
/// spends NFR-05's battery budget, five entries pasted in producing five
/// cycles, a device that lost its network retrying every fifteen minutes
/// forever because nothing consulted OFF-06's schedule.
///
/// None of those are visible in a normal session. They show up as a flat
/// battery or a server under load, hours later and somewhere else. So the
/// rules live in one place with no Flutter dependency beyond the lifecycle
/// enum, and they are tested with a fake clock rather than by waiting.
///
/// # Everything here is a request, not a command
///
/// Each trigger calls [SyncRunner.syncIfDue], which OFF-06's backoff is free to
/// decline. A scheduler that forced a cycle would be a way around the backoff,
/// and the triggers below fire often enough that it would be a wide one.
abstract interface class SyncRunner {
  /// Runs a cycle if the backoff schedule allows it.
  Future<void> syncIfDue();

  /// Whether this device has an account at all. Sync is optional (OFF-04), and
  /// a local-only device must never open a socket.
  bool get isSignedIn;
}

/// The interval in section 10.3.
const foregroundInterval = Duration(minutes: 15);

/// How long to wait after a local change before syncing.
///
/// Importing a file writes many entries in a row. Without this each one would
/// start a cycle, and the outbox would be pushed in dozens of requests instead
/// of one — against a server whose quota is measured in requests per minute
/// (NFR-11).
const changeDebounce = Duration(seconds: 2);

class SyncScheduler with WidgetsBindingObserver {
  SyncScheduler({
    required this.runner,
    Timer Function(Duration, void Function())? scheduleTimer,
  }) : _scheduleTimer = scheduleTimer ?? Timer.new;

  final SyncRunner runner;

  /// Injected so tests do not wait fifteen real minutes to find out whether
  /// the interval works.
  final Timer Function(Duration, void Function()) _scheduleTimer;

  Timer? _periodic;
  Timer? _debounce;
  bool _started = false;

  /// Begins scheduling, and runs the start-of-application cycle.
  void start() {
    if (_started) return;
    _started = true;
    WidgetsBinding.instance.addObserver(this);
    _resume();
  }

  void dispose() {
    if (!_started) return;
    _started = false;
    WidgetsBinding.instance.removeObserver(this);
    _periodic?.cancel();
    _debounce?.cancel();
    _periodic = null;
    _debounce = null;
  }

  /// A local write happened. Section 10.3's "on a change" trigger, debounced.
  void onLocalChange() {
    if (!_started) return;
    _debounce?.cancel();
    _debounce = _scheduleTimer(changeDebounce, _run);
  }

  /// The vault was opened.
  ///
  /// A separate entry point from [start] because it happens later and more
  /// often: the vault locks and reopens many times in a session, and each
  /// reopen is the moment a user is most likely to be looking at the list and
  /// least likely to forgive it being stale.
  void onUnlocked() => _run();

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        _resume();
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        // Section 10.3 says "every 15 minutes *in the foreground*". A timer
        // that survives into the background is how an application spends
        // NFR-05's one percent per day on nothing — and on Android it would be
        // killed unpredictably anyway, so it buys no reliability either.
        _periodic?.cancel();
        _periodic = null;
        _debounce?.cancel();
        _debounce = null;
    }
  }

  void _resume() {
    _run();
    _periodic?.cancel();
    _periodic = _scheduleTimer(foregroundInterval, _onInterval);
  }

  void _onInterval() {
    _run();
    // Re-armed rather than periodic, so the next interval is measured from the
    // end of this one. A periodic timer that fires while a slow cycle is still
    // running queues another immediately behind it.
    _periodic = _scheduleTimer(foregroundInterval, _onInterval);
  }

  void _run() {
    // Sync is optional (OFF-04). A device with no account has nothing to talk
    // to, and opening a socket to find that out would be both wasteful and, to
    // a user who chose local-only, a surprise.
    if (!runner.isSignedIn) return;

    // Deliberately not awaited: OFF-08 says a sync must not block the
    // interface, and every caller here is a lifecycle callback or a timer.
    // Failures are recorded by the core and surfaced through the status
    // indicator, which is where a user can act on them.
    unawaited(runner.syncIfDue());
  }
}
