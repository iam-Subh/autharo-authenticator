import 'dart:async';

import 'package:authenticator/src/services/sync_scheduler.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

/// Counts cycles and says whether this device has an account.
class FakeRunner implements SyncRunner {
  FakeRunner({this.isSignedIn = true});

  @override
  bool isSignedIn;

  int runs = 0;

  @override
  Future<void> syncIfDue() async => runs++;
}

/// A timer that fires when the test says so.
///
/// The alternative is waiting fifteen real minutes to find out whether the
/// interval works, which means nobody ever checks it.
///
/// It keeps a current time rather than treating every delay as relative to the
/// start of the call. The first version did not, so a timer that re-armed
/// itself for fifteen minutes was immediately due again inside the same
/// advance, and looped until the guard tripped. A fake clock without a clock
/// tests the fake, not the code.
class FakeClock {
  Duration _now = Duration.zero;
  final _pending = <_Scheduled>[];

  Timer schedule(Duration delay, void Function() callback) {
    final entry = _Scheduled(_now + delay, callback);
    _pending.add(entry);
    return entry.timer;
  }

  /// Moves time forward, firing what falls due on the way, in order.
  void advance(Duration elapsed) {
    final target = _now + elapsed;

    while (true) {
      final due = _pending.where((entry) => !entry.cancelled && entry.at <= target).toList()
        ..sort((a, b) => a.at.compareTo(b.at));
      if (due.isEmpty) break;

      final next = due.first;
      _pending.remove(next);
      // Time is at the moment of firing, so anything the callback arms is
      // measured from there — which is what a real timer does.
      _now = next.at;
      next.callback();
    }

    _now = target;
  }

  int get armed => _pending.where((entry) => !entry.cancelled).length;
}

class _Scheduled {
  _Scheduled(this.at, this.callback) {
    timer = _FakeTimer(() => cancelled = true);
  }

  /// Absolute, not a delay.
  final Duration at;
  final void Function() callback;
  late final Timer timer;
  bool cancelled = false;
}

class _FakeTimer implements Timer {
  _FakeTimer(this._onCancel);

  final void Function() _onCancel;
  bool _active = true;

  @override
  void cancel() {
    _active = false;
    _onCancel();
  }

  @override
  bool get isActive => _active;

  @override
  int get tick => 0;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late FakeRunner runner;
  late FakeClock clock;
  late SyncScheduler scheduler;

  setUp(() {
    runner = FakeRunner();
    clock = FakeClock();
    scheduler = SyncScheduler(runner: runner, scheduleTimer: clock.schedule);
  });

  tearDown(() => scheduler.dispose());

  group('section 10.3 triggers', () {
    test('starting the application syncs', () {
      scheduler.start();
      expect(runner.runs, 1);
    });

    test('unlocking syncs', () {
      // The moment a user is most likely to be looking at the list, and least
      // likely to forgive it being stale.
      scheduler.start();
      scheduler.onUnlocked();
      expect(runner.runs, 2);
    });

    test('the foreground interval is fifteen minutes', () {
      scheduler.start();
      expect(runner.runs, 1);

      clock.advance(const Duration(minutes: 14));
      expect(runner.runs, 1, reason: 'it must not fire early');

      clock.advance(foregroundInterval);
      expect(runner.runs, 2);
    });

    test('the interval keeps firing', () {
      scheduler.start();
      clock.advance(foregroundInterval);
      clock.advance(foregroundInterval);
      expect(runner.runs, greaterThanOrEqualTo(2));
    });
  });

  group('a local change', () {
    test('syncs, after a pause', () {
      scheduler.start();
      scheduler.onLocalChange();
      expect(runner.runs, 1, reason: 'not immediately');

      clock.advance(changeDebounce);
      expect(runner.runs, 2);
    });

    test('several changes in a row produce one cycle', () {
      // Importing a file writes many entries. One cycle per entry would push
      // the outbox in dozens of requests against a per-minute quota (NFR-11),
      // and would be slower than a single push besides.
      scheduler.start();
      for (var i = 0; i < 20; i++) {
        scheduler.onLocalChange();
      }
      clock.advance(changeDebounce);

      expect(
        runner.runs,
        2,
        reason: 'the start cycle, then one for the whole burst',
      );
    });
  });

  group('the background', () {
    test('no timer survives being backgrounded', () {
      // NFR-05 allows one percent of battery per day. A timer left running
      // spends it on nothing, and Android would kill it unpredictably anyway.
      scheduler.start();
      expect(clock.armed, greaterThan(0));

      scheduler.didChangeAppLifecycleState(AppLifecycleState.paused);
      expect(clock.armed, 0);

      clock.advance(const Duration(hours: 6));
      expect(runner.runs, 1, reason: 'nothing should have fired');
    });

    test('coming back to the foreground syncs and re-arms', () {
      scheduler.start();
      scheduler.didChangeAppLifecycleState(AppLifecycleState.paused);
      scheduler.didChangeAppLifecycleState(AppLifecycleState.resumed);

      expect(runner.runs, 2, reason: 'returning is a trigger in its own right');

      clock.advance(foregroundInterval);
      expect(runner.runs, 3, reason: 'and the interval is running again');
    });

    test('a pending change does not fire from the background', () {
      scheduler.start();
      scheduler.onLocalChange();
      scheduler.didChangeAppLifecycleState(AppLifecycleState.paused);

      clock.advance(const Duration(hours: 1));
      expect(runner.runs, 1);
    });
  });

  group('a device with no account', () {
    test('never syncs, whatever happens', () {
      // OFF-04: the app is fully usable with no account. A local-only device
      // opening a socket would be wasteful and, to someone who chose local
      // only, a surprise.
      runner.isSignedIn = false;
      scheduler.start();
      scheduler.onUnlocked();
      scheduler.onLocalChange();
      clock.advance(foregroundInterval);
      clock.advance(foregroundInterval);

      expect(runner.runs, 0);
    });

    test('starts syncing once an account exists', () {
      runner.isSignedIn = false;
      scheduler.start();
      expect(runner.runs, 0);

      runner.isSignedIn = true;
      clock.advance(foregroundInterval);
      expect(runner.runs, 1);
    });
  });

  group('shutting down', () {
    test('disposing stops everything', () {
      scheduler.start();
      scheduler.onLocalChange();
      scheduler.dispose();

      clock.advance(const Duration(hours: 6));
      expect(runner.runs, 1, reason: 'a disposed scheduler must be silent');
    });

    test('starting twice does not double every cycle', () {
      scheduler.start();
      scheduler.start();
      clock.advance(foregroundInterval);

      expect(runner.runs, 2, reason: 'one start cycle and one interval cycle');
    });
  });
}
