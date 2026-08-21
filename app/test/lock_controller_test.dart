import 'package:authenticator/src/services/lock_controller.dart';
import 'package:authenticator/src/services/monotonic_clock.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

/// A vault that records whether it was locked, without a keystore behind it.
class _FakeVault implements LockTarget {
  bool open = true;
  int lockCount = 0;

  @override
  bool get isOpen => open;

  @override
  void lock() {
    open = false;
    lockCount++;
  }
}

/// A clock the test drives. This is the point of injecting one: FR-33 is about
/// elapsed time across sleep and reboot, and neither is reachable in a test
/// that waits for a real clock.
class _FakeClock implements MonotonicClock {
  int now = 1000;
  bool broken = false;

  @override
  Future<int> elapsedRealtime() async {
    if (broken) throw StateError('no monotonic time');
    return now;
  }

  void advance(Duration by) => now += by.inMilliseconds;

  /// `elapsedRealtime` counts from boot, so a restart takes it back to near
  /// zero — the case FR-33 calls out.
  void reboot() => now = 5;
}

class _FakeStore implements LockPolicyStore {
  _FakeStore([this.stored = const LockPolicy()]);

  LockPolicy stored;
  int saves = 0;

  @override
  Future<LockPolicy> loadPolicy() async => stored;

  @override
  Future<void> savePolicy(LockPolicy policy) async {
    stored = policy;
    saves++;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _FakeVault vault;
  late _FakeClock clock;

  setUp(() {
    vault = _FakeVault();
    clock = _FakeClock();
  });

  LockController build({
    LockTimeout timeout = LockTimeout.after1Minute,
    bool lockOnBackground = false,
    LockPolicyStore? store,
  }) =>
      LockController(
        session: vault,
        clock: clock,
        store: store,
        policy: LockPolicy(
          timeout: timeout,
          lockOnBackground: lockOnBackground,
        ),
      );

  group('FR-34, lock when backgrounded', () {
    test('locks on leaving the foreground when the option is on', () async {
      final lock = build(lockOnBackground: true, timeout: LockTimeout.never);

      await lock.handleBackgrounded();

      expect(vault.lockCount, 1);
      expect(vault.isOpen, isFalse);
    });

    test('does not lock on backgrounding when the option is off', () async {
      final lock = build(timeout: LockTimeout.after15Minutes);

      await lock.handleBackgrounded();

      expect(vault.lockCount, 0, reason: 'the timeout decides, not the switch');
    });

    /// `inactive` fires for a notification shade pull and an incoming call.
    /// Locking on those would make the application unusable.
    test('ignores the inactive state', () {
      final lock = build(lockOnBackground: true);

      lock.didChangeAppLifecycleState(AppLifecycleState.inactive);

      expect(vault.lockCount, 0);
    });
  });

  group('FR-33, elapsed time in the background', () {
    test('immediately means on leaving the foreground', () async {
      final lock = build(timeout: LockTimeout.immediately);

      await lock.handleBackgrounded();

      expect(vault.lockCount, 1);
    });

    test('an absence shorter than the timeout does not lock', () async {
      final lock = build(timeout: LockTimeout.after1Minute);

      await lock.handleBackgrounded();
      clock.advance(const Duration(seconds: 59));
      await lock.handleResumed();

      expect(vault.lockCount, 0);
      expect(vault.isOpen, isTrue);
    });

    test('an absence at or past the timeout locks', () async {
      final lock = build(timeout: LockTimeout.after1Minute);

      await lock.handleBackgrounded();
      clock.advance(const Duration(seconds: 60));
      await lock.handleResumed();

      expect(vault.lockCount, 1);
    });

    /// The reason FR-33 names `elapsedRealtime` rather than a `Stopwatch`: a
    /// phone asleep in a pocket must still be counted as time away.
    test('time spent with the device asleep counts', () async {
      final lock = build(timeout: LockTimeout.after15Minutes);

      await lock.handleBackgrounded();
      clock.advance(const Duration(hours: 8));
      await lock.handleResumed();

      expect(vault.lockCount, 1, reason: 'eight hours is past fifteen minutes');
    });

    test('never leaves the vault open however long it was away', () async {
      final lock = build(timeout: LockTimeout.never);

      await lock.handleBackgrounded();
      clock.advance(const Duration(days: 7));
      await lock.handleResumed();

      expect(vault.lockCount, 0);
      expect(vault.isOpen, isTrue);
    });

    /// The rule is time spent away, so a resume with no prior background must
    /// not lock — that is what a first run looks like.
    test('a resume without a backgrounding does nothing', () async {
      final lock = build(timeout: LockTimeout.immediately);

      await lock.handleResumed();

      expect(vault.lockCount, 0);
    });
  });

  group('FR-33, the counter resetting', () {
    /// "Treat a value lower than the stored one as expired, because a reboot
    /// resets the counter." A reboot cannot mean less time passed.
    test('a reboot expires the session', () async {
      final lock = build(timeout: LockTimeout.after15Minutes);

      await lock.handleBackgrounded();
      clock.reboot();
      await lock.handleResumed();

      expect(vault.lockCount, 1, reason: 'a lower reading must not read as no time');
    });

    test('a clock failure locks rather than guessing', () async {
      final lock = build(timeout: LockTimeout.after15Minutes);

      await lock.handleBackgrounded();
      clock.broken = true;
      await lock.handleResumed();

      expect(vault.lockCount, 1);
    });

    test('a clock failure while backgrounding also locks', () async {
      final lock = build(timeout: LockTimeout.after15Minutes);
      clock.broken = true;

      await lock.handleBackgrounded();

      expect(
        vault.lockCount,
        1,
        reason: 'an unmeasurable absence must not be treated as no absence',
      );
    });
  });

  group('FR-33a, the policy survives a restart', () {
    test('the stored policy is loaded', () async {
      final store = _FakeStore(
        const LockPolicy(
          timeout: LockTimeout.after15Seconds,
          lockOnBackground: true,
        ),
      );
      final lock = build(store: store);

      await lock.loadPolicy();

      expect(lock.timeout, LockTimeout.after15Seconds);
      expect(lock.lockOnBackground, isTrue);
    });

    test('a change is written through', () async {
      final store = _FakeStore();
      final lock = build(store: store);

      await lock.setPolicy(
        const LockPolicy(timeout: LockTimeout.after5Minutes),
      );

      expect(store.saves, 1);
      expect(store.stored.timeout, LockTimeout.after5Minutes);

      // And a fresh controller over the same store sees it.
      final restarted = build(store: store);
      await restarted.loadPolicy();
      expect(restarted.timeout, LockTimeout.after5Minutes);
    });

    test('a loaded policy takes effect immediately', () async {
      final store = _FakeStore(
        const LockPolicy(timeout: LockTimeout.immediately),
      );
      final lock = build(timeout: LockTimeout.never, store: store);

      await lock.loadPolicy();
      await lock.handleBackgrounded();

      expect(vault.lockCount, 1, reason: 'the stored choice, not the default');
    });

    test('every choice round trips through seconds', () {
      for (final choice in LockTimeout.values) {
        expect(
          LockTimeout.fromSeconds(choice.seconds),
          choice,
          reason: '${choice.label} did not survive',
        );
      }
    });

    /// A value written by a version offering different choices must not switch
    /// the lock off.
    test('an unrecognised stored value falls back to a working timeout', () {
      expect(LockTimeout.fromSeconds(42), LockTimeout.after1Minute);
      expect(LockTimeout.fromSeconds(null), LockTimeout.never);
    });

    test('FR-33 lists exactly these choices', () {
      expect(
        LockTimeout.values.map((t) => t.label),
        containsAll(<String>[
          'Immediately',
          'After 15 seconds',
          'After 1 minute',
          'After 5 minutes',
          'After 15 minutes',
          'Never',
        ]),
      );
      expect(LockTimeout.never.duration, isNull);
    });
  });

  group('locking is idempotent and safe', () {
    test('a closed vault is not locked twice', () async {
      final lock = build(lockOnBackground: true);
      vault.open = false;

      await lock.handleBackgrounded();
      lock.lockNow();

      expect(vault.lockCount, 0, reason: 'nothing to lock');
    });

    test('lockNow locks whatever the settings say', () {
      final lock = build(timeout: LockTimeout.never);

      lock.lockNow();

      expect(vault.lockCount, 1);
    });
  });
}
