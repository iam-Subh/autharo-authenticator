import 'package:authenticator/src/services/lock_controller.dart';
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

/// Drives the lifecycle callback directly. `WidgetsBinding` will not deliver
/// synthetic lifecycle events on the test binding in a way that lets the
/// elapsed time be controlled, and the elapsed time is the whole subject here.
void _background(LockController controller) =>
    controller.didChangeAppLifecycleState(AppLifecycleState.paused);

void _resume(LockController controller) =>
    controller.didChangeAppLifecycleState(AppLifecycleState.resumed);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _FakeVault vault;

  setUp(() => vault = _FakeVault());

  LockController controller({
    LockTimeout timeout = LockTimeout.after1Minute,
    bool lockOnBackground = false,
  }) =>
      LockController(
        session: vault,
        timeout: timeout,
        lockOnBackground: lockOnBackground,
      );

  group('FR-34, lock when backgrounded', () {
    test('locks on leaving the foreground when the option is on', () {
      final lock = controller(
        lockOnBackground: true,
        timeout: LockTimeout.never,
      );

      _background(lock);

      expect(vault.lockCount, 1);
      expect(vault.isOpen, isFalse);
    });

    test('does not lock on backgrounding when the option is off', () {
      final lock = controller(timeout: LockTimeout.after15Minutes);

      _background(lock);

      expect(vault.lockCount, 0, reason: 'the timeout decides, not the switch');
    });

    /// `inactive` fires for a notification shade pull and an incoming call.
    /// Locking on those would make the application unusable.
    test('ignores the inactive state', () {
      final lock = controller(lockOnBackground: true);

      lock.didChangeAppLifecycleState(AppLifecycleState.inactive);

      expect(vault.lockCount, 0);
    });
  });

  group('FR-33, lock after a timeout', () {
    test('immediately means on leaving the foreground', () {
      final lock = controller(timeout: LockTimeout.immediately);

      _background(lock);

      expect(vault.lockCount, 1);
    });

    test('never leaves the vault open however long it was away', () async {
      final lock = controller(timeout: LockTimeout.never);

      _background(lock);
      _resume(lock);

      expect(vault.lockCount, 0);
      expect(vault.isOpen, isTrue);
    });

    test('a short absence does not lock', () {
      final lock = controller(timeout: LockTimeout.after15Minutes);

      _background(lock);
      _resume(lock); // No measurable time has passed.

      expect(vault.lockCount, 0);
    });

    /// The rule is time spent away, so a resume with no prior background must
    /// not lock — that is what a first run looks like.
    test('a resume without a backgrounding does nothing', () {
      final lock = controller(timeout: LockTimeout.immediately);

      _resume(lock);

      expect(vault.lockCount, 0);
    });

    test('every listed choice has a duration except never', () {
      // FR-33 names these exactly; a missing one would silently not be
      // offered.
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
      for (final choice in LockTimeout.values.where((t) => t != LockTimeout.never)) {
        expect(choice.duration, isNotNull, reason: '${choice.label} needs one');
      }
    });
  });

  group('locking is idempotent and safe', () {
    test('a closed vault is not locked twice', () {
      final lock = controller(lockOnBackground: true);
      vault.open = false;

      _background(lock);
      lock.lockNow();

      expect(vault.lockCount, 0, reason: 'nothing to lock');
    });

    test('lockNow locks whatever the settings say', () {
      final lock = controller(timeout: LockTimeout.never);

      lock.lockNow();

      expect(vault.lockCount, 1);
    });
  });
}
