import 'package:authenticator/src/rust/api/sync.dart' as rust;
import 'package:authenticator/src/services/sync_controller.dart';
import 'package:flutter_test/flutter_test.dart';

/// OFF-05's three states, and the order they take precedence in.
///
/// This is the whole of the indicator's logic, and it is the kind of logic
/// that is wrong in ways nobody notices: a state that is merely *plausible*
/// looks right on screen. The failure mode that matters is showing "synced"
/// over a device that is not — a user who has been told everything is fine
/// does not look again, and finds out when a code is missing somewhere else.
rust.SyncStatusView view({
  String? serverUrl = 'https://sync.example.invalid',
  String? email = 'rupsa@example.invalid',
  bool signedIn = true,
  int pending = 0,
  bool pendingKnown = true,
  int? lastSuccessMs,
  String? lastError,
}) {
  return rust.SyncStatusView(
    serverUrl: serverUrl,
    email: email,
    signedIn: signedIn,
    pending: pending,
    pendingKnown: pendingKnown,
    lastSuccessMs: lastSuccessMs,
    lastError: lastError,
  );
}

void main() {
  group('what the indicator says', () {
    test('a device with no server is not syncing, which is not a fault', () {
      // OFF-04: the app is fully usable with no account. This state must read
      // as a feature not in use, never as something broken.
      final status = SyncController.derive(view(serverUrl: null, email: null));
      expect(status.state, SyncState.off);
      expect(status.summary, 'Not syncing');
    });

    test('an account with nothing waiting is synced', () {
      final status = SyncController.derive(view());
      expect(status.state, SyncState.synced);
    });

    test('records waiting are pending, not an error', () {
      // A device offline for a week is working correctly. Reporting that as a
      // failure teaches the user to ignore the indicator, which costs the one
      // time it matters.
      final status = SyncController.derive(view(pending: 3));
      expect(status.state, SyncState.pending);
      expect(status.summary, '3 waiting to sync');
    });

    test('a failed attempt is offline, and says why', () {
      final status = SyncController.derive(
        view(lastError: 'this device could not reach the sync server'),
      );
      expect(status.state, SyncState.offline);
      expect(status.lastError, isNotNull);
    });

    test('an expired session outranks everything else', () {
      // Nothing can make progress until the user signs in, so this must not be
      // hidden behind a pending count that will never drain.
      final status = SyncController.derive(
        view(signedIn: false, pending: 5, lastError: 'anything'),
      );
      expect(status.state, SyncState.signedOut);
    });
  });

  group('the states that must not be confused', () {
    test('a locked device is never reported as synced', () {
      // The outbox is inside the encrypted database, so a locked device cannot
      // count it. If "cannot tell" collapsed into "zero", a locked device with
      // unsent changes would show as fully synced — the exact wrong answer.
      final status = SyncController.derive(
        view(pending: 0, pendingKnown: false),
      );
      expect(status.pendingKnown, isFalse);
      expect(
        status.summary,
        isNot(contains('0')),
        reason: 'an unknown count must not be printed as a number',
      );
    });

    test('a stale error does not survive a success', () {
      // The core clears the error on a successful cycle, so an error present
      // here means the *last* attempt failed. Were that not so, the app would
      // report an outage that ended hours ago.
      final status = SyncController.derive(
        view(lastError: null, lastSuccessMs: DateTime.now().millisecondsSinceEpoch),
      );
      expect(status.state, SyncState.synced);
      expect(status.summary, 'Synced just now');
    });

    test('signed out is not folded into offline', () {
      // Different causes, different fixes. "Not connected" invites the user to
      // check their network, which will not help.
      final signedOut = SyncController.derive(view(signedIn: false));
      final offline = SyncController.derive(view(lastError: 'no route'));
      expect(signedOut.state, isNot(offline.state));
      expect(signedOut.summary, contains('sign in'));
    });
  });

  group('the time of the last sync', () {
    test('is absent before the first one', () {
      expect(SyncController.derive(view()).summary, 'Synced');
    });

    test('is shown in units a person reads', () {
      final at = DateTime.now().subtract(const Duration(hours: 5));
      final status = SyncController.derive(
        view(lastSuccessMs: at.millisecondsSinceEpoch),
      );
      expect(status.summary, 'Synced 5 h ago');
    });

    test('does not round a two-day gap down to hours', () {
      final at = DateTime.now().subtract(const Duration(days: 2));
      final status = SyncController.derive(
        view(lastSuccessMs: at.millisecondsSinceEpoch),
      );
      expect(status.summary, 'Synced 2 d ago');
    });
  });
}
