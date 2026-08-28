// The stage S5 device check: a record moves between this phone and a real
// server.
//
// # Why this exists as a test and not as a button
//
// The Android build being green proves the crate links. It does not prove the
// bridge reaches the Rust, that the Rust reaches the network, or that the
// server accepts what it is sent. Every one of those was green while the whole
// sync API was unreachable from Dart, because nobody had regenerated the
// bridge.
//
// A throwaway button would answer the question once, for whoever was holding
// the phone. This answers it every time anyone runs it, in the terminal, with
// a reason when it fails.
//
// # It talks to a real server on purpose
//
// `core/tests/convergence_http.rs` already drives the same transport against
// the same server from the desktop. What it cannot cover is this device: its
// bridge, its network stack, its TLS, and the `.so` that was actually packaged.
// That is the whole point, and it is why this file asserts almost nothing about
// sync semantics — those are covered where they can be tested properly, in the
// harness.
//
// # Running it
//
//   cd server
//   BIND=0.0.0.0:8080 cargo run
//
//   cd app
//   flutter test integration_test/sync_test.dart -d <device> \
//     --dart-define=SYNC_URL=http://<this machine on the LAN>:8080
//
// The phone cannot reach the desktop's localhost, and the server binds
// 127.0.0.1 unless told otherwise, so both halves of that are needed.

import 'package:authenticator/src/rust/api/sync.dart' as sync_api;
import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:authenticator/src/services/vault_session.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Where the server is. No default worth having: `localhost` is this phone, and
/// a wrong address fails as a connection error several steps later, which reads
/// like a bug in the client.
const syncUrl = String.fromEnvironment('SYNC_URL');

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final added = <String>[];

  setUpAll(() async {
    await RustLib.init();

    final session = VaultSession();
    switch (await session.load()) {
      case VaultState.needsSetup:
        await session.setUp(requireUserAuthentication: false);
      case VaultState.locked:
        await session.unlock();
      case VaultState.lockedNeedsPin:
        // Not a defect in the app — the phone has been used by hand and a
        // PIN was set. The tests cannot open a vault whose PIN they do not
        // know, and guessing would burn FR-35's failed-attempt counter.
        fail(
          'This device has a PIN on its vault, so the tests cannot open it. '
          'Either remove the PIN in Settings, or reinstall the app with '
          '"adb uninstall app.autharo.authenticator". Reinstalling destroys '
          'the codes on the device, so export a backup first if any of them '
          'matter.',
        );
    }
  });

  tearDown(() async {
    for (final id in added) {
      await rust.deleteEntry(
        id: id,
        nowMs: DateTime.now().millisecondsSinceEpoch,
      );
    }
    added.clear();
  });

  test('the address of a server was supplied', () {
    expect(
      syncUrl,
      isNotEmpty,
      reason:
          'Pass --dart-define=SYNC_URL=http://<host>:8080. Without it the '
          'test below would fail as a connection error and read like a defect '
          'in the client.',
    );
  });

  test(
    'a record reaches a real server from this device',
    () async {
      // A fresh account per run. `create_account` re-wraps the vault key this
      // device already holds — section 9.2.4 forbids minting a new one — so the
      // entries below survive it.
      final email =
          'device-${DateTime.now().microsecondsSinceEpoch.toRadixString(16)}'
          '@example.invalid';
      const password = 'device-test-password-that-is-long-enough';

      final recovery = await rust.createAccount(
        email: email,
        password: password,
      );
      await sync_api.setServerUrl(url: syncUrl);

      // One entry, so there is something to push that was not there before.
      final outcome = await rust.addFromUri(
        uri:
            'otpauth://totp/DeviceProbe:one?secret=GEZDGNBVGY3TQOJQ'
            '&issuer=DeviceProbe',
        nowMs: DateTime.now().millisecondsSinceEpoch,
      );
      expect(
        outcome.addedId,
        isNotNull,
        reason: 'the entry has to exist before a push can carry it',
      );
      added.add(outcome.addedId!);

      await sync_api.registerAccount(
        password: password,
        recoveryPhrase: recovery.phrase,
        deviceName: 'probe',
        identityToken: 'development-test-token',
      );

      final status = sync_api.syncStatus();
      expect(
        status.signedIn,
        isTrue,
        reason: 'registration should sign in too',
      );
      expect(status.serverUrl, syncUrl);

      // Forced, because a test asking for a cycle is the same case as a user
      // pressing the button: OFF-06's backoff is for automatic retries, and a
      // test made to wait it out would be a test of the backoff instead.
      final first = await sync_api.syncNow(force: true);
      expect(first.needsSignIn, isFalse);
      expect(
        first.pushed,
        greaterThanOrEqualTo(1),
        reason:
            'the entry added above was in the outbox, so a cycle must carry it '
            'to the server. Zero here means the bridge, the transport or the '
            'server did not do its half.',
      );

      // A second cycle with nothing new. It pulls back what the first pushed,
      // because a push does not move the cursor — and that record must not be
      // treated as a rival version of itself. When it was, every entry a device
      // pushed stopped producing codes until the next unlock.
      final second = await sync_api.syncNow(force: true);
      expect(second.needsSignIn, isFalse);
      expect(
        second.countersCorrected,
        0,
        reason: 'a record coming back unchanged is not a conflict',
      );
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    "a sync measures and corrects this device's clock",
    () async {
      // FR-37, FR-38. The one defect in this project that is invisible from
      // inside: every code is generated correctly for the time the device
      // believes it is, and the answer is still wrong. The user sees "invalid
      // code" with no explanation and blames the app or their account.
      //
      // Proved by putting a wrong offset in deliberately and watching a cycle
      // replace it. A test that only checked "an offset exists" would pass
      // against a device whose clock happens to be right, which is most of them.
      await rust.setTimeOffsetSeconds(offset: 9999);
      expect(await rust.timeOffsetSeconds(), 9999);

      await sync_api.syncNow(force: true);

      final corrected = await rust.timeOffsetSeconds();
      expect(
        corrected,
        isNot(9999),
        reason:
            'the cycle read a Date header and should have replaced the nonsense. '
            'Unchanged means nothing measured the clock — check that the server '
            'sends a Date header and that the client reads it.',
      );

      // The development server and this device share a network and, usually, a
      // clock. The point is not that the answer is zero — it is that the answer
      // is now a measurement rather than the number that was planted.
      expect(
        corrected.abs(),
        lessThan(60),
        reason: 'a measured offset against a nearby server should be small',
      );
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test('signing out leaves the codes alone', () async {
    final before = await rust.listEntries(
      nowUnixSeconds: DateTime.now().millisecondsSinceEpoch ~/ 1000,
    );

    await sync_api.signOut();

    final after = await rust.listEntries(
      nowUnixSeconds: DateTime.now().millisecondsSinceEpoch ~/ 1000,
    );
    expect(
      after.length,
      before.length,
      reason: 'signing out of sync must not cost the user their codes',
    );
    expect(sync_api.syncStatus().signedIn, isFalse);
  });
}
