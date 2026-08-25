import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'dart:io';

import 'package:authenticator/src/services/vault_session.dart';
import 'package:path_provider/path_provider.dart';

/// On-device tests for the Rust bridge.
///
/// The unit tests in `core/tests` already prove the OTP engine against the RFC
/// vectors on the host. What they cannot prove is that the same engine, cross
/// compiled for Android and reached over the bridge, returns the same answer.
/// That is what this file is for, and it is the evidence behind the stage S2
/// exit criterion in section 18.
/// The budget for a test that runs Argon2id at section 9.2.1's real cost.
///
/// 64 MiB and three iterations takes about fourteen seconds on a mid-range
/// phone, and these tests derive two or three keys each. That is over
/// `package:test`'s thirty-second default — and it was under it only while the
/// handset was cool. The same test passed all session and then timed out at
/// twenty-eight seconds once a warm device started throttling.
///
/// Lowering the cost would make the tests fast and stop them testing the thing
/// that matters, because the cost *is* the security property. So the budget is
/// raised and named instead. A flaky timeout on a security test is worse than a
/// slow one: it teaches whoever sees it to re-run rather than look.
const argon2idBudget = Timeout(Duration(minutes: 4));

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final session = VaultSession();

  setUpAll(() async {
    await RustLib.init();

    // The real device-slot path: read the metadata file, then either create a
    // keystore-wrapped vault key or unwrap the existing one. This is the only
    // way the vault opens, so the tests below also prove section 9.2.4 works
    // against a real Android Keystore rather than a stub.
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
          '"adb uninstall dev.authcore.authenticator". Reinstalling destroys '
          'the codes on the device, so export a backup first if any of them '
          'matter.',
        );
    }
  });

  /// RFC 6238 Appendix B: the SHA-1 seed at T=59 gives 94287082 at 8 digits.
  const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  test('the vault opens through the Android Keystore', () {
    expect(rust.isVaultOpen(), isTrue);
  });

  /// Section 9.2.4: the key on disk is wrapped, and only the keystore can
  /// open it. If this ever returns the raw key, the vault is unprotected.
  test('the stored key is not the vault key', () async {
    final blob = await rust.beginDeviceOpen();

    expect(blob.scheme, 'keystore-v1');
    expect(blob.needsPin, isFalse);
    expect(blob.nonce.length, 12, reason: 'AES-GCM nonce');
    expect(
      blob.wrapped.length,
      greaterThan(32),
      reason: 'a wrapped 32-byte key carries a GCM tag, so it is longer',
    );

    // Finish the handshake this test opened, or the next unlock would find
    // one already pending.
    await session.unlock();
  });

  test('an entry added over the bridge generates the RFC 6238 code', () async {
    final outcome = await rust.addFromUri(
      uri:
          'otpauth://totp/RFC6238:appendix-b'
          '?secret=$rfcSecret&issuer=RFC6238&digits=8&period=30',
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
    final id = outcome.addedId ?? outcome.duplicateOf;
    expect(id, isNotNull);

    // T=59 is the first published vector.
    final entries = await rust.listEntries(nowUnixSeconds: 59);
    final entry = entries.firstWhere((e) => e.id == id);

    expect(
      entry.code,
      '94287082',
      reason: 'the Android build of the core must agree with RFC 6238',
    );
    expect(entry.digits, 8);
    expect(
      entry.remainingSeconds,
      1,
      reason: 'T=59 is one second from the step boundary',
    );

    await rust.deleteEntry(
      id: id!,
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
  });

  test(
    'a duplicate secret is reported rather than stored twice (FR-16)',
    () async {
      const uri = 'otpauth://totp/Duplicate:test?secret=$rfcSecret';
      final now = DateTime.now().millisecondsSinceEpoch;

      final first = await rust.addFromUri(uri: uri, nowMs: now);
      expect(first.addedId, isNotNull);

      final second = await rust.addFromUri(uri: uri, nowMs: now);
      expect(second.addedId, isNull);
      expect(second.duplicateOf, first.addedId);

      await rust.deleteEntry(id: first.addedId!, nowMs: now);
    },
  );

  test('an HOTP counter advances and never repeats a code', () async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final added = await rust.addFromUri(
      uri:
          'otpauth://hotp/RFC4226:appendix-d'
          '?secret=$rfcSecret&issuer=RFC4226&counter=0',
      nowMs: now,
    );
    final id = added.addedId!;

    // RFC 4226 Appendix D, counters 0 through 3.
    final expected = ['755224', '287082', '359152', '969429'];

    final entries = await rust.listEntries(nowUnixSeconds: 0);
    expect(entries.firstWhere((e) => e.id == id).code, expected[0]);

    for (var counter = 1; counter < expected.length; counter++) {
      final code = await rust.advanceHotp(id: id, nowMs: now + counter);
      expect(
        code,
        expected[counter],
        reason: 'HOTP counter $counter must match RFC 4226 Appendix D',
      );
    }

    await rust.deleteEntry(id: id, nowMs: now);
  });

  test('an invalid secret is refused with a readable reason (FR-09)', () async {
    expect(
      () => rust.addFromUri(
        uri: 'otpauth://totp/Bad:entry?secret=NOT!BASE32',
        nowMs: DateTime.now().millisecondsSinceEpoch,
      ),
      throwsA(
        predicate(
          (error) => error.toString().contains('Base32'),
          'an error naming the problem, not a generic failure',
        ),
      ),
    );
  });

  test('an HOTP entry with no counter is refused (FR-15d)', () async {
    expect(
      () => rust.addFromUri(
        uri: 'otpauth://hotp/NoCounter:test?secret=$rfcSecret',
        nowMs: DateTime.now().millisecondsSinceEpoch,
      ),
      throwsA(
        predicate(
          (error) => error.toString().toLowerCase().contains('counter'),
          'the reason must name the missing counter',
        ),
      ),
    );
  });

  test('entries survive locking and unlocking the vault', () async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final added = await rust.addFromUri(
      uri: 'otpauth://totp/Persisted:test?secret=$rfcSecret',
      nowMs: now,
    );
    final id = added.addedId!;

    // FR-31: locking zeroes the vault key, so this is not a screen change.
    session.lock();
    expect(rust.isVaultOpen(), isFalse);

    // And the entries are genuinely unreachable while locked.
    await expectLater(
      rust.listEntries(nowUnixSeconds: 0),
      throwsA(predicate((e) => e.toString().contains('locked'))),
    );

    await session.unlock();
    expect(rust.isVaultOpen(), isTrue);

    final entries = await rust.listEntries(
      nowUnixSeconds: DateTime.now().millisecondsSinceEpoch ~/ 1000,
    );
    expect(entries.map((e) => e.id), contains(id));

    await rust.deleteEntry(id: id, nowMs: now);
  });

  /// The end-to-end version of the inverted `pipeline.rs` assertion: not that
  /// the cipher works, but that what actually lands on this device's flash
  /// cannot be read.
  ///
  /// Worth doing separately from the core test because everything between the
  /// cipher and the file — the bridge, the store, SQLite's own paging — could
  /// in principle write a copy of the plaintext somewhere the core never sees.
  test('nothing readable reaches the database file', () async {
    final directory = await getApplicationSupportDirectory();
    final now = DateTime.now().millisecondsSinceEpoch;

    final added = await rust.addFromUri(
      uri:
          'otpauth://totp/InspectMe:findthisaccount'
          '?secret=$rfcSecret&issuer=InspectMe',
      nowMs: now,
    );

    final vaultFile = File('${directory.path}/vault.db');
    expect(
      await vaultFile.exists(),
      isTrue,
      reason: 'the vault file should exist',
    );

    final bytes = await vaultFile.readAsBytes();

    // Section 12.1 rule 1, on the device: test the bytes, not the open.
    // SQLite3 Multiple Ciphers opens an unencrypted database transparently, so
    // every other test in this file would still pass if the key were never
    // applied. The file header is the one thing a working connection cannot
    // fake — a plain SQLite database starts with these bytes and an encrypted
    // one does not.
    final header = String.fromCharCodes(bytes.take(15));
    expect(
      header,
      isNot('SQLite format 3'),
      reason: 'the vault on this device is not encrypted at the page level',
    );

    final text = String.fromCharCodes(bytes.where((b) => b >= 32 && b < 127));

    for (final readable in [
      rfcSecret, // the secret
      'InspectMe', // the issuer
      'findthisaccount', // the account name
      '"secret"', // even a payload field name
      'CREATE TABLE', // and the schema, which the page layer covers
    ]) {
      expect(
        text.contains(readable),
        isFalse,
        reason: '$readable is readable in ${vaultFile.path}',
      );
    }

    await rust.deleteEntry(id: added.addedId!, nowMs: now);
  });

  /// Section 9.2.4: the metadata file is deliberately unencrypted, so what it
  /// holds matters. It must carry the wrapped key and nothing that opens it.
  test('the unencrypted metadata file leaks nothing', () async {
    final directory = await getApplicationSupportDirectory();
    final metaFile = File('${directory.path}/meta.db');
    expect(await metaFile.exists(), isTrue);

    final bytes = await metaFile.readAsBytes();
    final text = String.fromCharCodes(bytes.where((b) => b >= 32 && b < 127));

    // It should name the slot it holds...
    expect(text, contains('device_slot.wrapped_key'));
    expect(text, contains('keystore-v1'));

    // ...and hold no secret of its own.
    expect(text.contains(rfcSecret), isFalse);

    // The wrapped key must not be the vault key sitting in the open. The
    // keystore's AES-GCM output is the key plus a 16-byte tag, so a 32-byte
    // value here would mean nothing wrapped it.
    final blob = await rust.beginDeviceOpen();
    expect(blob.wrapped.length, 48, reason: '32-byte key plus a GCM tag');
    await session.unlock();
  });

  /// The application lock, against a real keystore (FR-31, FR-35).
  ///
  /// These run last and put the device back the way they found it: the PIN is
  /// removed in the teardown, so a failure here does not leave every later run
  /// unable to open the vault.
  group('the PIN factor', () {
    const pin = '284915';

    tearDown(() async {
      // Back to a keystore-only slot whatever happened above.
      if (!rust.isVaultOpen()) {
        await session.unlock(pin: pin).catchError((_) {});
      }
      if (rust.isVaultOpen()) {
        await session.changePin(null, requireUserAuthentication: false);
      }
    });

    test(
      'a PIN is required once set, and the wrong one is refused',
      () async {
        await session.changePin(pin, requireUserAuthentication: false);

        // The slot now says so, and the keystore alone is not enough.
        final blob = await rust.beginDeviceOpen();
        expect(blob.scheme, 'keystore-pin-v1');
        expect(blob.needsPin, isTrue);

        session.lock();
        expect(rust.isVaultOpen(), isFalse);

        await expectLater(
          session.unlock(),
          throwsA(predicate((e) => e.toString().contains('PIN'))),
          reason: 'no PIN supplied',
        );
        expect(rust.isVaultOpen(), isFalse);

        final before = rust.failedUnlockAttempts();
        await expectLater(
          session.unlock(pin: '999888'),
          throwsA(anything),
          reason: 'the wrong PIN',
        );
        expect(
          rust.failedUnlockAttempts(),
          before + 1,
          reason: 'FR-35 counts the failure',
        );
        expect(rust.isVaultOpen(), isFalse);

        // The right one opens it and clears the count.
        await session.unlock(pin: pin);
        expect(rust.isVaultOpen(), isTrue);
        expect(rust.failedUnlockAttempts(), 0);
      },
      timeout: argon2idBudget,
    );

    test('adding a PIN keeps every existing entry readable', () async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final added = await rust.addFromUri(
        uri: 'otpauth://totp/BeforePin:account?secret=$rfcSecret',
        nowMs: now,
      );

      await session.changePin(pin, requireUserAuthentication: false);
      session.lock();
      await session.unlock(pin: pin);

      // The vault key did not change, so the record still decrypts.
      final entries = await rust.listEntries(nowUnixSeconds: 59);
      expect(
        entries.map((e) => e.id),
        contains(added.addedId),
        reason: 'setting a PIN must not re-encrypt or orphan records',
      );

      await rust.deleteEntry(id: added.addedId!, nowMs: now);
    }, timeout: argon2idBudget);

    test(
      'a PIN that fails FR-31 is refused before anything is stored',
      () async {
        for (final bad in ['12345', '123456', '000000']) {
          await expectLater(
            session.changePin(bad, requireUserAuthentication: false),
            throwsA(anything),
            reason: '$bad should be refused',
          );
        }

        // And the slot is untouched.
        final blob = await rust.beginDeviceOpen();
        expect(blob.needsPin, isFalse);
        await session.unlock();
      },
    );
  });

  /// NFR-13: the library on the device must be the one built from this source.
  ///
  /// The reason this exists: a gradle build once packaged the previous
  /// `librust_lib_authenticator.so` and reported success, so the tests above
  /// all passed against stale native code. The cargokit wrapper that swallowed
  /// that failure is fixed, but this check does not depend on knowing which
  /// path went wrong — it asks the library what it is.
  ///
  /// Run with the commit to compare against:
  ///
  /// ```sh
  /// flutter test integration_test -d <device>   ///   --dart-define=EXPECTED_COMMIT=$(git rev-parse HEAD)
  /// ```
  group('build provenance', () {
    const expectedCommit = String.fromEnvironment('EXPECTED_COMMIT');

    test('the native library reports where it came from', () {
      final info = rust.buildInfo();

      expect(info.commit, isNotEmpty);
      expect(
        info.builtAt,
        greaterThan(1750000000),
        reason: 'the build timestamp was never stamped',
      );
    });

    test('the library matches the source it should have been built from', () {
      final info = rust.buildInfo();

      if (expectedCommit.isEmpty) {
        // No commit to compare against. Fall back to the weaker check and say
        // so, rather than passing silently and implying more than was checked.
        final age = DateTime.now().difference(
          DateTime.fromMillisecondsSinceEpoch(info.builtAt * 1000),
        );
        expect(
          age.inDays,
          lessThan(7),
          reason:
              'EXPECTED_COMMIT was not passed, so only the age of the '
              'library could be checked, and it is $age old. Re-run with '
              '--dart-define=EXPECTED_COMMIT=\$(git rev-parse HEAD) for the '
              'real check.',
        );
        return;
      }

      if (info.dirty) {
        // A library built from an uncommitted tree cannot match any commit.
        // Checking its age is the most that can honestly be claimed.
        final age = DateTime.now().difference(
          DateTime.fromMillisecondsSinceEpoch(info.builtAt * 1000),
        );
        expect(
          age.inHours,
          lessThan(24),
          reason:
              'the library was built from a dirty tree $age ago, so it '
              'cannot be matched to a commit and is too old to trust',
        );
        return;
      }

      expect(
        info.commit,
        expectedCommit,
        reason:
            'the library on this device was built from ${info.commit}, '
            'but the source is at $expectedCommit. It is stale — the APK '
            'carries a library from an earlier build.',
      );
    });
  });

  /// The sync account slots on a real device (sections 9.2.1, 9.2.3).
  ///
  /// No server exists yet, so what is proved here is the derivation and the
  /// slot handling: that the account wraps the key the device already holds,
  /// and that both ways back return exactly that key.  ///
  /// # Why these carry an explicit timeout
  ///
  /// Argon2id at section 9.2.1's cost — 64 MiB, three iterations — takes about
  /// fourteen seconds on a mid-range phone, and these tests derive two or three
  /// keys each. That is over `package:test`'s thirty-second default, and it was
  /// under it only while the handset was cool: the same test passed all session
  /// and then timed out at twenty-eight seconds after a warm device throttled.
  ///
  /// Lowering the cost would make the tests fast and stop them testing the
  /// thing that matters, since the cost *is* the security property. So the
  /// budget is raised and named instead. A flaky timeout on a security test is
  /// worse than a slow one: it teaches whoever sees it to re-run rather than
  /// look.
  group('sync account slots', () {
    const email = 'rupsa@example.com';
    const password = 'correct horse battery staple';

    test(
      'an account wraps the existing vault key and recovery returns it',
      () async {
        final now = DateTime.now().millisecondsSinceEpoch;

        // An entry that exists before the account does. If sign-up replaced the
        // vault key, this is what would be lost.
        final added = await rust.addFromUri(
          uri: 'otpauth://totp/BeforeAccount:someone?secret=$rfcSecret',
          nowMs: now,
        );

        final recovery = await rust.createAccount(
          email: email,
          password: password,
        );

        expect(
          recovery.phrase.split(' ').length,
          24,
          reason: 'BIP-39, 24 words',
        );
        expect(
          recovery.confirmIndices.length,
          3,
          reason: 'section 9.2.3 step 4',
        );
        expect(recovery.confirmIndices.every((i) => i < 24), isTrue);
        expect(rust.accountEmail(), email);

        // The entry added before sign-up is still readable, which is only true
        // if the vault key did not change.
        final entries = await rust.listEntries(nowUnixSeconds: 59);
        expect(
          entries.map((e) => e.id),
          contains(added.addedId),
          reason: 'creating an account must not re-key the vault',
        );

        // Lock, then come back in through the recovery phrase rather than the
        // keystore. This is the path a new device would take.
        session.lock();
        expect(rust.isVaultOpen(), isFalse);

        await rust.unlockWithRecovery(
          vaultPath: session.vaultPath,
          phrase: recovery.phrase,
        );
        expect(rust.isVaultOpen(), isTrue);

        final afterRecovery = await rust.listEntries(nowUnixSeconds: 59);
        expect(
          afterRecovery.map((e) => e.id),
          contains(added.addedId),
          reason: 'recovery returned a different key',
        );

        await rust.deleteEntry(id: added.addedId!, nowMs: now);
      },
      timeout: argon2idBudget,
    );

    test(
      'the password slot opens the vault and the wrong one does not',
      () async {
        session.lock();

        await expectLater(
          rust.unlockWithPassword(
            vaultPath: session.vaultPath,
            password: 'not the password',
          ),
          throwsA(anything),
        );
        expect(rust.isVaultOpen(), isFalse);

        await rust.unlockWithPassword(
          vaultPath: session.vaultPath,
          password: password,
        );
        expect(rust.isVaultOpen(), isTrue);
      },
      timeout: argon2idBudget,
    );

    // Authentication-key derivation stays inside Rust. Core tests verify its
    // deterministic result without exposing the key through the Dart bridge.
  });
}
