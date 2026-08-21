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
        fail('the test device should not have a PIN-protected slot');
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
      uri: 'otpauth://totp/RFC6238:appendix-b'
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
    expect(entry.remainingSeconds, 1, reason: 'T=59 is one second from the step boundary');

    await rust.deleteEntry(id: id!, nowMs: DateTime.now().millisecondsSinceEpoch);
  });

  test('a duplicate secret is reported rather than stored twice (FR-16)', () async {
    const uri = 'otpauth://totp/Duplicate:test?secret=$rfcSecret';
    final now = DateTime.now().millisecondsSinceEpoch;

    final first = await rust.addFromUri(uri: uri, nowMs: now);
    expect(first.addedId, isNotNull);

    final second = await rust.addFromUri(uri: uri, nowMs: now);
    expect(second.addedId, isNull);
    expect(second.duplicateOf, first.addedId);

    await rust.deleteEntry(id: first.addedId!, nowMs: now);
  });

  test('an HOTP counter advances and never repeats a code', () async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final added = await rust.addFromUri(
      uri: 'otpauth://hotp/RFC4226:appendix-d'
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
      uri: 'otpauth://totp/InspectMe:findthisaccount'
          '?secret=$rfcSecret&issuer=InspectMe',
      nowMs: now,
    );

    final vaultFile = File('${directory.path}/vault.db');
    expect(await vaultFile.exists(), isTrue, reason: 'the vault file should exist');

    final bytes = await vaultFile.readAsBytes();
    final text = String.fromCharCodes(bytes.where((b) => b >= 32 && b < 127));

    for (final readable in [
      rfcSecret,          // the secret
      'InspectMe',        // the issuer
      'findthisaccount',  // the account name
      '"secret"',         // even a payload field name
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
}
