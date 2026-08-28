// FR-14 on the device: an imported entry produces a working code.
//
// # Why this runs on a phone
//
// The parser is tested thoroughly in `authcore`, against the published example
// and an independently computed code. What that cannot cover is the path this
// test takes: the bridge carrying a protocol buffer across the FFI boundary,
// the batch state living in a static across several calls, the entry reaching
// the encrypted vault, and the code coming back out of it.
//
// Every one of those was green while the sync API was unreachable from Dart.
//
// # No camera involved
//
// The scan screen's job is to turn a photograph into a string. Automating that
// would be testing `mobile_scanner`. What is worth testing is what happens to
// the string, so the string is supplied directly.

import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:authenticator/src/services/vault_session.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// The published example from Google Authenticator's export format: one TOTP
/// entry, `Example (alice@google.com)`, secret `JBSWY3DPEHPK3PXP`.
const example =
    'otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VA'
    'Z29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhACGAEgAA%3D%3D';

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

  setUp(() async => rust.migrationReset());

  tearDown(() async {
    for (final id in added) {
      await rust.deleteEntry(
        id: id,
        nowMs: DateTime.now().millisecondsSinceEpoch,
      );
    }
    added.clear();
    await rust.migrationReset();
  });

  test('an exported account imports and produces a code', () async {
    final scan = await rust.migrationScan(uri: example);
    expect(scan.remaining, 0, reason: 'the example is a single-part export');
    expect(scan.ready, 1);
    expect(scan.refused, 0);

    final report = await rust.migrationFinish(
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
    expect(report.refused, isEmpty, reason: 'the example is well formed');
    expect(report.imported + report.duplicates, 1);

    // The assertion that matters. An entry can import cleanly and still be
    // wrong — a secret re-encoded with the wrong padding, a digit count read as
    // an ordinal — and every one of those produces a number the service
    // rejects with no error at all.
    final entries = await rust.listEntries(nowUnixSeconds: 59);
    final imported = entries.where((e) => e.issuer == 'Example').toList();
    expect(imported, hasLength(1), reason: 'the entry must reach the vault');
    added.add(imported.first.id);

    expect(
      imported.first.code,
      '996554',
      reason:
          'the code at t=59 for JBSWY3DPEHPK3PXP, computed independently. A '
          'different value means the secret did not survive the import.',
    );
    expect(imported.first.account, 'alice@google.com');
    expect(
      imported.first.account,
      isNot(contains(':')),
      reason: 'the "Issuer:account" form must be split on import',
    );
  });

  test('scanning the same export twice does not import it twice', () async {
    // FR-16 applies to imports too. Two rows producing identical codes is the
    // kind of mess that looks like data loss when the wrong one is deleted.
    await rust.migrationScan(uri: example);
    var report = await rust.migrationFinish(
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
    expect(report.imported, 1);

    final entries = await rust.listEntries(nowUnixSeconds: 59);
    for (final entry in entries.where((e) => e.issuer == 'Example')) {
      added.add(entry.id);
    }

    await rust.migrationScan(uri: example);
    report = await rust.migrationFinish(
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );

    expect(report.imported, 0);
    expect(
      report.duplicates,
      1,
      reason: 'the second import must recognise what it already holds',
    );
  });

  test('an abandoned scan does not leak into the next one', () async {
    // Backing out halfway and starting again must not leave the app waiting
    // for parts of an export the user is no longer holding.
    await rust.migrationScan(uri: example);
    await rust.migrationReset();

    await expectLater(
      rust.migrationFinish(nowMs: DateTime.now().millisecondsSinceEpoch),
      throwsA(anything),
      reason: 'there is no scan in progress to finish',
    );
  });

  test('something that is not an export is refused with an explanation',
      () async {
    // A user who scans the wrong code should be told what to scan.
    await expectLater(
      rust.migrationScan(uri: 'otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP'),
      throwsA(anything),
    );
  });
}
