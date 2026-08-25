// FR-26 to FR-28 on the device: a backup that actually restores.
//
// # Why this runs on a phone
//
// `authcore::backup` is tested hard, and every one of those tests would still
// pass if the bridge dropped the passphrase, if `exportBackup` read from an
// empty vault, or if `importBackup` wrote entries that never reached the
// encrypted database. All three are in the path this test takes and none are in
// the path the unit tests take.
//
// # The failure being guarded against
//
// A backup is the one feature whose defects are invisible until the moment
// nothing else can help. A user exports, believes they are covered, loses the
// phone, and finds out then. There is no retry and no support path — section
// 16.4 says plainly that the server cannot decrypt anything.
//
// So the assertions here are about the restored *codes*, not about counts. An
// entry can round-trip with the right name and the wrong secret, and a report
// saying "1 imported" is exactly what that looks like.

import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:authenticator/src/services/vault_session.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// `JBSWY3DPEHPK3PXP` at t=59 is 996554 — the RFC 6238 example secret, with a
/// value computed outside this project.
const secret = 'JBSWY3DPEHPK3PXP';
const codeAt59 = '996554';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final added = <String>[];
  int now() => DateTime.now().millisecondsSinceEpoch;

  // Kept, not rebuilt per use. `VaultSession.unlock` reads a path that only
  // `load` sets, so a fresh instance throws before it reaches the keystore —
  // which looks like an unlock failure and is not one.
  final session = VaultSession();

  setUpAll(() async {
    await RustLib.init();

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

  tearDown(() async {
    for (final id in added) {
      await rust.deleteEntry(id: id, nowMs: now());
    }
    added.clear();
  });

  /// Puts one known account in the vault and returns its identifier.
  Future<String> seed({String issuer = 'BackupTest'}) async {
    final outcome = await rust.addFromUri(
      uri: 'otpauth://totp/$issuer:alice@example.com?secret=$secret'
          '&issuer=$issuer',
      nowMs: now(),
    );
    final entries = await rust.listEntries(nowUnixSeconds: 59);
    final id = entries.firstWhere((entry) => entry.issuer == issuer).id;
    added.add(id);
    expect(outcome, isNotNull);
    return id;
  }

  test('an encrypted backup restores a working code', () async {
    final original = await seed();
    final file = await rust.exportBackup(passphrase: 'a long enough one');

    // Removed, so the restore has to actually produce the entry rather than
    // finding it already there and reporting a duplicate — which is what a
    // completely broken import would also do.
    await rust.deleteEntry(id: original, nowMs: now());
    added.remove(original);

    final report = await rust.importBackup(
      text: file,
      passphrase: 'a long enough one',
      nowMs: now(),
    );
    expect(report.refused, isEmpty);
    expect(report.imported, 1);

    final restored = (await rust.listEntries(
      nowUnixSeconds: 59,
    )).where((entry) => entry.issuer == 'BackupTest').toList();
    expect(restored, hasLength(1));
    added.add(restored.first.id);

    // The assertion the whole file exists for. The name surviving proves
    // nothing; the code surviving proves the secret did.
    expect(
      restored.first.code,
      codeAt59,
      reason:
          'the restored entry produces a different code, so the secret did '
          'not survive the round trip',
    );
  });

  test('the encrypted file carries no readable secret', () async {
    await seed(issuer: 'SecretCheck');
    final file = await rust.exportBackup(passphrase: 'a long enough one');

    // Asserting absence on the bytes that leave the device, in the same shape
    // as the check that the server database holds no plaintext. A backup that
    // encrypts everything except the issuer is still a list of every service
    // the user has an account with.
    expect(file, isNot(contains(secret)));
    expect(file, isNot(contains('SecretCheck')));
    expect(file, isNot(contains('alice@example.com')));
  });

  test('a wrong passphrase restores nothing', () async {
    await seed(issuer: 'WrongPass');
    final file = await rust.exportBackup(passphrase: 'the right one entirely');

    await expectLater(
      rust.importBackup(text: file, passphrase: 'not it', nowMs: now()),
      throwsA(anything),
    );
  });

  test('an unprotected export restores too', () async {
    // FR-27's file is the escape hatch, and an escape hatch that cannot be
    // read back is not one. Tested through the same importer, because a user
    // who exported in plain text to move away may well change their mind.
    final original = await seed(issuer: 'PlainTest');
    final file = await rust.exportBackup();

    expect(
      rust.backupNeedsPassphrase(text: file),
      isFalse,
      reason: 'a plain backup must not demand a passphrase',
    );
    expect(
      file,
      contains(secret),
      reason: 'a plain export that hid the secret would not be a plain export',
    );

    await rust.deleteEntry(id: original, nowMs: now());
    added.remove(original);

    final report = await rust.importBackup(text: file, nowMs: now());
    expect(report.imported, 1);

    final restored = (await rust.listEntries(
      nowUnixSeconds: 59,
    )).where((entry) => entry.issuer == 'PlainTest').toList();
    added.add(restored.single.id);
    expect(restored.single.code, codeAt59);
  });

  test('restoring onto a device that already has the accounts is safe',
      () async {
    // The common case, and the one where a careless importer does damage: a
    // user restores a backup onto a working phone. FR-16 must leave them with
    // one of each, not two rows producing identical codes.
    await seed(issuer: 'DupTest');
    final file = await rust.exportBackup(passphrase: 'a long enough one');

    final report = await rust.importBackup(
      text: file,
      passphrase: 'a long enough one',
      nowMs: now(),
    );
    expect(report.imported, 0);
    expect(report.duplicates, greaterThanOrEqualTo(1));

    final rows = (await rust.listEntries(
      nowUnixSeconds: 59,
    )).where((entry) => entry.issuer == 'DupTest');
    expect(rows, hasLength(1), reason: 'the restore duplicated an account');
  });

  test('a file from another app is refused rather than half-read', () async {
    // An Aegis or 2FAS export goes through the import screens, not this one.
    // Reading one here must fail cleanly: a partial read would put entries in
    // the vault while reporting an error, which is the worst of both.
    for (final text in [
      '{"db":{"entries":[]}}',
      '{"services":[],"schemaVersion":4}',
      'not json at all',
      '',
    ]) {
      await expectLater(
        rust.importBackup(text: text, nowMs: now()),
        throwsA(anything),
        reason: 'accepted: $text',
      );
    }
  });

  test('a locked vault exports nothing (FR-36)', () async {
    // The requirement is an unlock before any export, and the whole reason
    // FR-31 zeroes the key on lock is that a locked device must not be able to
    // read its own entries. An export path that worked while locked would make
    // that guarantee decorative — and it would be a quiet regression, because
    // every other test in this file runs unlocked and would stay green.
    //
    // Asserted on both kinds, since they are separate calls into the bridge and
    // a guard can be lost from one without the other noticing.
    await seed(issuer: 'LockedTest');
    rust.lockVault();
    expect(rust.isVaultOpen(), isFalse);

    await expectLater(
      rust.exportBackup(passphrase: 'a long enough one'),
      throwsA(anything),
      reason: 'an encrypted backup was produced from a locked vault',
    );
    await expectLater(
      rust.exportBackup(),
      throwsA(anything),
      reason: 'a plain export was produced from a locked vault',
    );
    // The import direction goes through the same gate.
    await expectLater(
      rust.importBackup(text: '{}', nowMs: now()),
      throwsA(anything),
    );

    // Put the device back, or every test after this one fails for the wrong
    // reason and the tear-down cannot delete what it seeded.
    await session.load();
    await session.unlock();
    expect(rust.isVaultOpen(), isTrue);
  });

  test('backing up an empty vault is refused, not silently written', () async {
    // Only meaningful when the device really is empty, which it is not when
    // this file runs alongside the others. Skipped rather than deleted, so the
    // rule is visible here — a backup with no accounts in it looks exactly like
    // a working one until the day it is needed.
    final entries = await rust.listEntries(nowUnixSeconds: 59);
    if (entries.isNotEmpty) {
      markTestSkipped('the vault is not empty on this device');
      return;
    }
    await expectLater(
      rust.exportBackup(passphrase: 'a long enough one'),
      throwsA(anything),
    );
  });

  test('a trashed account is not carried into a backup', () async {
    // Trash is recoverable inside the app; it is not something to carry off the
    // device. Somebody who deletes an account and then makes a backup does not
    // expect the secret they just removed to be in the file - and in FR-27's
    // plain export it would be sitting there in clear text.
    //
    // The code list already hid these. The backup did not, which is the gap
    // that opens whenever a new state is added to a payload and only the
    // obvious reader is updated.
    final keep = await seed(issuer: 'KeepMe');
    final bin = await seed(issuer: 'BinMe');

    await rust.moveEntryToTrash(id: bin, nowMs: now());
    added.remove(bin);

    final encrypted = await rust.exportBackup(passphrase: 'a long enough one');
    final report = await rust.importBackup(
      text: encrypted,
      passphrase: 'a long enough one',
      nowMs: now(),
    );
    // The kept one is already present, so it is a duplicate rather than an
    // import. What matters is that the trashed one is not in the file at all.
    expect(report.imported, 0, reason: 'the trashed entry was backed up');

    final plain = await rust.exportBackup();
    expect(
      plain,
      isNot(contains('BinMe')),
      reason: 'a deleted account reached the plain-text export',
    );
    expect(plain, contains('KeepMe'), reason: 'a live account must be exported');

    // And the single-secret paths refuse it too.
    await expectLater(rust.exportEntryUri(id: bin), throwsA(anything));
    await expectLater(rust.revealSecretForExport(id: bin), throwsA(anything));

    // Restoring it puts it back in reach.
    await rust.restoreEntry(id: bin, nowMs: now());
    added.add(bin);
    expect(await rust.exportEntryUri(id: bin), contains('BinMe'));

    final _ = keep;
  });
}
