import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
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

  setUpAll(() async {
    await RustLib.init();
    final directory = await getApplicationSupportDirectory();
    rust.openVault(dbPath: '${directory.path}/integration-test.db');
  });

  /// RFC 6238 Appendix B: the SHA-1 seed at T=59 gives 94287082 at 8 digits.
  const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  test('the vault opens on the device', () {
    expect(rust.isVaultOpen(), isTrue);
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

  test('entries survive closing and reopening the vault', () async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final added = await rust.addFromUri(
      uri: 'otpauth://totp/Persisted:test?secret=$rfcSecret',
      nowMs: now,
    );
    final id = added.addedId!;

    rust.closeVault();
    expect(rust.isVaultOpen(), isFalse);

    final directory = await getApplicationSupportDirectory();
    rust.openVault(dbPath: '${directory.path}/integration-test.db');

    final entries = await rust.listEntries(
      nowUnixSeconds: DateTime.now().millisecondsSinceEpoch ~/ 1000,
    );
    expect(entries.map((e) => e.id), contains(id));

    await rust.deleteEntry(id: id, nowMs: now);
  });
}
