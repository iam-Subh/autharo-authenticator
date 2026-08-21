import 'package:authenticator/main.dart';
import 'package:authenticator/src/pages/entry_list_page.dart';
import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:authenticator/src/services/reference_time.dart';
import 'package:authenticator/src/vault_controller.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';

/// Drives the real screens against the real core on a device.
///
/// `vault_test.dart` proves the bridge returns correct codes. This file proves
/// they reach the screen — which is the half of the stage S2 exit criterion
/// that a bridge test cannot cover.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late VaultController controller;
  final added = <String>[];

  setUpAll(() async {
    await RustLib.init();
    final directory = await getApplicationSupportDirectory();
    rust.openVault(dbPath: '${directory.path}/ui-test.db');
    controller = VaultController(await ReferenceTime.load());
  });

  tearDown(() async {
    for (final id in added) {
      await rust.deleteEntry(id: id, nowMs: DateTime.now().millisecondsSinceEpoch);
    }
    added.clear();
  });

  Future<void> seed(String issuer, String account, String secret) async {
    final outcome = await rust.addFromUri(
      uri: 'otpauth://totp/$issuer:$account?secret=$secret&issuer=$issuer',
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
    if (outcome.addedId != null) added.add(outcome.addedId!);
  }

  Future<void> pumpList(WidgetTester tester) async {
    await controller.refresh();
    await tester.pumpWidget(
      MaterialApp(home: EntryListPage(controller: controller)),
    );
    await tester.pump();
  }

  testWidgets('an empty vault explains what to do next', (tester) async {
    await pumpList(tester);

    expect(find.text('No accounts yet.'), findsOneWidget);
    expect(find.textContaining('scanning the QR code'), findsOneWidget);
    expect(find.text('Add'), findsOneWidget);
  });

  testWidgets('a stored entry renders its code and countdown', (tester) async {
    await seed('GitHub', 'rupsa', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    await pumpList(tester);

    expect(find.text('GitHub'), findsOneWidget);
    expect(find.text('rupsa'), findsOneWidget);

    // The code is grouped for display, so match the rendered shape rather than
    // the raw digits.
    final codeText = tester
        .widgetList<Text>(find.byType(Text))
        .map((t) => t.data)
        .whereType<String>()
        .firstWhere(
          (text) => RegExp(r'^\d{3} \d{3}$').hasMatch(text),
          orElse: () => '',
        );
    expect(codeText, isNotEmpty, reason: 'a 6-digit code should be on screen');
  });

  testWidgets('search filters by issuer and by account (FR-21)', (tester) async {
    await seed('GitHub', 'rupsa', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    await seed('GitLab', 'someone', 'MZXW6YTBOIZQ');
    await pumpList(tester);

    expect(find.text('GitHub'), findsOneWidget);
    expect(find.text('GitLab'), findsOneWidget);

    // Matching on any part of the string, not just a prefix.
    await tester.enterText(find.byType(SearchBar), 'lab');
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsNothing);
    expect(find.text('GitLab'), findsOneWidget);

    await tester.enterText(find.byType(SearchBar), 'rupsa');
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsOneWidget);
    expect(find.text('GitLab'), findsNothing);

    await tester.enterText(find.byType(SearchBar), 'nothing matches this');
    await tester.pumpAndSettle();
    expect(find.text('No entry matches that search.'), findsOneWidget);
  });

  testWidgets('deleting asks first and warns about other devices (FR-18)',
      (tester) async {
    await seed('GitHub', 'rupsa', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    await pumpList(tester);

    await tester.tap(find.byType(PopupMenuButton<String>).first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Delete'));
    await tester.pumpAndSettle();

    expect(find.textContaining('Delete GitHub'), findsOneWidget);
    expect(find.textContaining('every device'), findsOneWidget);

    // Declining must leave the entry alone.
    await tester.tap(find.text('Keep'));
    await tester.pumpAndSettle();
    expect(find.text('GitHub'), findsOneWidget);
  });

  testWidgets('favourites pin to the top of the list (FR-20)', (tester) async {
    await seed('AAA First', 'a', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    await seed('ZZZ Last', 'z', 'MZXW6YTBOIZQ');
    await pumpList(tester);

    await controller.setFavourite(added.last, true);
    await pumpList(tester);

    expect(controller.entries.first.issuer, 'ZZZ Last');
    expect(controller.entries.first.favourite, isTrue);
  });

  /// The other tests pump their own widget tree, which skips everything
  /// `main.dart` does: locating the application support directory, opening the
  /// vault at that path, loading the time offset, and starting the ticker. A
  /// failure in any of those shows up only as an application that never leaves
  /// the splash screen, so it is worth a test of its own.
  testWidgets('the real application starts and reaches the code list',
      (tester) async {
    await tester.pumpWidget(const AuthenticatorApp());

    // Not `pumpAndSettle`: the controller runs a one second `Timer.periodic`
    // for the FR-07 countdown, so the tree never settles and that call would
    // time out rather than fail honestly.
    for (var i = 0; i < 15; i++) {
      await tester.pump(const Duration(milliseconds: 200));
    }

    expect(
      find.byType(EntryListPage),
      findsOneWidget,
      reason: 'the bootstrap should hand off to the code list',
    );
    expect(find.text('Authenticator'), findsOneWidget);
    expect(
      find.textContaining('could not be opened'),
      findsNothing,
      reason: 'the vault should open at the real application support path',
    );
  });
}
