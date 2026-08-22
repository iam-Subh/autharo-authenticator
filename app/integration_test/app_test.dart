import 'package:authenticator/main.dart';
import 'package:authenticator/src/pages/create_account_page.dart';
import 'package:authenticator/src/pages/entry_list_page.dart';
import 'package:authenticator/src/pages/recovery_key_page.dart';
import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/rust/frb_generated.dart';
import 'package:authenticator/src/services/reference_time.dart';
import 'package:authenticator/src/vault_controller.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:authenticator/src/services/vault_session.dart';

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

    final session = VaultSession();
    switch (await session.load()) {
      case VaultState.needsSetup:
        await session.setUp(requireUserAuthentication: false);
      case VaultState.locked:
        await session.unlock();
      case VaultState.lockedNeedsPin:
        fail('the test device should not have a PIN-protected slot');
    }
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

  /// The sign-up screens on a real device (FR-29, FR-55, section 9.2.3).
  ///
  /// These are host-tested against a fabricated phrase. Here they run against
  /// the real core: the phrase comes from BIP-39 over a real random recovery
  /// key, and the positions to confirm come from the core's own random choice.
  /// A screen that works on a fabricated 24 words and fails on real ones would
  /// pass every host test.
  group('sign-up screens', () {
    testWidgets('the create-account screen refuses an address it cannot use',
        (tester) async {
      await tester.pumpWidget(
        MaterialApp(home: CreateAccountPage(session: VaultSession())),
      );

      // The button sits below the fold on a phone, so it has to be scrolled
      // to — the same as a user would. The validation message then renders on
      // the email field, which scrolling moved off screen, and a ListView does
      // not build off-screen children; so the assertion needs the field back
      // in view before it can see anything.
      Future<void> submitAndReturnToTheField() async {
        final button = find.widgetWithText(FilledButton, 'Create account');
        await tester.scrollUntilVisible(
          button,
          200,
          scrollable: find.byType(Scrollable).first,
        );
        await tester.pumpAndSettle();
        await tester.tap(button);
        await tester.pumpAndSettle();

        await tester.scrollUntilVisible(
          find.widgetWithText(TextFormField, 'Email address'),
          -200,
          scrollable: find.byType(Scrollable).first,
        );
        await tester.pumpAndSettle();
      }

      // Section 16.4 and decision 6: an email address is required.
      await submitAndReturnToTheField();
      expect(find.text('An email address is required.'), findsOneWidget);

      await tester.enterText(
        find.widgetWithText(TextFormField, 'Email address'),
        'not-an-address',
      );
      await submitAndReturnToTheField();
      expect(find.textContaining('does not look like'), findsOneWidget);
    });

    testWidgets('the real phrase renders and its real positions confirm',
        (tester) async {
      // A real account, so the words are BIP-39 over real entropy.
      final email = 'screens-${DateTime.now().microsecondsSinceEpoch}@example.com';
      final recovery = await rust.createAccount(
        email: email,
        password: 'correct horse battery staple',
      );

      final words = recovery.phrase.split(' ');
      final indices = recovery.confirmIndices.map((i) => i.toInt()).toList();
      expect(words.length, 24);
      expect(indices.length, 3);

      var confirmed = false;
      await tester.pumpWidget(
        MaterialApp(
          home: RecoveryKeyPage(
            phrase: recovery.phrase,
            confirmIndices: indices,
            onConfirmed: () => confirmed = true,
          ),
        ),
      );

      // Every real word is on screen.
      for (final word in words) {
        expect(find.text(word), findsWidgets, reason: '$word is missing');
      }

      final scroller = find.byType(Scrollable).first;
      await tester.scrollUntilVisible(
        find.byType(CheckboxListTile),
        200,
        scrollable: scroller,
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byType(CheckboxListTile));
      await tester.pumpAndSettle();

      final continueButton = find.widgetWithText(FilledButton, 'Continue');
      await tester.scrollUntilVisible(continueButton, 200, scrollable: scroller);
      await tester.pumpAndSettle();
      await tester.tap(continueButton);
      await tester.pumpAndSettle();

      // The positions the core picked, typed back.
      for (final index in indices) {
        await tester.enterText(
          find.widgetWithText(TextField, 'Word ${index + 1}'),
          words[index],
        );
      }
      final confirmButton = find.widgetWithText(FilledButton, 'Confirm');
      await tester.scrollUntilVisible(
        confirmButton,
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.pumpAndSettle();
      await tester.tap(confirmButton);
      await tester.pumpAndSettle();

      expect(confirmed, isTrue, reason: 'the real phrase did not confirm');
    });
  });
}
