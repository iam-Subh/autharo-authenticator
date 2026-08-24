import 'package:authenticator/src/pages/backup_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'localized_test_app.dart';

/// FR-27's double confirmation, held in place.
///
/// # What is on the other side of this gate
///
/// A file containing every TOTP secret in the vault, in clear text, sitting in
/// a downloads folder that half the apps on the phone can read and that most
/// cloud services back up automatically. It is the single most dangerous action
/// in this application, and it exists only because refusing to let users leave
/// is worse — that is the whole argument in [BackupPage]'s documentation.
///
/// The requirement is therefore not "warn the user". It is that the export
/// cannot be reached by tapping. Two identical "are you sure" dialogs would
/// satisfy a reading of FR-27 and fail the intent completely: the reflex that
/// dismisses the first dismisses the second, and a warning nobody reads is
/// decoration.
///
/// So the second step asks for something that cannot be done without reading
/// the screen, and these tests hold that: the confirm button is *disabled*
/// until the word is typed, and every exit that is not both confirmations
/// returns false.
void main() {
  /// Pumps a page whose only button opens the real gate, and records what it
  /// returned. The gate under test is the one [BackupPage] calls — not a copy
  /// of its logic, which would pass while the shipped path lost a dialog.
  Future<List<bool>> harness(WidgetTester tester) async {
    final results = <bool>[];
    await tester.pumpWidget(
      localizedTestApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () async =>
                  results.add(await confirmPlainExport(context)),
              child: const Text('go'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('go'));
    await tester.pumpAndSettle();
    return results;
  }

  testWidgets('the first dialog names what the file actually is', (
    tester,
  ) async {
    await harness(tester);

    // Not "this is less secure". The user has to know that the file signs them
    // in everywhere, and that anything syncing that folder carries it off the
    // device.
    expect(find.textContaining('plain text'), findsOneWidget);
    expect(find.textContaining('sign in as you'), findsOneWidget);
  });

  testWidgets('the safe choice is the prominent one', (tester) async {
    await harness(tester);

    // The filled button is the encrypted backup, and "Continue anyway" is the
    // plain text button. A dialog whose default action is the dangerous one is
    // a dialog that leaks vaults.
    final safe = tester.widget<FilledButton>(
      find.widgetWithText(FilledButton, 'Use the encrypted backup'),
    );
    expect(safe.onPressed, isNotNull);
    expect(find.widgetWithText(TextButton, 'Continue anyway'), findsOneWidget);
  });

  testWidgets('backing out of the first dialog exports nothing', (
    tester,
  ) async {
    final results = await harness(tester);

    await tester.tap(find.text('Use the encrypted backup'));
    await tester.pumpAndSettle();

    expect(results, [false]);
  });

  testWidgets('the second step cannot be tapped through', (tester) async {
    final results = await harness(tester);

    await tester.tap(find.text('Continue anyway'));
    await tester.pumpAndSettle();

    // The whole point. The confirm button exists, is visible, and does
    // nothing — so a user tapping where the previous dialog's button was does
    // not export their vault.
    final button = tester.widget<FilledButton>(
      find.widgetWithText(FilledButton, 'Export in plain text'),
    );
    expect(
      button.onPressed,
      isNull,
      reason: 'the plain export can be reached by tapping twice',
    );

    await tester.tap(find.text('Export in plain text'));
    await tester.pumpAndSettle();
    expect(results, isEmpty, reason: 'a disabled button still exported');
  });

  testWidgets('a near miss does not open the gate', (tester) async {
    final results = await harness(tester);
    await tester.tap(find.text('Continue anyway'));
    await tester.pumpAndSettle();

    // Typing something plausible must not count. Anything that accepted a
    // prefix would make the field a formality.
    for (final attempt in ['EXPOR', 'EXPORTS', 'export it', '']) {
      await tester.enterText(find.byType(TextField), attempt);
      await tester.pump();
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Export in plain text'),
            )
            .onPressed,
        isNull,
        reason: '"$attempt" was accepted',
      );
    }
    expect(results, isEmpty);
  });

  testWidgets('typing the word, and only then, exports', (tester) async {
    final results = await harness(tester);
    await tester.tap(find.text('Continue anyway'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'EXPORT');
    await tester.pump();
    await tester.tap(find.text('Export in plain text'));
    await tester.pumpAndSettle();

    expect(results, [true]);
  });

  testWidgets('the word is accepted however the keyboard cased it', (
    tester,
  ) async {
    // A phone keyboard fights case, and autocorrect adds spaces. Refusing a
    // user who typed the right word would push them to give up on a legitimate
    // action — the gate is meant to require reading, not typing accuracy.
    final results = await harness(tester);
    await tester.tap(find.text('Continue anyway'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), ' export ');
    await tester.pump();
    await tester.tap(find.text('Export in plain text'));
    await tester.pumpAndSettle();

    expect(results, [true]);
  });

  testWidgets('cancelling the second dialog exports nothing', (tester) async {
    final results = await harness(tester);
    await tester.tap(find.text('Continue anyway'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'EXPORT');
    await tester.pump();
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();

    expect(results, [false]);
  });
}
