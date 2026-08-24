import 'package:authenticator/src/pages/recovery_key_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

import 'localized_test_app.dart';

/// A phrase with distinct, recognisable words, so a test failure names the
/// position that went wrong rather than one of 24 identical strings.
const _phrase =
    'alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima '
    'mike november oscar papa quebec romeo sierra tango uniform victor '
    'whiskey xray';

/// The page's own scroll view.
///
/// Named explicitly because the word grid is a second `Scrollable` nested
/// inside the outer list, and `scrollUntilVisible` cannot choose between them.
Finder get _pageScroller => find.byType(Scrollable).first;

/// Scrolls a finder into view before interacting with it.
///
/// The page is a `ListView` and the default 800x600 test surface shows only
/// part of it, so the acknowledgement and the button start off screen — the
/// same as on a phone. Scrolling is what a user does, so the test does it too
/// rather than growing the window to hide the problem.
Future<void> scrollTo(WidgetTester tester, Finder target) async {
  await tester.scrollUntilVisible(target, 200, scrollable: _pageScroller);
  await tester.pumpAndSettle();
}

Future<void> tapAfterScrolling(WidgetTester tester, Finder target) async {
  await scrollTo(tester, target);
  await tester.tap(target);
  await tester.pumpAndSettle();
}

void main() {
  late int confirmed;

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
  });

  Widget page({List<int> indices = const [2, 7, 19]}) {
    confirmed = 0;
    return localizedTestApp(
      home: RecoveryKeyPage(
        phrase: _phrase,
        confirmIndices: indices,
        onConfirmed: () => confirmed++,
      ),
    );
  }

  group('showing the key (FR-29, FR-55)', () {
    testWidgets('shows all 24 words, numbered', (tester) async {
      await tester.pumpWidget(page());

      final words = _phrase.split(' ');
      expect(words.length, 24);
      for (final word in words) {
        expect(find.text(word), findsOneWidget, reason: '$word is missing');
      }
      // Numbered, because the confirmation asks for positions.
      expect(find.text('1'), findsOneWidget);
      expect(find.text('24'), findsOneWidget);
    });

    testWidgets('says plainly that it cannot be shown again', (tester) async {
      await tester.pumpWidget(page());

      expect(find.textContaining('shown once'), findsOneWidget);
      expect(find.textContaining('cannot show them again'), findsOneWidget);
    });

    /// The acknowledgement is the difference between reading the warning and
    /// scrolling past it.
    testWidgets('cannot continue until the box is ticked', (tester) async {
      await tester.pumpWidget(page());

      final button = find.widgetWithText(FilledButton, 'Continue');
      await scrollTo(tester, button);
      expect(tester.widget<FilledButton>(button).onPressed, isNull);

      await tapAfterScrolling(tester, find.byType(CheckboxListTile));

      expect(tester.widget<FilledButton>(button).onPressed, isNotNull);
    });
  });

  group('confirming three words (section 9.2.3 step 4)', () {
    Future<void> reachConfirmation(WidgetTester tester) async {
      await tapAfterScrolling(tester, find.byType(CheckboxListTile));
      await tapAfterScrolling(
        tester,
        find.widgetWithText(FilledButton, 'Continue'),
      );
    }

    testWidgets('asks for the positions the core chose, one-based', (
      tester,
    ) async {
      await tester.pumpWidget(page(indices: [2, 7, 19]));
      await reachConfirmation(tester);

      // Position 2 zero-based is word 3 to a human.
      expect(find.widgetWithText(TextField, 'Word 3'), findsOneWidget);
      expect(find.widgetWithText(TextField, 'Word 8'), findsOneWidget);
      expect(find.widgetWithText(TextField, 'Word 20'), findsOneWidget);
    });

    testWidgets('the right words complete sign-up', (tester) async {
      await tester.pumpWidget(page(indices: [2, 7, 19]));
      await reachConfirmation(tester);

      await tester.enterText(
        find.widgetWithText(TextField, 'Word 3'),
        'charlie',
      );
      await tester.enterText(find.widgetWithText(TextField, 'Word 8'), 'hotel');
      await tester.enterText(
        find.widgetWithText(TextField, 'Word 20'),
        'tango',
      );
      await tapAfterScrolling(
        tester,
        find.widgetWithText(FilledButton, 'Confirm'),
      );

      expect(confirmed, 1);
    });

    testWidgets('a wrong word names the position and does not continue', (
      tester,
    ) async {
      await tester.pumpWidget(page(indices: [2, 7, 19]));
      await reachConfirmation(tester);

      await tester.enterText(
        find.widgetWithText(TextField, 'Word 3'),
        'charlie',
      );
      await tester.enterText(find.widgetWithText(TextField, 'Word 8'), 'wrong');
      await tester.enterText(
        find.widgetWithText(TextField, 'Word 20'),
        'tango',
      );
      await tapAfterScrolling(
        tester,
        find.widgetWithText(FilledButton, 'Confirm'),
      );

      expect(confirmed, 0, reason: 'sign-up must not complete');
      expect(find.textContaining('word at position 8'), findsOneWidget);
    });

    /// A keyboard suggestion adds a trailing space and a capital. Neither is a
    /// wrong answer, and rejecting them would send someone back to a list they
    /// copied correctly.
    testWidgets('tolerates surrounding space and capitals', (tester) async {
      await tester.pumpWidget(page(indices: [2, 7, 19]));
      await reachConfirmation(tester);

      await tester.enterText(
        find.widgetWithText(TextField, 'Word 3'),
        ' Charlie ',
      );
      await tester.enterText(find.widgetWithText(TextField, 'Word 8'), 'HOTEL');
      await tester.enterText(
        find.widgetWithText(TextField, 'Word 20'),
        'Tango',
      );
      await tapAfterScrolling(
        tester,
        find.widgetWithText(FilledButton, 'Confirm'),
      );

      expect(confirmed, 1);
    });

    testWidgets('the words can be shown again before confirming', (
      tester,
    ) async {
      await tester.pumpWidget(page());
      await reachConfirmation(tester);

      await tapAfterScrolling(
        tester,
        find.widgetWithText(TextButton, 'Show the words again'),
      );

      expect(find.text('charlie'), findsOneWidget);
    });
  });
}
