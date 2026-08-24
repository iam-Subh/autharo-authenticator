import 'package:authenticator/src/pages/create_account_page.dart';
import 'package:authenticator/src/pages/manual_entry_page.dart';
import 'package:authenticator/src/pages/set_pin_page.dart';
import 'package:authenticator/src/services/vault_session.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'localized_test_app.dart';

/// The form rules from section 17, applied to **every** form rather than to
/// the two where the defect was first found.
///
/// Two failures motivate this file, and both were invisible on a default host
/// surface and certain on a phone:
///
/// 1. `Form.validate()` only reaches fields that are currently built, and a
///    `ListView` disposes its off-screen children. A submit button below the
///    fold meant scrolling unregistered the fields above it, and `validate()`
///    returned true having run no validator at all.
/// 2. With a field focused, the soft keyboard covers the bottom of the screen.
///    A button at the end of a scroll view sits behind it, and a tap aimed at
///    the button lands on the keyboard.
///
/// `FormPage` fixes both by pinning the action outside the scroll view, and
/// each page validates from its controllers. These tests hold that for all
/// three forms at a phone-sized surface with the keyboard shown, so a fourth
/// form added later has an obvious place to be covered.
void main() {
  /// A small phone in portrait, with room taken at the bottom for the soft
  /// keyboard. `viewInsets` is what `Scaffold` reads to lift its body.
  void useSmallPhoneWithKeyboard(WidgetTester tester) {
    tester.view.physicalSize = const Size(360, 640);
    tester.view.devicePixelRatio = 1.0;
    tester.view.viewInsets = FakeViewPadding(bottom: 300);
    addTearDown(tester.view.reset);
  }

  /// Every form page under test, with the label of its action and a check
  /// that must appear when it is pressed with nothing filled in.
  final forms = <String, ({Widget page, String action, String expected})>{
    'create account': (
      page: CreateAccountPage(session: VaultSession()),
      action: 'Create account',
      expected: 'An email address is required.',
    ),
    'set PIN': (
      page: SetPinPage(session: VaultSession()),
      action: 'Save',
      expected: 'Use at least 6 digits.',
    ),
    'manual entry': (
      page: const ManualEntryPage(),
      action: 'Add account',
      expected: 'An account name is required.',
    ),
  };

  for (final entry in forms.entries) {
    final name = entry.key;
    final form = entry.value;

    group(name, () {
      testWidgets('the action is reachable with the keyboard up', (
        tester,
      ) async {
        useSmallPhoneWithKeyboard(tester);
        await tester.pumpWidget(localizedTestApp(home: form.page));
        await tester.pumpAndSettle();

        // No scrolling. The action is pinned outside the scroll view, so it is
        // on screen from the start even with the keyboard taking 300 pixels.
        final action = find.widgetWithText(FilledButton, form.action);
        expect(
          action,
          findsOneWidget,
          reason: 'the action must be built without scrolling to it',
        );
        expect(
          tester.getRect(action).bottom,
          lessThanOrEqualTo(tester.view.physicalSize.height - 300),
          reason: 'the action must sit above the keyboard, not behind it',
        );
      });

      testWidgets('no field autofocuses, so the keyboard does not open '
          'over the action', (tester) async {
        useSmallPhoneWithKeyboard(tester);
        await tester.pumpWidget(localizedTestApp(home: form.page));
        await tester.pumpAndSettle();

        // Not `primaryFocus`: some node always holds it, usually the root
        // scope. What opens the keyboard is a focused *text field*, so that is
        // what to look for.
        final aFieldHasFocus = tester
            .widgetList<EditableText>(find.byType(EditableText))
            .any((field) => field.focusNode.hasFocus);

        expect(
          aFieldHasFocus,
          isFalse,
          reason:
              'a focused field opens the keyboard before the user has read '
              'the screen, and on a short screen that hides the explanation',
        );
      });

      testWidgets('validation runs even when the fields are scrolled away', (
        tester,
      ) async {
        useSmallPhoneWithKeyboard(tester);
        await tester.pumpWidget(localizedTestApp(home: form.page));
        await tester.pumpAndSettle();

        // Scroll the fields out of the ListView, which disposes them. This is
        // the state in which `Form.validate()` silently checks nothing.
        await tester.drag(find.byType(ListView), const Offset(0, -2000));
        await tester.pumpAndSettle();

        await tester.tap(find.widgetWithText(FilledButton, form.action));
        await tester.pumpAndSettle();

        expect(
          find.text(form.expected),
          findsWidgets,
          reason: 'the check must not depend on the field being built',
        );
      });
    });
  }
}
