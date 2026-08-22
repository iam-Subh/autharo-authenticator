import 'package:authenticator/src/pages/create_account_page.dart';
import 'package:authenticator/src/services/vault_session.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

/// The bug this file exists for.
///
/// `Form.validate()` only reaches fields that are currently built. These pages
/// are `ListView`s, which dispose their off-screen children, so on a phone —
/// where the submit button sits below the fold — scrolling to the button
/// unregisters the fields above it. `validate()` then returns **true** having
/// run no validator at all, and an empty or malformed address sails past every
/// client-side check.
///
/// It was found on the device, not on the host: the host surface happened to
/// show the whole form. That is the argument for running the suite on the
/// phone rather than trusting a passing host run.
void main() {
  /// Demonstrates the Flutter behaviour itself, so the reason for the fix
  /// stays visible even if the pages are rewritten.
  testWidgets('a Form does not validate a field scrolled out of a ListView',
      (tester) async {
    final formKey = GlobalKey<FormState>();
    var validatorRan = false;

    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: Form(
          key: formKey,
          child: ListView(
            children: [
              TextFormField(
                validator: (_) {
                  validatorRan = true;
                  return 'always invalid';
                },
              ),
              const SizedBox(height: 2000),
              const Text('bottom'),
            ],
          ),
        ),
      ),
    ));

    expect(formKey.currentState!.validate(), isFalse);
    expect(validatorRan, isTrue, reason: 'visible: the validator runs');

    validatorRan = false;
    await tester.scrollUntilVisible(
      find.text('bottom'),
      300,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();

    expect(
      formKey.currentState!.validate(),
      isTrue,
      reason: 'this is the trap: validate() passes having checked nothing',
    );
    expect(validatorRan, isFalse);
  });

  /// And the fix: the page checks its controllers, so the result does not
  /// depend on what happens to be on screen.
  testWidgets('create-account still refuses a bad address after scrolling',
      (tester) async {
    // A small surface, so the button is below the fold as it is on a phone.
    tester.view.physicalSize = const Size(400, 700);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      MaterialApp(home: CreateAccountPage(session: VaultSession())),
    );

    final button = find.widgetWithText(FilledButton, 'Create account');
    await tester.scrollUntilVisible(
      button,
      200,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    await tester.tap(button);
    await tester.pumpAndSettle();

    // At least one: the message shows beside the button, and also inline on
    // the field when the field happens to still be visible. Either way the
    // user sees it, which is the point — the check no longer depends on what
    // is on screen.
    expect(
      find.text('An email address is required.'),
      findsWidgets,
      reason: 'validation must not depend on the field being on screen',
    );
  });
}
