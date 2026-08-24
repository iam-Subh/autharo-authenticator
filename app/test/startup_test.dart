import 'dart:async';

import 'package:authenticator/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets(
    'a Flutter frame is visible before native initialization starts',
    (tester) async {
      final pending = Completer<void>();
      var initializerCalls = 0;
      var loadingWasVisibleAtInitialization = false;

      await tester.pumpWidget(
        AuthenticatorApp(
          initialize: () {
            initializerCalls++;
            loadingWasVisibleAtInitialization = find
                .text('Opening authenticator…')
                .evaluate()
                .isNotEmpty;
            return pending.future;
          },
        ),
      );

      expect(initializerCalls, 1);
      expect(loadingWasVisibleAtInitialization, isTrue);
      expect(find.text('Opening authenticator…'), findsOneWidget);
    },
  );
}
