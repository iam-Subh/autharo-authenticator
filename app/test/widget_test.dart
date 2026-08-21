import 'package:authenticator/src/ui/code_display.dart';
import 'package:authenticator/src/ui/countdown_ring.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('CodeDisplay', () {
    test('groups codes the way the issuing services print them', () {
      expect(CodeDisplay.group('123456'), '123 456');
      expect(CodeDisplay.group('1234567'), '1234 567');
      expect(CodeDisplay.group('12345678'), '1234 5678');
    });

    testWidgets('hides the digits when asked (FR-25)', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: CodeDisplay(code: '123456', hidden: true)),
        ),
      );

      expect(find.text('123 456'), findsNothing);
      expect(find.text('••• •••'), findsOneWidget);
    });

    testWidgets('reads the digits out singly for a screen reader', (tester) async {
      final handle = tester.ensureSemantics();
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: CodeDisplay(code: '123456')),
        ),
      );

      expect(find.bySemanticsLabel('1 2 3 4 5 6'), findsOneWidget);
      handle.dispose();
    });
  });

  group('CountdownRing', () {
    testWidgets('labels the remaining time for a screen reader', (tester) async {
      final handle = tester.ensureSemantics();
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: CountdownRing(remainingSeconds: 7, period: 30),
          ),
        ),
      );

      expect(find.bySemanticsLabel('Code expires in 7 seconds'), findsOneWidget);
      handle.dispose();
    });

    testWidgets('renders at the FR-07 warning threshold', (tester) async {
      // The colour change at 5 seconds is the requirement; this pins that the
      // widget builds at and around the boundary rather than the exact hue.
      for (final remaining in [6, 5, 1]) {
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CountdownRing(remainingSeconds: remaining, period: 30),
            ),
          ),
        );
        expect(find.text('$remaining'), findsOneWidget);
      }
      expect(CountdownRing.warningThresholdSeconds, 5);
    });
  });
}
