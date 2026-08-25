import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:authenticator/src/services/clipboard_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('dev.authcore.authenticator/clipboard');

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('disposing the service clears its copied secret', () async {
    String? clipboard;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'copySensitive') {
            clipboard = (call.arguments as Map)['text'] as String;
          } else if (call.method == 'clearIfEquals') {
            final expected = (call.arguments as Map)['expected'] as String;
            if (clipboard == expected) clipboard = null;
          }
          return null;
        });

    final service = ClipboardService(clearAfter: const Duration(hours: 1));
    await service.copyCode('123456');
    expect(clipboard, '123456');

    service.dispose();
    await Future<void>.delayed(Duration.zero);

    expect(clipboard, isNull);
  });
}
