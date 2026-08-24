import 'package:authenticator/src/services/screen_capture_service.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('dev.authcore.authenticator/screen_capture');

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('reads the current screenshot policy', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          expect(call.method, 'isBlocked');
          return false;
        });

    final service = ScreenCaptureService(channel: channel);
    expect(await service.isBlocked(), isFalse);
  });

  test('sends and stores a changed screenshot policy', () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });

    final service = ScreenCaptureService(channel: channel);
    await service.setBlocked(false);

    expect(received?.method, 'setBlocked');
    expect(received?.arguments, <String, Object>{'blocked': false});
  });
}
