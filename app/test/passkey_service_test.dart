import 'dart:convert';

import 'package:authenticator/src/services/passkey_service.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('app.autharo.authenticator/passkey');

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('registration keeps the PRF secret on the device', () async {
    final secret = Uint8List.fromList(List<int>.generate(32, (index) => index));
    final encoded = base64Url.encode(secret).replaceAll('=', '');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          expect(call.method, 'create');
          return jsonEncode({
            'id': 'credential',
            'clientExtensionResults': {
              'prf': {
                'enabled': true,
                'results': {'first': encoded},
              },
            },
          });
        });

    final response = await PasskeyService().create('{}');

    expect(response.prfSupported, isTrue);
    expect(response.prfResult, secret);
    expect(response.credentialJson, isNot(contains('results')));
    expect(response.credentialJson, isNot(contains(encoded)));
  });

  test('an invalid PRF result is rejected', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async {
          return jsonEncode({
            'clientExtensionResults': {
              'prf': {
                'enabled': true,
                'results': {
                  'first': base64Url.encode([1, 2, 3]),
                },
              },
            },
          });
        });

    await expectLater(
      PasskeyService().create('{}'),
      throwsA(isA<FormatException>()),
    );
  });
}
