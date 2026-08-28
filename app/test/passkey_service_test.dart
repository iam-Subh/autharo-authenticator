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

  test('authentication keeps the PRF result on the device', () async {
    final prf = List<int>.generate(32, (index) => index);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          channel,
          (_) async => jsonEncode({
            'id': 'credential',
            'clientExtensionResults': {
              'prf': {
                'results': {'first': base64UrlEncode(prf)},
              },
            },
          }),
        );

    final response = await PasskeyService().get('{}');
    final sanitized =
        jsonDecode(response.credentialJson) as Map<String, Object?>;

    expect(response.prfResult, prf);
    expect(response.credentialJson, isNot(contains(base64UrlEncode(prf))));
    final extensions =
        sanitized['clientExtensionResults'] as Map<String, Object?>;
    expect(
      (extensions['prf'] as Map<String, Object?>).containsKey('results'),
      isFalse,
    );
  });

  test(
    'registration reports PRF support without returning key material',
    () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (_) async => jsonEncode({
              'id': 'credential',
              'clientExtensionResults': {
                'prf': {'enabled': true},
              },
            }),
          );

      final response = await PasskeyService().create('{}');

      expect(response.prfSupported, isTrue);
      expect(response.credentialJson, contains('credential'));
    },
  );

  test('authentication rejects a PRF result with the wrong length', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          channel,
          (_) async => jsonEncode({
            'clientExtensionResults': {
              'prf': {
                'results': {'first': base64UrlEncode(List<int>.filled(31, 1))},
              },
            },
          }),
        );

    expect(PasskeyService().get('{}'), throwsFormatException);
  });
}
