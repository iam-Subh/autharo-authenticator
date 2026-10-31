import 'package:authenticator/src/config/deployment.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the official deployment uses the AuthFactor HTTPS service', () {
    final uri = Uri.parse(syncServerUrl);

    expect(uri.scheme, 'https');
    expect(uri.host, 'api.authfactor.app');
    expect(uri.path, isEmpty);
    expect(uri.hasPort, isFalse);
  });

  test('passkey registration is enabled for the production association', () {
    expect(passkeysEnabled, isTrue);
  });
}
