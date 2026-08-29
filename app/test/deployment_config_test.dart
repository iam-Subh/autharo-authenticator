import 'package:authenticator/src/config/deployment.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the official deployment uses the Autharo HTTPS service', () {
    final uri = Uri.parse(autharoSyncServerUrl);

    expect(uri.scheme, 'https');
    expect(uri.host, 'autharo-api.onrender.com');
    expect(uri.path, isEmpty);
    expect(uri.hasPort, isFalse);
  });

  test('passkeys stay hidden until the web association is deployed', () {
    expect(autharoPasskeysEnabled, isFalse);
  });
}
