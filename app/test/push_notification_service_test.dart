import 'package:authenticator/src/services/push_notification_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('push signal filtering', () {
    test('accepts the supported vault-change signal', () {
      expect(
        PushNotificationService.isVaultChangeSignal(const {
          'type': 'vault_changed',
          'schema': '1',
        }),
        isTrue,
      );
    });

    test('rejects unknown types and schema versions', () {
      expect(
        PushNotificationService.isVaultChangeSignal(const {
          'type': 'security_event',
          'schema': '1',
        }),
        isFalse,
      );
      expect(
        PushNotificationService.isVaultChangeSignal(const {
          'type': 'vault_changed',
          'schema': '2',
        }),
        isFalse,
      );
    });
  });
}
