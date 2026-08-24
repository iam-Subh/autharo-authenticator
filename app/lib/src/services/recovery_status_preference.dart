import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Records that this installation completed the recovery-phrase word check.
///
/// The phrase is never stored. This flag records only the completed check.
class RecoveryStatusPreference {
  RecoveryStatusPreference._();

  static const _key = 'account.recovery_phrase_confirmed';
  static const _storage = FlutterSecureStorage();

  static final confirmed = ValueNotifier<bool>(false);

  static Future<void> load() async {
    confirmed.value = await _storage.read(key: _key) == 'true';
  }

  static Future<void> markConfirmed() async {
    await _storage.write(key: _key, value: 'true');
    confirmed.value = true;
  }

  static Future<void> clear() async {
    await _storage.delete(key: _key);
    confirmed.value = false;
  }
}
