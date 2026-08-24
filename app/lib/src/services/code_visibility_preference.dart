import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Stores whether the account list hides OTP codes until the user taps a row.
class CodeVisibilityPreference {
  CodeVisibilityPreference._();

  static const _key = 'ui.hide_codes_until_tap';
  static const _storage = FlutterSecureStorage();

  static final hideCodesUntilTap = ValueNotifier<bool>(false);

  static Future<void> load() async {
    hideCodesUntilTap.value = await _storage.read(key: _key) == 'true';
  }

  static Future<void> setHideCodesUntilTap(bool value) async {
    await _storage.write(key: _key, value: value.toString());
    hideCodesUntilTap.value = value;
  }
}
