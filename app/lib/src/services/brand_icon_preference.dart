import 'package:flutter/foundation.dart';

import '../rust/api/vault.dart' as rust;

/// Controls the bundled service-symbol pack for the current installation.
///
/// The symbols are part of the application. This service never sends issuer
/// names to a favicon service or another network endpoint.
class BrandIconPreference {
  BrandIconPreference._();

  static final enabled = ValueNotifier<bool>(true);

  static void load() {
    enabled.value = rust.brandIconsEnabled();
  }

  static Future<void> setEnabled(bool value) async {
    await rust.setBrandIconsEnabled(enabled: value);
    enabled.value = value;
  }
}
