import 'package:flutter/foundation.dart';

import '../rust/api/vault.dart' as rust;

/// Controls full-colour service favicons for the current installation.
///
/// When enabled, the avatar sends the matched service domain to Google's
/// favicon service. When disabled, the app uses only local letter tiles.
class BrandIconPreference {
  BrandIconPreference._();

  // Remote icon lookup discloses the matched service domain. Require explicit
  // user consent before the first request.
  static final enabled = ValueNotifier<bool>(false);

  static void load() {
    enabled.value = rust.brandIconsEnabled();
  }

  static Future<void> setEnabled(bool value) async {
    await rust.setBrandIconsEnabled(enabled: value);
    enabled.value = value;
  }
}
