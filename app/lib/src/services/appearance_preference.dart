import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

enum AppThemeChoice {
  system,
  light,
  dark,
  amoled;

  ThemeMode get themeMode => switch (this) {
    AppThemeChoice.system => ThemeMode.system,
    AppThemeChoice.light => ThemeMode.light,
    AppThemeChoice.dark || AppThemeChoice.amoled => ThemeMode.dark,
  };
}

enum ListDensityChoice { comfortable, compact }

enum AppLanguageChoice {
  system,
  english,
  hindi;

  Locale? get locale => switch (this) {
    AppLanguageChoice.system => null,
    AppLanguageChoice.english => const Locale('en'),
    AppLanguageChoice.hindi => const Locale('hi'),
  };
}

/// Stores the colour theme selected for this installation.
class AppearancePreference {
  AppearancePreference._();

  static const _key = 'ui.theme_mode';
  static const _densityKey = 'ui.list_density';
  static const _dynamicColourKey = 'ui.dynamic_colour';
  static const _languageKey = 'ui.language';
  static const _storage = FlutterSecureStorage();
  static const _channel = MethodChannel(
    'dev.authcore.authenticator/appearance',
  );

  static final theme = ValueNotifier<AppThemeChoice>(AppThemeChoice.system);
  static final listDensity = ValueNotifier<ListDensityChoice>(
    ListDensityChoice.comfortable,
  );
  static final useDynamicColour = ValueNotifier<bool>(true);
  static final dynamicSeed = ValueNotifier<Color?>(null);
  static final language = ValueNotifier<AppLanguageChoice>(
    AppLanguageChoice.system,
  );

  static Future<void> load() async {
    final values = await Future.wait([
      _storage.read(key: _key),
      _storage.read(key: _densityKey),
      _storage.read(key: _dynamicColourKey),
      _storage.read(key: _languageKey),
    ]);
    theme.value = AppThemeChoice.values.firstWhere(
      (choice) => choice.name == values[0],
      orElse: () => AppThemeChoice.system,
    );
    listDensity.value = ListDensityChoice.values.firstWhere(
      (choice) => choice.name == values[1],
      orElse: () => ListDensityChoice.comfortable,
    );
    useDynamicColour.value = values[2] != 'false';
    language.value = AppLanguageChoice.values.firstWhere(
      (choice) => choice.name == values[3],
      orElse: () => AppLanguageChoice.system,
    );
  }

  static Future<void> loadDynamicColour() async {
    try {
      final value = await _channel.invokeMethod<int>('dynamicSeed');
      dynamicSeed.value = value == null ? null : Color(value);
    } on MissingPluginException {
      dynamicSeed.value = null;
    } on PlatformException {
      dynamicSeed.value = null;
    }
  }

  static Future<void> setTheme(AppThemeChoice choice) async {
    await _storage.write(key: _key, value: choice.name);
    theme.value = choice;
  }

  static Future<void> setListDensity(ListDensityChoice choice) async {
    await _storage.write(key: _densityKey, value: choice.name);
    listDensity.value = choice;
  }

  static Future<void> setUseDynamicColour(bool value) async {
    await _storage.write(key: _dynamicColourKey, value: value.toString());
    useDynamicColour.value = value;
  }

  static Future<void> setLanguage(AppLanguageChoice choice) async {
    await _storage.write(key: _languageKey, value: choice.name);
    language.value = choice;
  }

  static void resetAfterWipe() {
    theme.value = AppThemeChoice.system;
    listDensity.value = ListDensityChoice.comfortable;
    useDynamicColour.value = true;
    language.value = AppLanguageChoice.system;
  }

  static Color get activeSeed =>
      useDynamicColour.value ? dynamicSeed.value ?? fallbackSeed : fallbackSeed;

  static const fallbackSeed = Color(0xFF3B6EA5);

  static String themeLabel(AppThemeChoice choice) => switch (choice) {
    AppThemeChoice.system => 'Use device setting',
    AppThemeChoice.light => 'Light',
    AppThemeChoice.dark => 'Dark',
    AppThemeChoice.amoled => 'AMOLED black',
  };

  static String densityLabel(ListDensityChoice choice) => switch (choice) {
    ListDensityChoice.comfortable => 'Comfortable',
    ListDensityChoice.compact => 'Compact',
  };
}
