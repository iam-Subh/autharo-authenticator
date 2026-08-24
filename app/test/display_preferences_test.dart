import 'package:authenticator/src/services/appearance_preference.dart';
import 'package:authenticator/src/services/code_visibility_preference.dart';
import 'package:authenticator/src/services/recovery_status_preference.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    AppearancePreference.theme.value = AppThemeChoice.system;
    AppearancePreference.listDensity.value = ListDensityChoice.comfortable;
    AppearancePreference.language.value = AppLanguageChoice.system;
    CodeVisibilityPreference.hideCodesUntilTap.value = false;
    RecoveryStatusPreference.confirmed.value = false;
  });

  test(
    'display preferences use safe defaults when no choice is stored',
    () async {
      await AppearancePreference.load();
      await CodeVisibilityPreference.load();

      expect(AppearancePreference.theme.value, AppThemeChoice.system);
      expect(
        AppearancePreference.listDensity.value,
        ListDensityChoice.comfortable,
      );
      expect(CodeVisibilityPreference.hideCodesUntilTap.value, isFalse);
      expect(AppearancePreference.language.value, AppLanguageChoice.system);
    },
  );

  test('display preferences persist and reload both choices', () async {
    await AppearancePreference.setTheme(AppThemeChoice.amoled);
    await AppearancePreference.setListDensity(ListDensityChoice.compact);
    await AppearancePreference.setLanguage(AppLanguageChoice.hindi);
    await CodeVisibilityPreference.setHideCodesUntilTap(true);

    AppearancePreference.theme.value = AppThemeChoice.system;
    AppearancePreference.listDensity.value = ListDensityChoice.comfortable;
    AppearancePreference.language.value = AppLanguageChoice.system;
    CodeVisibilityPreference.hideCodesUntilTap.value = false;

    await AppearancePreference.load();
    await CodeVisibilityPreference.load();

    expect(AppearancePreference.theme.value, AppThemeChoice.amoled);
    expect(AppearancePreference.listDensity.value, ListDensityChoice.compact);
    expect(AppearancePreference.language.value, AppLanguageChoice.hindi);
    expect(CodeVisibilityPreference.hideCodesUntilTap.value, isTrue);
  });

  test('an unknown stored theme falls back to the device setting', () async {
    FlutterSecureStorage.setMockInitialValues({'ui.theme_mode': 'unknown'});

    await AppearancePreference.load();

    expect(AppearancePreference.theme.value, AppThemeChoice.system);
  });

  test('recovery status records only the completed confirmation', () async {
    await RecoveryStatusPreference.markConfirmed();
    RecoveryStatusPreference.confirmed.value = false;

    await RecoveryStatusPreference.load();
    expect(RecoveryStatusPreference.confirmed.value, isTrue);

    await RecoveryStatusPreference.clear();
    expect(RecoveryStatusPreference.confirmed.value, isFalse);
  });
}
