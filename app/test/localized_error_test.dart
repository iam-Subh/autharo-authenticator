import 'package:authenticator/l10n/generated/app_localizations_en.dart';
import 'package:authenticator/src/services/localized_error.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final l10n = AppLocalizationsEn();

  test('maps a stable server error code to localized text', () {
    expect(
      localizedError(
        l10n,
        Exception('[email_verification_required] Token required.'),
      ),
      l10n.errorEmailVerificationRequired,
    );
  });

  test('uses the safe server detail for an unknown code', () {
    expect(
      localizedError(l10n, '[future_error] Try again later.'),
      'Try again later.',
    );
  });

  test('keeps local errors that do not have a stable code', () {
    expect(
      localizedError(l10n, 'Local validation failed.'),
      'Local validation failed.',
    );
  });
}
