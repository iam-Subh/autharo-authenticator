import '../../l10n/generated/app_localizations.dart';

/// Converts stable Rust and server error codes to translated interface text.
String localizedError(AppLocalizations l10n, Object error) {
  var text = '$error';
  for (final prefix in const ['AnyhowException(', 'Exception: ']) {
    if (text.startsWith(prefix)) text = text.substring(prefix.length);
  }
  if (text.endsWith(')')) text = text.substring(0, text.length - 1);

  final match = RegExp(r'\[([a-z0-9_]+)\]').firstMatch(text);
  final code = match?.group(1);
  return switch (code) {
    'invalid_credentials' => l10n.errorInvalidCredentials,
    'conflict' => l10n.errorAccountConflict,
    'transport' => l10n.errorServerUnavailable,
    'invalid_response' => l10n.errorInvalidServerResponse,
    'unauthorized' => l10n.errorSignedOut,
    'device_approval_required' => l10n.errorDeviceApprovalRequired,
    'insufficient_scope' => l10n.errorInsufficientScope,
    'elevation_required' => l10n.errorElevationRequired,
    'invalid_scope' => l10n.errorInvalidScope,
    'capability_expired' => l10n.errorCapabilityExpired,
    'not_found' => l10n.errorNotFound,
    'email_verification_required' => l10n.errorEmailVerificationRequired,
    'invalid_identity' => l10n.errorInvalidIdentity,
    'rate_limited' => l10n.errorRateLimited,
    'quota_exceeded' => l10n.errorQuotaExceeded,
    'too_large' => l10n.errorRequestTooLarge,
    'feature_unavailable' => l10n.errorFeatureUnavailable,
    'internal' => l10n.errorServerInternal,
    'identity_wrong_password' ||
    'identity_invalid_credential' ||
    'identity_user_not_found' => l10n.errorIdentityCredentials,
    'identity_invalid_email' => l10n.errorIdentityEmail,
    'identity_weak_password' => l10n.errorIdentityWeakPassword,
    'identity_network_request_failed' => l10n.errorIdentityNetwork,
    'identity_too_many_requests' => l10n.errorRateLimited,
    'identity_user_disabled' => l10n.errorIdentityDisabled,
    'identity_google_canceled' => l10n.errorIdentityCanceled,
    _ =>
      match == null
          ? text.trim()
          : text.substring(match.end).trim().isEmpty
          ? l10n.errorUnknown
          : text.substring(match.end).trim(),
  };
}
