import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../config/deployment.dart';
import '../rust/api/sync.dart' as rust;
import '../services/device_identity_service.dart';
import '../services/identity_auth_service.dart';
import '../services/localized_error.dart';
import '../services/sync_controller.dart';
import '../services/vault_session.dart';
import '../ui/form_page.dart';
import 'recover_password_page.dart';

/// The two ways a device joins an account.
enum SignInMode {
  /// This device already holds the vault and the account slots. It is telling
  /// the server about them for the first time.
  register,

  /// This device holds nothing. It is fetching the wrapped vault key and
  /// unwrapping it locally.
  signIn,
}

/// Joins this device to a sync account.
///
/// Built on [FormPage] so the action stays outside the scroll view. A field
/// that scrolls off is disposed, and a validator that never runs returns
/// success — which is how a form once reported valid while checking nothing.
class SyncSignInPage extends StatefulWidget {
  const SyncSignInPage({
    super.key,
    required this.controller,
    required this.session,
    required this.mode,
  });

  final SyncController controller;
  final VaultSession session;
  final SignInMode mode;

  @override
  State<SyncSignInPage> createState() => _SyncSignInPageState();
}

class _SyncSignInPageState extends State<SyncSignInPage> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _approval = TextEditingController();
  final _recovery = TextEditingController();
  final _identityPassword = TextEditingController();

  bool _busy = false;
  String? _problem;
  IdentityProof? _identityProof;
  bool _verificationSent = false;

  bool get _isRegister => widget.mode == SignInMode.register;

  @override
  void initState() {
    super.initState();
    if (_isRegister) {
      _email.text = widget.controller.status.email ?? '';
    }
  }

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _approval.dispose();
    _recovery.dispose();
    _identityPassword.dispose();
    super.dispose();
  }

  /// Validation read from the controllers, not from the widget tree.
  ///
  /// Returns the first problem, so the message names one thing to fix rather
  /// than listing everything at once.
  String? _firstProblem() {
    if (!_isRegister && !_email.text.contains('@')) {
      return AppLocalizations.of(context).enterAccountEmail;
    }
    if (_password.text.isEmpty) {
      return _isRegister
          ? AppLocalizations.of(context).enterNewAccountPassword
          : AppLocalizations.of(context).enterAccountPassword;
    }
    if (_isRegister &&
        _recovery.text.trim().split(RegExp(r'\s+')).length != 24) {
      return AppLocalizations.of(context).enterRecoveryPhraseForSync;
    }
    if (_isRegister && _identityProof == null) {
      return AppLocalizations.of(context).verifyEmailBeforeSync;
    }
    return null;
  }

  Future<void> _submit() async {
    final problem = _firstProblem();
    if (problem != null) {
      setState(() => _problem = problem);
      return;
    }

    setState(() {
      _busy = true;
      _problem = null;
    });

    try {
      await rust.setServerUrl(url: autharoSyncServerUrl);
      final device = await DeviceIdentityService.current();
      if (_isRegister) {
        final proof = await IdentityAuthService.instance.freshProof();
        if (proof.email.trim().toLowerCase() !=
            _email.text.trim().toLowerCase()) {
          throw IdentityEmailMismatch();
        }
        await rust.registerAccount(
          password: _password.text,
          recoveryPhrase: _recovery.text.trim(),
          deviceName: device.name,
          identityToken: proof.token,
        );
        await IdentityAuthService.instance.clear();
      } else {
        final handle = await rust.beginSignIn(
          email: _email.text.trim(),
          password: _password.text,
          deviceName: device.name,
          deviceApprovalToken: _approval.text.trim().isEmpty
              ? null
              : _approval.text.trim(),
          recoveryPhrase: _recovery.text.trim().isEmpty
              ? null
              : _recovery.text.trim(),
        );
        await widget.session.finishSyncSignIn(handle);
      }

      // Straight into a first cycle. Turning sync on and seeing nothing happen
      // is indistinguishable from turning it on and it not working.
      await widget.controller.syncNow();

      if (mounted) Navigator.of(context).pop();
    } catch (error) {
      // The message the core produced, not a generic one. These are written
      // for the user — "the email address or password is not correct", "choose
      // a sync server first" — and replacing them with "something went wrong"
      // would throw away the only useful part.
      if (mounted) {
        setState(
          () => _problem = localizedError(AppLocalizations.of(context), error),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _startEmailVerification() async {
    final l10n = AppLocalizations.of(context);
    if (_identityPassword.text.length < 6) {
      setState(() => _problem = l10n.identityPasswordTooShort);
      return;
    }
    if (_identityPassword.text == _password.text) {
      setState(() => _problem = l10n.identityPasswordMustDiffer);
      return;
    }
    await _runIdentity(() async {
      final proof = await IdentityAuthService.instance.startEmailVerification(
        email: _email.text.trim(),
        identityPassword: _identityPassword.text,
        languageCode: Localizations.localeOf(context).languageCode,
      );
      if (proof == null) {
        setState(() {
          _verificationSent = true;
          _problem = l10n.emailVerificationSent;
        });
      } else {
        _acceptIdentity(proof);
      }
    });
  }

  Future<void> _finishEmailVerification() => _runIdentity(() async {
    final proof = await IdentityAuthService.instance.finishEmailVerification();
    _acceptIdentity(proof);
  });

  Future<void> _continueWithGoogle() => _runIdentity(() async {
    final proof = await IdentityAuthService.instance.signInWithGoogle();
    _acceptIdentity(proof);
  });

  Future<void> _runIdentity(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _problem = null;
    });
    try {
      await action();
    } on IdentityConfigurationException {
      if (mounted) {
        setState(
          () => _problem = AppLocalizations.of(context).firebaseNotConfigured,
        );
      }
    } on EmailVerificationPending {
      if (mounted) {
        setState(
          () =>
              _problem = AppLocalizations.of(context).verificationStillPending,
        );
      }
    } on IdentityEmailMismatch {
      if (mounted) {
        setState(
          () => _problem = AppLocalizations.of(context).identityEmailMismatch,
        );
      }
    } catch (error) {
      if (mounted) {
        setState(
          () => _problem = localizedError(AppLocalizations.of(context), error),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _acceptIdentity(IdentityProof proof) {
    final expected = _email.text.trim().toLowerCase();
    if (proof.email.trim().toLowerCase() != expected) {
      throw IdentityEmailMismatch();
    }
    setState(() {
      _identityProof = proof;
      _verificationSent = false;
      _problem = null;
    });
  }

  Future<void> _recoverPassword() async {
    await rust.setServerUrl(url: autharoSyncServerUrl);
    if (!mounted) return;
    final recovered = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => RecoverPasswordPage(
          serverUrl: autharoSyncServerUrl,
          initialEmail: _email.text.trim(),
        ),
      ),
    );
    if (recovered != true || !mounted) return;
    await widget.controller.syncNow();
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: _isRegister ? l10n.turnOnSync : l10n.signIn,
      actionLabel: _isRegister ? l10n.turnOnSync : l10n.signIn,
      busy: _busy,
      errorMessage: _problem,
      onAction: _busy ? null : _submit,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: Text(
            _isRegister
                ? l10n.syncEncryptionDescription
                : l10n.signInDownloadDescription,
          ),
        ),
        TextField(
          controller: _email,
          decoration: InputDecoration(
            labelText: l10n.email,
            // On the register path the address is already decided: it came
            // from the account this device built. Showing it read-only says
            // which account is about to be created, without inviting an edit
            // that would not take effect.
            helperText: _isRegister ? l10n.fromDeviceAccount : null,
          ),
          keyboardType: TextInputType.emailAddress,
          autocorrect: false,
          enabled: !_busy && !_isRegister,
        ),
        if (_isRegister) ...[
          const SizedBox(height: 20),
          Text(
            l10n.verifyEmailOwnership,
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          if (_identityProof != null)
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.verified_user_outlined),
              title: Text(l10n.emailOwnershipVerified(_identityProof!.email)),
            )
          else ...[
            TextField(
              controller: _identityPassword,
              decoration: InputDecoration(
                labelText: l10n.identityPassword,
                helperText: l10n.identityPasswordHelp,
              ),
              obscureText: true,
              enabled: !_busy,
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: _busy ? null : _startEmailVerification,
              icon: const Icon(Icons.mark_email_read_outlined),
              label: Text(l10n.verifyWithEmail),
            ),
            if (_verificationSent)
              TextButton(
                onPressed: _busy ? null : _finishEmailVerification,
                child: Text(l10n.iVerifiedMyEmail),
              ),
            const SizedBox(height: 4),
            OutlinedButton.icon(
              onPressed: _busy ? null : _continueWithGoogle,
              icon: const Icon(Icons.account_circle_outlined),
              label: Text(l10n.continueWithGoogle),
            ),
          ],
        ],
        const SizedBox(height: 12),
        TextField(
          controller: _password,
          decoration: InputDecoration(labelText: l10n.accountPassword),
          obscureText: true,
          enabled: !_busy,
          onSubmitted: (_) => _busy ? null : _submit(),
        ),
        if (!_isRegister)
          Align(
            alignment: Alignment.centerRight,
            child: TextButton(
              onPressed: _busy ? null : _recoverPassword,
              child: Text(l10n.forgotPassword),
            ),
          ),
        if (!_isRegister) ...[
          const SizedBox(height: 12),
          TextField(
            controller: _approval,
            decoration: InputDecoration(
              labelText: l10n.deviceApprovalCodeOptional,
              helperText: l10n.deviceApprovalSignInHelp,
            ),
            autocorrect: false,
            enableSuggestions: false,
            enabled: !_busy,
          ),
        ],
        const SizedBox(height: 12),
        TextField(
          controller: _recovery,
          decoration: InputDecoration(
            labelText: _isRegister
                ? l10n.recoveryPhraseRequired
                : l10n.recoveryPhraseOptional,
            helperText: _isRegister
                ? l10n.recoveryPhraseSyncRegistrationHelp
                : l10n.recoveryPhraseSignInHelp,
          ),
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          enabled: !_busy,
        ),
      ],
    );
  }
}
