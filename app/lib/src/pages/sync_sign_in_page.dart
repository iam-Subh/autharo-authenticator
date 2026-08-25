import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/sync_controller.dart';
import '../ui/form_page.dart';

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
    required this.mode,
  });

  final SyncController controller;
  final SignInMode mode;

  @override
  State<SyncSignInPage> createState() => _SyncSignInPageState();
}

class _SyncSignInPageState extends State<SyncSignInPage> {
  final _server = TextEditingController();
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _approval = TextEditingController();
  final _recovery = TextEditingController();

  bool _busy = false;
  String? _problem;

  bool get _isRegister => widget.mode == SignInMode.register;

  @override
  void initState() {
    super.initState();
    _server.text = widget.controller.status.serverUrl ?? '';
    if (_isRegister) {
      _email.text = widget.controller.status.email ?? '';
    }
  }

  @override
  void dispose() {
    _server.dispose();
    _email.dispose();
    _password.dispose();
    _approval.dispose();
    _recovery.dispose();
    super.dispose();
  }

  /// Validation read from the controllers, not from the widget tree.
  ///
  /// Returns the first problem, so the message names one thing to fix rather
  /// than listing everything at once.
  String? _firstProblem() {
    final server = _server.text.trim();
    if (server.isEmpty) {
      return AppLocalizations.of(context).enterSyncServer;
    }
    if (!server.startsWith('http://') && !server.startsWith('https://')) {
      return AppLocalizations.of(context).syncServerRequiresHttps;
    }
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
      await rust.setServerUrl(url: _server.text.trim());
      if (_isRegister) {
        await rust.registerAccount(
          password: _password.text,
          recoveryPhrase: _recovery.text.trim(),
          deviceName: 'this device',
        );
      } else {
        await rust.signIn(
          email: _email.text.trim(),
          password: _password.text,
          deviceName: 'this device',
          deviceApprovalToken: _approval.text.trim().isEmpty
              ? null
              : _approval.text.trim(),
          recoveryPhrase: _recovery.text.trim().isEmpty
              ? null
              : _recovery.text.trim(),
        );
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
      if (mounted) setState(() => _problem = '$error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
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
          controller: _server,
          decoration: InputDecoration(
            labelText: l10n.syncServer,
            hintText: AppLocalizations.of(context).syncServerExample,
          ),
          keyboardType: TextInputType.url,
          autocorrect: false,
          enabled: !_busy,
        ),
        const SizedBox(height: 12),
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
        const SizedBox(height: 12),
        TextField(
          controller: _password,
          decoration: InputDecoration(labelText: l10n.accountPassword),
          obscureText: true,
          enabled: !_busy,
          onSubmitted: (_) => _busy ? null : _submit(),
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
