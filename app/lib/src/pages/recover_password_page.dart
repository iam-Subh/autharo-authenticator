import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/device_identity_service.dart';
import '../services/localized_error.dart';
import '../ui/form_page.dart';

class RecoverPasswordPage extends StatefulWidget {
  const RecoverPasswordPage({
    super.key,
    required this.serverUrl,
    required this.initialEmail,
  });

  final String serverUrl;
  final String initialEmail;

  @override
  State<RecoverPasswordPage> createState() => _RecoverPasswordPageState();
}

class _RecoverPasswordPageState extends State<RecoverPasswordPage> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _email = TextEditingController(
    text: widget.initialEmail,
  );
  final _recovery = TextEditingController();
  final _password = TextEditingController();
  final _confirm = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _email.dispose();
    _recovery.dispose();
    _password.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _reset() async {
    if (_busy) return;
    final l10n = AppLocalizations.of(context);
    final words = _recovery.text.trim().split(RegExp(r'\s+'));
    final problem = !_email.text.contains('@')
        ? l10n.enterAccountEmail
        : words.length != 24
        ? l10n.enterRecoveryPhraseForSync
        : _password.text.length < 10
        ? l10n.passwordMinimumTen
        : _password.text != _confirm.text
        ? l10n.passwordsDoNotMatch
        : null;
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await rust.setServerUrl(url: widget.serverUrl);
      final device = await DeviceIdentityService.current();
      await rust.recoverAccountPassword(
        email: _email.text.trim(),
        recoveryPhrase: _recovery.text.trim(),
        newPassword: _password.text,
        deviceName: device.name,
      );
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l10n.passwordResetComplete)));
      Navigator.of(context).pop(true);
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = localizedError(l10n, error);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: l10n.resetAccountPassword,
      formKey: _formKey,
      busy: _busy,
      errorMessage: _error,
      actionLabel: l10n.resetAccountPassword,
      onAction: _reset,
      children: [
        Text(l10n.resetPasswordDescription),
        const SizedBox(height: 24),
        TextFormField(
          controller: _email,
          enabled: !_busy,
          keyboardType: TextInputType.emailAddress,
          autocorrect: false,
          decoration: InputDecoration(
            labelText: l10n.email,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _recovery,
          enabled: !_busy,
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          decoration: InputDecoration(
            labelText: l10n.recoveryPhraseRequired,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _password,
          enabled: !_busy,
          obscureText: true,
          autofillHints: const [AutofillHints.newPassword],
          decoration: InputDecoration(
            labelText: l10n.newPassword,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _confirm,
          enabled: !_busy,
          obscureText: true,
          autofillHints: const [AutofillHints.newPassword],
          decoration: InputDecoration(
            labelText: l10n.enterNewPasswordAgain,
            border: const OutlineInputBorder(),
          ),
        ),
      ],
    );
  }
}
