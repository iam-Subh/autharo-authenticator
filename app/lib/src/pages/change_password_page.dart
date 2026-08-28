import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/localized_error.dart';
import '../ui/form_page.dart';

/// Replaces the sync-account password and revokes older device sessions.
class ChangePasswordPage extends StatefulWidget {
  const ChangePasswordPage({super.key});

  @override
  State<ChangePasswordPage> createState() => _ChangePasswordPageState();
}

class _ChangePasswordPageState extends State<ChangePasswordPage> {
  final _formKey = GlobalKey<FormState>();
  final _current = TextEditingController();
  final _password = TextEditingController();
  final _confirm = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _current.dispose();
    _password.dispose();
    _confirm.dispose();
    super.dispose();
  }

  String? _validateNewPassword(String? value) {
    if ((value ?? '').length < 10) {
      return AppLocalizations.of(context).passwordMinimumTen;
    }
    return null;
  }

  Future<void> _change() async {
    if (_busy) return;
    final l10n = AppLocalizations.of(context);
    _formKey.currentState?.validate();
    final problem = _current.text.isEmpty
        ? l10n.currentPassword
        : _validateNewPassword(_password.text) ??
              (_password.text == _confirm.text
                  ? null
                  : l10n.passwordsDoNotMatch);
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await rust.changeAccountPassword(
        currentPassword: _current.text,
        newPassword: _password.text,
      );
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l10n.passwordChanged)));
      Navigator.of(context).pop(true);
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = l10n.passwordChangeFailed(localizedError(l10n, error));
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: l10n.changeAccountPassword,
      formKey: _formKey,
      busy: _busy,
      errorMessage: _error,
      actionLabel: l10n.changeAccountPassword,
      onAction: _change,
      children: [
        Text(l10n.passwordChangeRevokesDevices),
        const SizedBox(height: 24),
        TextFormField(
          controller: _current,
          obscureText: true,
          enabled: !_busy,
          autofillHints: const [AutofillHints.password],
          decoration: InputDecoration(
            labelText: l10n.currentPassword,
            border: const OutlineInputBorder(),
          ),
          validator: (value) =>
              (value ?? '').isEmpty ? l10n.currentPassword : null,
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _password,
          obscureText: true,
          enabled: !_busy,
          autofillHints: const [AutofillHints.newPassword],
          decoration: InputDecoration(
            labelText: l10n.newPassword,
            border: const OutlineInputBorder(),
          ),
          validator: _validateNewPassword,
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _confirm,
          obscureText: true,
          enabled: !_busy,
          autofillHints: const [AutofillHints.newPassword],
          decoration: InputDecoration(
            labelText: l10n.enterNewPasswordAgain,
            border: const OutlineInputBorder(),
          ),
          validator: (value) =>
              value == _password.text ? null : l10n.passwordsDoNotMatch,
        ),
      ],
    );
  }
}
