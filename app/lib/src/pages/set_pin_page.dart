import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../l10n/generated/app_localizations.dart';
import '../services/vault_session.dart';
import '../ui/form_page.dart';

/// Sets, changes, or removes the application lock PIN (FR-31).
///
/// The confirmation field is not ceremony. A mistyped PIN here is not
/// recoverable: it becomes half of what wraps the vault key, and nothing on
/// the device or the server can work out what the user meant to type.
class SetPinPage extends StatefulWidget {
  const SetPinPage({
    super.key,
    required this.session,
    this.hasExistingPin = false,
  });

  final VaultSession session;

  /// Changes the wording, and offers removal.
  final bool hasExistingPin;

  @override
  State<SetPinPage> createState() => _SetPinPageState();
}

class _SetPinPageState extends State<SetPinPage> {
  final _pin = TextEditingController();
  final _confirm = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  bool _busy = false;
  bool _useBiometrics = true;
  String? _error;

  @override
  void dispose() {
    _pin.dispose();
    _confirm.dispose();
    super.dispose();
  }

  /// The client-side half of FR-31. The core validates again and is the
  /// authority — this exists to answer while the user is still typing, not to
  /// be the check that matters.
  String? _validate(String? value) {
    final pin = value ?? '';
    final digitsOnly = pin.isNotEmpty && RegExp(r'^\d+$').hasMatch(pin);

    if (pin.length < 6) {
      return digitsOnly || pin.isEmpty
          ? AppLocalizations.of(context).useAtLeastSixDigits
          : AppLocalizations.of(context).useAtLeastSixCharacters;
    }
    if (digitsOnly) {
      if (pin.split('').toSet().length == 1) {
        return AppLocalizations.of(context).avoidRepeatedPin;
      }
      if (_isRun(pin)) {
        return AppLocalizations.of(context).avoidSequentialPin;
      }
    }
    return null;
  }

  static bool _isRun(String pin) {
    final codes = pin.codeUnits;
    final step = codes[1] - codes[0];
    if (step != 1 && step != -1) return false;
    for (var i = 1; i < codes.length; i++) {
      if (codes[i] - codes[i - 1] != step) return false;
    }
    return true;
  }

  /// Validates from the controllers, not through the `Form`.
  ///
  /// Same reason as the create-account screen: a `ListView` disposes its
  /// off-screen children, so `Form.validate()` skips any field that has
  /// scrolled away and returns true having checked nothing.
  String? _firstProblem() {
    return _validate(_pin.text) ??
        (_confirm.text == _pin.text
            ? null
            : AppLocalizations.of(context).entriesDoNotMatch);
  }

  Future<void> _save() async {
    _formKey.currentState?.validate();

    final problem = _firstProblem();
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.session.changePin(
        _pin.text,
        requireUserAuthentication: _useBiometrics,
      );
      if (!mounted) return;
      Navigator.pop(context, true);
    } on PlatformException catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error.code == 'authentication_cancelled'
            ? null
            : (error.message ??
                  AppLocalizations.of(context).deviceKeyProtectionFailed);
        _busy = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error.toString();
        _busy = false;
      });
    }
  }

  Future<void> _remove() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).removePinQuestion),
        content: Text(AppLocalizations.of(context).removePinWarning),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).keepIt),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(AppLocalizations.of(context).remove),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() => _busy = true);
    try {
      await widget.session.changePin(null, requireUserAuthentication: false);
      if (!mounted) return;
      Navigator.pop(context, true);
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error.toString();
        _busy = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: widget.hasExistingPin ? l10n.changePin : l10n.setPin,
      formKey: _formKey,
      busy: _busy,
      errorMessage: _error,
      actionLabel: l10n.save,
      onAction: _save,
      secondaryAction: widget.hasExistingPin
          ? TextButton(
              onPressed: _busy ? null : _remove,
              child: Text(l10n.removePin),
            )
          : null,
      children: [
        Text(l10n.pinKeyDescription),
        const SizedBox(height: 24),
        TextFormField(
          controller: _pin,
          // Not autofocused: the keyboard would cover the pinned action.
          obscureText: true,
          enabled: !_busy,
          validator: _validate,
          decoration: InputDecoration(
            labelText: l10n.newPinOrPassphrase,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _confirm,
          obscureText: true,
          enabled: !_busy,
          validator: (value) =>
              value == _pin.text ? null : l10n.entriesDoNotMatch,
          decoration: InputDecoration(
            labelText: l10n.enterItAgain,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        SwitchListTile(
          value: _useBiometrics,
          onChanged: _busy
              ? null
              : (value) => setState(() => _useBiometrics = value),
          title: Text(l10n.allowBiometricUnlock),
          subtitle: Text(l10n.biometricInvalidationDescription),
          contentPadding: EdgeInsets.zero,
        ),
        const SizedBox(height: 16),
        Text(
          l10n.pinDerivationDescription,
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    );
  }
}
