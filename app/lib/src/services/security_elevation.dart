import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;

const securityReadScope = 'security:read';
const shareWriteScope = 'share:write';

/// Requests a temporary server permission without retaining the password or
/// token in Dart. Rust derives the proof and keeps the token in memory.
Future<bool> authorizeScope(
  BuildContext context, {
  required String scope,
  required String action,
}) async {
  if (await rust.hasElevatedScope(scope: scope)) return true;
  if (!context.mounted) return false;
  final password = await showDialog<String>(
    context: context,
    builder: (_) => _ElevationDialog(action: action),
  );
  if (password == null || password.isEmpty || !context.mounted) return false;
  await rust.elevateSession(password: password, scopes: [scope]);
  return true;
}

class _ElevationDialog extends StatefulWidget {
  const _ElevationDialog({required this.action});

  final String action;

  @override
  State<_ElevationDialog> createState() => _ElevationDialogState();
}

class _ElevationDialogState extends State<_ElevationDialog> {
  final _password = TextEditingController();

  @override
  void dispose() {
    _password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      icon: const Icon(Icons.password_outlined),
      title: Text(widget.action),
      content: TextField(
        controller: _password,
        autofocus: true,
        obscureText: true,
        autocorrect: false,
        enableSuggestions: false,
        decoration: InputDecoration(
          labelText: l10n.accountPassword,
          helperText: l10n.passwordRequiredForProtectedAction,
        ),
        onSubmitted: (value) => Navigator.pop(context, value),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _password.text),
          child: Text(l10n.continueLabel),
        ),
      ],
    );
  }
}
