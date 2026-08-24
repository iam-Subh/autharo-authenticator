import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../ui/form_page.dart';

/// FR-13: "Enter an account by hand. Ask for issuer, account name, secret,
/// type, algorithm, digits, and period."
///
/// The screen returns an `otpauth://` URI rather than a set of fields, so the
/// typed path and the scanned path meet at exactly one parser. Two paths with
/// two validations would eventually disagree about what a valid entry is.
class ManualEntryPage extends StatefulWidget {
  const ManualEntryPage({super.key});

  @override
  State<ManualEntryPage> createState() => _ManualEntryPageState();
}

class _ManualEntryPageState extends State<ManualEntryPage> {
  final _form = GlobalKey<FormState>();
  final _issuer = TextEditingController();
  final _account = TextEditingController();
  final _secret = TextEditingController();
  final _counter = TextEditingController(text: '0');

  String? _error;
  String _kind = 'totp';
  String _algorithm = 'SHA1';
  int _digits = 6;
  int _period = 30;

  @override
  void dispose() {
    _issuer.dispose();
    _account.dispose();
    _secret.dispose();
    _counter.dispose();
    super.dispose();
  }

  /// Builds the URI. Percent-encoding matters here: an issuer containing a
  /// colon or a space would otherwise change how the label parses.
  String _buildUri() {
    final issuer = _issuer.text.trim();
    final account = _account.text.trim();
    final label = issuer.isEmpty ? account : '$issuer:$account';

    final parameters = <String, String>{
      // The core normalizes and validates this; it is passed through as typed.
      'secret': _secret.text.trim(),
      if (issuer.isNotEmpty) 'issuer': issuer,
      'algorithm': _algorithm,
      'digits': '$_digits',
      if (_kind == 'totp') 'period': '$_period',
      if (_kind == 'hotp') 'counter': _counter.text.trim(),
    };

    final query = parameters.entries
        .map((e) => '${e.key}=${Uri.encodeComponent(e.value)}')
        .join('&');

    return 'otpauth://$_kind/${Uri.encodeComponent(label)}?$query';
  }

  /// Validates from the controllers rather than through the `Form`.
  ///
  /// The fields scroll, and a `ListView` disposes what scrolls away, so
  /// `Form.validate()` silently skips any field that is off screen and returns
  /// true having checked nothing. The controllers are owned by this State and
  /// outlive the widgets. See `FormPage` for the whole story.
  String? _firstProblem() {
    if (_account.text.trim().isEmpty) {
      return AppLocalizations.of(context).accountNameRequired;
    }
    if (_secret.text.trim().isEmpty) {
      return AppLocalizations.of(context).enterSetupKeyError;
    }
    if (_kind == 'hotp') {
      final counter = int.tryParse(_counter.text.trim());
      if (counter == null || counter < 0) {
        return AppLocalizations.of(context).counterInvalid;
      }
    }
    return null;
  }

  void _submit() {
    // Runs the visible fields' validators for inline feedback. The result is
    // ignored; the controller check below is what decides.
    _form.currentState?.validate();

    final problem = _firstProblem();
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    Navigator.of(context).pop(_buildUri());
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: l10n.enterSetupKey,
      formKey: _form,
      errorMessage: _error,
      actionLabel: l10n.addAccount,
      onAction: _submit,
      children: [
        TextFormField(
          controller: _issuer,
          textCapitalization: TextCapitalization.words,
          decoration: InputDecoration(
            labelText: l10n.service,
            helperText: l10n.issuerHelper,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _account,
          autocorrect: false,
          decoration: InputDecoration(
            labelText: l10n.account,
            helperText: l10n.accountHelper,
            border: const OutlineInputBorder(),
          ),
          validator: (value) => (value == null || value.trim().isEmpty)
              ? l10n.enterAccountForCode
              : null,
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _secret,
          autocorrect: false,
          // Not `obscureText`: a mistyped secret is the most likely failure
          // here, and hiding it makes that harder to catch, not safer. The
          // screen is covered by FLAG_SECURE when screenshot protection
          // is enabled.
          decoration: InputDecoration(
            labelText: l10n.setupKey,
            helperText: l10n.setupKeyHelper,
            border: const OutlineInputBorder(),
          ),
          validator: (value) => (value == null || value.trim().isEmpty)
              ? l10n.enterSetupKeyError
              : null,
        ),
        const SizedBox(height: 24),
        SegmentedButton<String>(
          segments: [
            ButtonSegment(value: 'totp', label: Text(l10n.timeBased)),
            ButtonSegment(value: 'hotp', label: Text(l10n.counterBased)),
          ],
          selected: {_kind},
          onSelectionChanged: (selected) =>
              setState(() => _kind = selected.first),
        ),
        const SizedBox(height: 8),
        Text(
          _kind == 'totp'
              ? l10n.timeBasedDescription
              : l10n.counterBasedDescription,
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        if (_kind == 'hotp')
          TextFormField(
            controller: _counter,
            keyboardType: TextInputType.number,
            decoration: InputDecoration(
              labelText: l10n.startingCounter,
              helperText: l10n.counterHelper,
              border: const OutlineInputBorder(),
            ),
            validator: (value) {
              if (_kind != 'hotp') return null;
              final parsed = int.tryParse(value?.trim() ?? '');
              if (parsed == null || parsed < 0) {
                return l10n.enterWholeCounter;
              }
              return null;
            },
          ),
        ExpansionTile(
          title: Text(l10n.advanced),
          subtitle: Text(
            '$_algorithm, $_digits digits'
            '${_kind == 'totp' ? ', every $_period seconds' : ''}',
          ),
          childrenPadding: const EdgeInsets.symmetric(vertical: 8),
          children: [
            // FR-03. Nearly every service uses SHA-1; the others are here
            // because the ones that do not, say so explicitly.
            DropdownButtonFormField<String>(
              initialValue: _algorithm,
              decoration: InputDecoration(
                labelText: l10n.algorithm,
                border: const OutlineInputBorder(),
              ),
              items: const [
                'SHA1',
                'SHA256',
                'SHA512',
              ].map((v) => DropdownMenuItem(value: v, child: Text(v))).toList(),
              onChanged: (value) =>
                  setState(() => _algorithm = value ?? 'SHA1'),
            ),
            const SizedBox(height: 16),
            // FR-04.
            DropdownButtonFormField<int>(
              initialValue: _digits,
              decoration: InputDecoration(
                labelText: l10n.digits,
                border: const OutlineInputBorder(),
              ),
              items: const [6, 7, 8]
                  .map((v) => DropdownMenuItem(value: v, child: Text('$v')))
                  .toList(),
              onChanged: (value) => setState(() => _digits = value ?? 6),
            ),
            if (_kind == 'totp') ...[
              const SizedBox(height: 16),
              // FR-05 allows any period from 10 to 300. The common values
              // are offered here; the core accepts the rest from a URI.
              DropdownButtonFormField<int>(
                initialValue: _period,
                decoration: InputDecoration(
                  labelText: l10n.period,
                  border: const OutlineInputBorder(),
                ),
                items: const [15, 30, 60]
                    .map(
                      (v) => DropdownMenuItem(
                        value: v,
                        child: Text(l10n.secondsValue(v)),
                      ),
                    )
                    .toList(),
                onChanged: (value) => setState(() => _period = value ?? 30),
              ),
            ],
          ],
        ),
      ],
    );
  }
}
