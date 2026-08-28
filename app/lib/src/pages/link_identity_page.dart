import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/identity_auth_service.dart';
import '../services/localized_error.dart';
import '../ui/form_page.dart';

class LinkIdentityPage extends StatefulWidget {
  const LinkIdentityPage({super.key, required this.email});

  final String email;

  @override
  State<LinkIdentityPage> createState() => _LinkIdentityPageState();
}

class _LinkIdentityPageState extends State<LinkIdentityPage> {
  final _vaultPassword = TextEditingController();
  final _identityPassword = TextEditingController();
  IdentityProof? _proof;
  bool _verificationSent = false;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _vaultPassword.dispose();
    _identityPassword.dispose();
    super.dispose();
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } on IdentityConfigurationException {
      if (mounted) {
        setState(
          () => _error = AppLocalizations.of(context).firebaseNotConfigured,
        );
      }
    } on EmailVerificationPending {
      if (mounted) {
        setState(
          () => _error = AppLocalizations.of(context).verificationStillPending,
        );
      }
    } on IdentityEmailMismatch {
      if (mounted) {
        setState(
          () => _error = AppLocalizations.of(context).identityEmailMismatch,
        );
      }
    } catch (error) {
      if (mounted) {
        setState(
          () => _error = localizedError(AppLocalizations.of(context), error),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _accept(IdentityProof proof) {
    if (proof.email.trim().toLowerCase() != widget.email.trim().toLowerCase()) {
      throw IdentityEmailMismatch();
    }
    setState(() {
      _proof = proof;
      _verificationSent = false;
    });
  }

  Future<void> _email() => _run(() async {
    final l10n = AppLocalizations.of(context);
    if (_identityPassword.text.length < 6) {
      throw StateError(l10n.identityPasswordTooShort);
    }
    if (_identityPassword.text == _vaultPassword.text) {
      throw StateError(l10n.identityPasswordMustDiffer);
    }
    final proof = await IdentityAuthService.instance.startEmailVerification(
      email: widget.email,
      identityPassword: _identityPassword.text,
      languageCode: Localizations.localeOf(context).languageCode,
    );
    if (proof == null) {
      setState(() => _verificationSent = true);
    } else {
      _accept(proof);
    }
  });

  Future<void> _finishEmail() => _run(() async {
    _accept(await IdentityAuthService.instance.finishEmailVerification());
  });

  Future<void> _google() => _run(() async {
    _accept(await IdentityAuthService.instance.signInWithGoogle());
  });

  Future<void> _link() => _run(() async {
    final l10n = AppLocalizations.of(context);
    if (_vaultPassword.text.isEmpty) {
      throw StateError(l10n.enterAccountPassword);
    }
    final proof = _proof;
    if (proof == null) throw StateError(l10n.verifyEmailBeforeSync);
    final fresh = await IdentityAuthService.instance.freshProof();
    if (fresh.email.trim().toLowerCase() != widget.email.trim().toLowerCase()) {
      throw IdentityEmailMismatch();
    }
    await rust.linkIdentity(
      password: _vaultPassword.text,
      identityToken: fresh.token,
    );
    await IdentityAuthService.instance.clear();
    if (mounted) Navigator.of(context).pop(true);
  });

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: l10n.linkVerifiedIdentity,
      actionLabel: l10n.linkVerifiedIdentity,
      busy: _busy,
      errorMessage: _error,
      onAction: _busy ? null : _link,
      children: [
        Text(l10n.linkVerifiedIdentityDescription(widget.email)),
        const SizedBox(height: 16),
        TextField(
          controller: _vaultPassword,
          obscureText: true,
          enabled: !_busy,
          decoration: InputDecoration(labelText: l10n.accountPassword),
        ),
        const SizedBox(height: 20),
        if (_proof != null)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.verified_user_outlined),
            title: Text(l10n.emailOwnershipVerified(_proof!.email)),
          )
        else ...[
          TextField(
            controller: _identityPassword,
            obscureText: true,
            enabled: !_busy,
            decoration: InputDecoration(
              labelText: l10n.identityPassword,
              helperText: l10n.identityPasswordHelp,
            ),
          ),
          const SizedBox(height: 8),
          OutlinedButton.icon(
            onPressed: _busy ? null : _email,
            icon: const Icon(Icons.mark_email_read_outlined),
            label: Text(l10n.verifyWithEmail),
          ),
          if (_verificationSent) ...[
            Text(l10n.emailVerificationSent),
            TextButton(
              onPressed: _busy ? null : _finishEmail,
              child: Text(l10n.iVerifiedMyEmail),
            ),
          ],
          OutlinedButton.icon(
            onPressed: _busy ? null : _google,
            icon: const Icon(Icons.account_circle_outlined),
            label: Text(l10n.continueWithGoogle),
          ),
        ],
      ],
    );
  }
}
