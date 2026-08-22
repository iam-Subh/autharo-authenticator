import 'package:flutter/material.dart';

import '../rust/api/vault.dart' as rust;
import '../services/vault_session.dart';
import 'recovery_key_page.dart';

/// Creating a sync account (PRD section 16.2).
///
/// # What this does not do
///
/// It does not generate a vault key. Section 9.2.4: "When the user later
/// creates a sync account, keep the same vault key." Every code on the device
/// is already encrypted under the device slot's key, and a new one would leave
/// all of them unreadable. The core enforces this — `create_account` takes the
/// existing key — and this screen only collects the address and password.
///
/// It also does not talk to a server. Stage S4 builds the slots locally and
/// leaves the exchange for later; the authentication key is derived and
/// nothing is sent.
class CreateAccountPage extends StatefulWidget {
  const CreateAccountPage({super.key, required this.session});

  final VaultSession session;

  @override
  State<CreateAccountPage> createState() => _CreateAccountPageState();
}

class _CreateAccountPageState extends State<CreateAccountPage> {
  final _formKey = GlobalKey<FormState>();
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _confirm = TextEditingController();

  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _confirm.dispose();
    super.dispose();
  }

  /// Section 16.4 and decision 6: every synced account requires an email
  /// address, including a passkey account. Recovery, device approval, and
  /// support all key on it.
  String? _validateEmail(String? value) {
    final email = (value ?? '').trim();
    if (email.isEmpty) return 'An email address is required.';
    if (!email.contains('@') || email.startsWith('@') || email.endsWith('@')) {
      return 'That does not look like an email address.';
    }
    return null;
  }

  String? _validatePassword(String? value) {
    final password = value ?? '';
    // The floor only. The real protection is Argon2id at the cost in section
    // 9.2.1, and a strength meter here would imply a guarantee this screen
    // cannot make.
    if (password.length < 10) {
      return 'Use at least 10 characters. Longer beats complicated.';
    }
    return null;
  }

  /// Validates from the controllers rather than through the `Form`.
  ///
  /// `Form.validate()` only reaches fields that are currently built, and this
  /// page is a `ListView`, which disposes its off-screen children. On a phone
  /// the button sits below the fold, so scrolling to it unregisters the email
  /// field — and `validate()` then returns true having run no validator at
  /// all. The form silently stopped checking anything.
  ///
  /// The controllers are owned by this State and outlive the widgets, so
  /// checking them directly is correct regardless of what is on screen. The
  /// per-field validators stay for inline feedback while a field is visible.
  String? _firstProblem() {
    return _validateEmail(_email.text) ??
        _validatePassword(_password.text) ??
        (_confirm.text == _password.text
            ? null
            : 'The two password entries do not match.');
  }

  Future<void> _create() async {
    // Runs the visible fields' validators too, so an on-screen field shows its
    // message inline. The result is deliberately ignored: the check below is
    // the one that decides.
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
      final recovery = await rust.createAccount(
        email: _email.text.trim(),
        password: _password.text,
      );
      if (!mounted) return;

      // FR-55: the recovery key is shown at sign-up, for every method. The
      // account is not finished until the three words are confirmed.
      await Navigator.of(context).push(
        MaterialPageRoute(
          builder: (context) => RecoveryKeyPage(
            phrase: recovery.phrase,
            confirmIndices: recovery.confirmIndices.map((i) => i.toInt()).toList(),
            onConfirmed: () {
              Navigator.of(context).pop();
            },
          ),
        ),
      );
      if (!mounted) return;
      Navigator.of(context).pop(true);
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = _message(error);
        _busy = false;
      });
    }
  }

  static String _message(Object error) {
    final text = error.toString();
    for (final prefix in ['AnyhowException(', 'Exception: ']) {
      if (text.startsWith(prefix)) {
        return text.substring(prefix.length).replaceAll(RegExp(r'\)$'), '');
      }
    }
    return text;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Create an account')),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            const Text(
              'An account lets your codes reach your other devices. They stay '
              'encrypted on the way and on the server — the key that opens '
              'them never leaves your devices.',
            ),
            const SizedBox(height: 24),
            TextFormField(
              controller: _email,
              autofocus: true,
              keyboardType: TextInputType.emailAddress,
              autocorrect: false,
              enabled: !_busy,
              validator: _validateEmail,
              decoration: const InputDecoration(
                labelText: 'Email address',
                border: OutlineInputBorder(),
                helperText: 'Used for recovery and for approving new devices.',
              ),
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _password,
              obscureText: true,
              enabled: !_busy,
              validator: _validatePassword,
              decoration: const InputDecoration(
                labelText: 'Password',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _confirm,
              obscureText: true,
              enabled: !_busy,
              validator: (value) =>
                  value == _password.text ? null : 'The two entries do not match.',
              decoration: const InputDecoration(
                labelText: 'Enter the password again',
                border: OutlineInputBorder(),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 16),
              // Beside the button rather than only on the field, because the
              // field may be scrolled out of view when the button is pressed.
              Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
            const SizedBox(height: 24),
            FilledButton(
              onPressed: _busy ? null : _create,
              child: _busy
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Create account'),
            ),
            const SizedBox(height: 24),
            Text(
              'Your existing codes are kept as they are. Creating an account '
              'adds a way to unlock them, it does not re-encrypt them.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}
