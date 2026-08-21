import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';

import '../services/vault_session.dart';

/// The unlock screen (FR-31, FR-32, FR-35).
///
/// This is the screen that stands between a stolen phone and the codes, so it
/// is worth being clear about what it does. It is not hiding the list: while
/// this screen is up the vault key does not exist in memory, and the records
/// are ciphertext. The PIN and the keystore together are what bring the key
/// back.
class UnlockPage extends StatefulWidget {
  const UnlockPage({
    super.key,
    required this.session,
    required this.onUnlocked,
  });

  final VaultSession session;
  final VoidCallback onUnlocked;

  @override
  State<UnlockPage> createState() => _UnlockPageState();
}

class _UnlockPageState extends State<UnlockPage> {
  final _pin = TextEditingController();
  final _auth = LocalAuthentication();

  bool _busy = false;
  bool _obscured = true;
  String? _error;

  /// FR-35's limit. The wipe itself is off by default, so this drives the
  /// warning rather than the action.
  static const _attemptLimit = 10;

  @override
  void dispose() {
    _pin.dispose();
    super.dispose();
  }

  Future<void> _unlock() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });

    try {
      await widget.session.unlock(pin: _pin.text);
      if (!mounted) return;
      widget.onUnlocked();
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = _message(error);
        _busy = false;
      });
      // Clear on failure so a wrong PIN is not silently resubmitted, and so a
      // shoulder-surfer does not get a second look at it.
      _pin.clear();
    }
  }

  /// FR-32. The keystore key can be bound to this check, in which case the
  /// unwrap below simply fails until it has happened.
  Future<void> _unlockWithBiometrics() async {
    try {
      final ok = await _auth.authenticate(
        localizedReason: 'Unlock your authenticator',
        // Not biometric-only: FR-32 lists the device credential alongside the
        // fingerprint, and a device with no enrolled biometric must still be
        // able to get in.
        biometricOnly: false,
        // Survives the system prompt taking the application off-screen, which
        // would otherwise read as a backgrounding and cancel the attempt.
        persistAcrossBackgrounding: true,
      );
      if (!ok || !mounted) return;
      await _unlock();
    } on LocalAuthException catch (error) {
      if (!mounted) return;
      setState(() => _error = error.description ?? 'Biometric unlock failed.');
    }
  }

  static String _message(Object error) {
    final text = error.toString();
    for (final prefix in ['Exception: ', 'AnyhowException(', 'Bad state: ']) {
      if (text.startsWith(prefix)) {
        return text.substring(prefix.length).replaceAll(RegExp(r'\)$'), '');
      }
    }
    return text;
  }

  @override
  Widget build(BuildContext context) {
    final attempts = widget.session.failedAttempts;
    final remaining = _attemptLimit - attempts;

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Icon(
                    Icons.lock_outline,
                    size: 56,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(height: 24),
                  Text(
                    'Locked',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Your codes are encrypted until you unlock.',
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 32),
                  TextField(
                    controller: _pin,
                    autofocus: true,
                    obscureText: _obscured,
                    enabled: !_busy,
                    keyboardType: TextInputType.visiblePassword,
                    onSubmitted: (_) => _unlock(),
                    decoration: InputDecoration(
                      labelText: 'PIN or passphrase',
                      border: const OutlineInputBorder(),
                      errorText: _error,
                      suffixIcon: IconButton(
                        icon: Icon(
                          _obscured ? Icons.visibility : Icons.visibility_off,
                        ),
                        tooltip: _obscured ? 'Show' : 'Hide',
                        onPressed: () => setState(() => _obscured = !_obscured),
                      ),
                    ),
                  ),
                  if (attempts > 0) ...[
                    const SizedBox(height: 12),
                    Text(
                      remaining > 0
                          ? '$attempts failed ${attempts == 1 ? "attempt" : "attempts"}. '
                              '$remaining left before this device is wiped, if you '
                              'turned that on.'
                          : 'The failed attempt limit has been reached.',
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ],
                  const SizedBox(height: 24),
                  FilledButton(
                    onPressed: _busy ? null : _unlock,
                    child: _busy
                        ? const SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Text('Unlock'),
                  ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: _busy ? null : _unlockWithBiometrics,
                    icon: const Icon(Icons.fingerprint),
                    label: const Text('Use biometrics'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
