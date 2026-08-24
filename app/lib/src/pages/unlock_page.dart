import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../services/vault_session.dart';

/// The unlock screen (FR-31, FR-32, FR-35).
///
/// This is the screen that stands between a stolen phone and the codes, so it
/// is worth being clear about what it does. It is not hiding the list: while
/// this screen is up the vault key does not exist in memory, and the records
/// are ciphertext. The PIN and the keystore together are what bring the key
/// back. A separate biometric slot can release the same key without the PIN.
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

  bool _busy = false;
  bool _obscured = true;
  String? _error;

  /// Whether this vault's slot needs a PIN, read from the slot itself.
  ///
  /// Null until it has been read. This controls the PIN field validation. The
  /// biometric button uses its own slot and does not submit an empty PIN.
  bool? _needsPin;
  bool _hasBiometricUnlock = false;
  bool _hasAccountRecovery = false;

  /// FR-35's limit. The wipe itself is off by default, so this drives the
  /// warning rather than the action.
  static const _attemptLimit = 10;

  @override
  void initState() {
    super.initState();
    _readSlot();
  }

  Future<void> _readSlot() async {
    try {
      final blob = await widget.session.slotDescription();
      if (mounted) {
        setState(() {
          _needsPin = blob.needsPin;
          _hasBiometricUnlock = widget.session.hasBiometricUnlock;
          _hasAccountRecovery = widget.session.hasAccountRecovery;
        });
      }
    } catch (_) {
      // Unknown. Treated as needing a PIN, which hides the biometric button
      // rather than offering one that might spend an attempt.
      if (mounted) setState(() => _needsPin = true);
    }
  }

  @override
  void dispose() {
    _pin.dispose();
    super.dispose();
  }

  Future<void> _unlock() async {
    if (_busy) return;
    // Never submitted. The core refuses an empty PIN without counting it, and
    // this stops the round trip that would show "PIN is incorrect" to someone
    // who simply has not typed anything yet.
    if (_needsPin == true && _pin.text.isEmpty) {
      setState(() => _error = AppLocalizations.of(context).enterPin);
      return;
    }
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
        // Dismissing the biometric prompt is a decision, not a failure. It
        // must not read as one, and it must not look like the vault is
        // damaged — the PIN field is right there and still works.
        _error = _isCancellation(error) ? null : _message(error);
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
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.session.unlockWithBiometrics();
      if (!mounted) return;
      widget.onUnlocked();
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = _isCancellation(error)
            ? null
            : AppLocalizations.of(context).biometricUnlockFailed;
        _busy = false;
      });
    }
  }

  Future<void> _unlockWithAccountCredential({required bool recovery}) async {
    final value = await showDialog<String>(
      context: context,
      builder: (_) => _AccountUnlockDialog(recovery: recovery),
    );
    if (value == null || value.trim().isEmpty || !mounted) return;

    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (recovery) {
        final normalized = value.trim().split(RegExp(r'\s+')).join(' ');
        await widget.session.unlockWithRecoveryPhrase(normalized);
      } else {
        await widget.session.unlockWithAccountPassword(value);
      }
      if (!mounted) return;
      widget.onUnlocked();
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = _message(error);
        _busy = false;
      });
    }
  }

  /// True when the user dismissed the system authentication prompt.
  ///
  /// Matched on the platform error code the activity sets, not on the message
  /// text, which is written by the OS and differs per device and per language.
  static bool _isCancellation(Object error) =>
      error.toString().contains('authentication_cancelled');

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
                    AppLocalizations.of(context).lockedTitle,
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    AppLocalizations.of(context).lockedBody,
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
                      labelText: AppLocalizations.of(context).pinOrPassphrase,
                      border: const OutlineInputBorder(),
                      errorText: _error,
                      suffixIcon: IconButton(
                        icon: Icon(
                          _obscured ? Icons.visibility : Icons.visibility_off,
                        ),
                        tooltip: _obscured
                            ? AppLocalizations.of(context).show
                            : AppLocalizations.of(context).hide,
                        onPressed: () => setState(() => _obscured = !_obscured),
                      ),
                    ),
                  ),
                  if (attempts > 0) ...[
                    const SizedBox(height: 12),
                    Text(
                      remaining > 0
                          ? AppLocalizations.of(
                              context,
                            ).failedAttemptsRemaining(attempts, remaining)
                          : AppLocalizations.of(
                              context,
                            ).failedAttemptLimitReached,
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
                        : Text(AppLocalizations.of(context).unlock),
                  ),
                  if (_hasBiometricUnlock) ...[
                    const SizedBox(height: 8),
                    TextButton.icon(
                      onPressed: _busy ? null : _unlockWithBiometrics,
                      icon: const Icon(Icons.fingerprint),
                      label: Text(AppLocalizations.of(context).useBiometrics),
                    ),
                  ],
                  if (_hasAccountRecovery) ...[
                    const SizedBox(height: 8),
                    TextButton(
                      onPressed: _busy
                          ? null
                          : () => _unlockWithAccountCredential(recovery: false),
                      child: Text(
                        AppLocalizations.of(context).useAccountPassword,
                      ),
                    ),
                    TextButton(
                      onPressed: _busy
                          ? null
                          : () => _unlockWithAccountCredential(recovery: true),
                      child: Text(
                        AppLocalizations.of(context).useRecoveryPhrase,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _AccountUnlockDialog extends StatefulWidget {
  const _AccountUnlockDialog({required this.recovery});

  final bool recovery;

  @override
  State<_AccountUnlockDialog> createState() => _AccountUnlockDialogState();
}

class _AccountUnlockDialogState extends State<_AccountUnlockDialog> {
  final _value = TextEditingController();
  bool _obscured = true;

  @override
  void dispose() {
    _value.dispose();
    super.dispose();
  }

  void _submit() {
    if (_value.text.trim().isEmpty) return;
    Navigator.pop(context, _value.text);
  }

  @override
  Widget build(BuildContext context) {
    final recovery = widget.recovery;
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(
        recovery ? l10n.useRecoveryPhraseTitle : l10n.useAccountPasswordTitle,
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              recovery
                  ? l10n.recoveryPhraseEntryHelp
                  : l10n.accountPasswordEntryHelp,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _value,
              autofocus: true,
              obscureText: _obscured,
              minLines: recovery && !_obscured ? 3 : 1,
              maxLines: recovery && !_obscured ? 5 : 1,
              autocorrect: false,
              enableSuggestions: false,
              textInputAction: recovery
                  ? TextInputAction.newline
                  : TextInputAction.done,
              onSubmitted: recovery ? null : (_) => _submit(),
              decoration: InputDecoration(
                labelText: recovery ? l10n.recoveryPhraseField : l10n.password,
                border: const OutlineInputBorder(),
                suffixIcon: IconButton(
                  tooltip: _obscured ? l10n.show : l10n.hide,
                  icon: Icon(
                    _obscured ? Icons.visibility : Icons.visibility_off,
                  ),
                  onPressed: () => setState(() => _obscured = !_obscured),
                ),
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(AppLocalizations.of(context).cancel),
        ),
        FilledButton(
          onPressed: _submit,
          child: Text(AppLocalizations.of(context).unlock),
        ),
      ],
    );
  }
}
