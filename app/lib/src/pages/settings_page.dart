import 'package:flutter/material.dart';

import '../rust/api/vault.dart' as rust;
import '../services/lock_controller.dart';
import '../services/vault_session.dart';
import 'create_account_page.dart';
import 'set_pin_page.dart';

/// The lock settings (FR-31 to FR-36).
///
/// FR-33 says to *offer* the timeout choices, so they need somewhere to live.
/// Without this screen the policy in `meta` would be written once and never
/// changed, and the PIN screen would be unreachable.
class SettingsPage extends StatefulWidget {
  const SettingsPage({
    super.key,
    required this.session,
    required this.lock,
  });

  final VaultSession session;
  final LockController lock;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  bool _hasPin = false;
  bool _busy = false;
  String? _accountEmail;

  @override
  void initState() {
    super.initState();
    _readSlot();
    _readAccount();
  }

  void _readAccount() {
    try {
      setState(() => _accountEmail = rust.accountEmail());
    } catch (_) {
      // A device with no account, or a metadata file that cannot be read.
      // Neither is a reason to fail the screen.
    }
  }

  /// Asks the core whether this device's slot uses a PIN, rather than keeping
  /// a separate flag that could drift from what is actually stored.
  Future<void> _readSlot() async {
    try {
      final blob = await rust.beginDeviceOpen();
      if (!mounted) return;
      setState(() => _hasPin = blob.needsPin);
    } catch (_) {
      // A slot that cannot be read is not a reason to fail the screen; the
      // rest of the settings still work.
    }
  }

  Future<void> _setPolicy(LockPolicy policy) async {
    setState(() => _busy = true);
    await widget.lock.setPolicy(policy);
    if (!mounted) return;
    setState(() => _busy = false);
  }

  Future<void> _openPinPage() async {
    final changed = await Navigator.push<bool>(
      context,
      MaterialPageRoute(
        builder: (_) => SetPinPage(
          session: widget.session,
          hasExistingPin: _hasPin,
        ),
      ),
    );
    if (changed == true) await _readSlot();
  }

  /// FR-36: an unlock is required before a destructive action. The vault is
  /// already unlocked to reach this screen, so the confirmation is what stands
  /// in the way — and it says plainly what cannot be undone.
  Future<void> _wipe() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Wipe this device?'),
        content: const Text(
          'Every code on this device is deleted and the key that decrypts them '
          'is destroyed. If you have not set up sync, nothing can bring them '
          'back — not this application, and not us.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Wipe'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    await widget.session.wipe();
    if (!mounted) return;
    Navigator.of(context).popUntil((route) => route.isFirst);
  }

  @override
  Widget build(BuildContext context) {
    final policy = widget.lock.policy;

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          const _SectionHeader('Application lock'),
          ListTile(
            leading: const Icon(Icons.pin_outlined),
            title: Text(_hasPin ? 'Change PIN' : 'Set a PIN'),
            subtitle: Text(
              _hasPin
                  ? 'Required along with this device\'s key to open your codes.'
                  : 'Without one, anyone who unlocks this device can read your codes.',
            ),
            onTap: _busy ? null : _openPinPage,
          ),
          ListTile(
            leading: const Icon(Icons.timer_outlined),
            title: const Text('Lock after'),
            subtitle: Text(policy.timeout.label),
            onTap: _busy ? null : _chooseTimeout,
          ),
          SwitchListTile(
            secondary: const Icon(Icons.visibility_off_outlined),
            title: const Text('Lock when leaving the app'),
            subtitle: const Text(
              'Locks the moment the app is no longer on screen.',
            ),
            value: policy.lockOnBackground,
            onChanged: _busy
                ? null
                : (value) =>
                    _setPolicy(policy.copyWith(lockOnBackground: value)),
          ),
          ListTile(
            leading: const Icon(Icons.lock_outline),
            title: const Text('Lock now'),
            onTap: _busy
                ? null
                : () {
                    widget.lock.lockNow();
                    Navigator.of(context).popUntil((route) => route.isFirst);
                  },
          ),
          const Divider(),
          const _SectionHeader('Sync'),
          if (_accountEmail == null)
            ListTile(
              leading: const Icon(Icons.cloud_outlined),
              title: const Text('Create an account'),
              subtitle: const Text(
                'Lets your codes reach your other devices. They stay encrypted.',
              ),
              onTap: _busy
                  ? null
                  : () async {
                      final created = await Navigator.push<bool>(
                        context,
                        MaterialPageRoute(
                          builder: (_) =>
                              CreateAccountPage(session: widget.session),
                        ),
                      );
                      if (created == true) _readAccount();
                    },
            )
          else
            ListTile(
              leading: const Icon(Icons.cloud_done_outlined),
              title: const Text('Account'),
              subtitle: Text(_accountEmail!),
            ),
          const Divider(),
          const _SectionHeader('This device'),
          ListTile(
            leading: Icon(
              Icons.delete_forever_outlined,
              color: Theme.of(context).colorScheme.error,
            ),
            title: Text(
              'Wipe this device',
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
            subtitle: const Text('Deletes every code and destroys the key.'),
            onTap: _busy ? null : _wipe,
          ),
          const Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Locking is not a screen that hides your codes. It removes the '
              'key from memory, so the stored codes cannot be read until you '
              'unlock again.',
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _chooseTimeout() async {
    final chosen = await showDialog<LockTimeout>(
      context: context,
      builder: (context) => SimpleDialog(
        title: const Text('Lock after'),
        children: [
          for (final choice in LockTimeout.values)
            RadioListTile<LockTimeout>(
              value: choice,
              groupValue: widget.lock.policy.timeout,
              title: Text(choice.label),
              onChanged: (value) => Navigator.pop(context, value),
            ),
        ],
      ),
    );
    if (chosen == null) return;
    await _setPolicy(widget.lock.policy.copyWith(timeout: chosen));
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelLarge?.copyWith(
              color: Theme.of(context).colorScheme.primary,
            ),
      ),
    );
  }
}
