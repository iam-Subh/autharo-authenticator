import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/clipboard_service.dart';
import '../services/security_elevation.dart';
import 'security_activity_page.dart';

/// Your devices, and the ways off the account (PRD §9.5).
///
/// # The question this screen answers
///
/// "I lost my phone."
///
/// The vault on it is encrypted behind a hardware key and a screen lock, so it
/// is not an emergency — but that device holds a refresh token good for thirty
/// days, and every code added anywhere else keeps arriving on it. Until this
/// screen existed there was nothing a user could do about that, which meant
/// asking them to trust a lock they could not change.
///
/// # Why deleting the account does not delete the codes
///
/// The most confusable pair on this screen. Deleting a sync account means "stop
/// storing my encrypted blobs" — it does not mean "destroy the authenticator I
/// use every day", and the codes on this device keep working afterwards.
///
/// Wiping the device is a different action on a different screen. Conflating
/// them would put the two most destructive operations in the product behind one
/// button, where the wrong outcome is unrecoverable in both directions.
class DevicesPage extends StatefulWidget {
  const DevicesPage({super.key, required this.onSignedOut});

  /// Called when this device is no longer signed in — after signing out
  /// everywhere, revoking this device, or deleting the account. The caller
  /// takes the user somewhere that makes sense, because this screen no longer
  /// does.
  final VoidCallback onSignedOut;

  @override
  State<DevicesPage> createState() => _DevicesPageState();
}

class _DevicesPageState extends State<DevicesPage> {
  List<rust.DeviceView>? _devices;
  Object? _error;
  bool _busy = false;
  final _clipboard = ClipboardService(clearAfter: const Duration(minutes: 10));

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _authorizeAndLoad());
  }

  @override
  void dispose() {
    _clipboard.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() => _error = null);
    try {
      final devices = await rust.listDevices();
      if (mounted) setState(() => _devices = devices);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _authorizeAndLoad() async {
    try {
      final authorized = await authorizeScope(
        context,
        scope: securityReadScope,
        action: AppLocalizations.of(context).yourDevices,
      );
      if (authorized && mounted) await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _guard(Future<void> Function() body) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await body();
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context)
          ..clearSnackBars()
          ..showSnackBar(SnackBar(content: Text(_message(error))));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// The core writes its errors for the user, so they are shown as written.
  static String _message(Object error) {
    final text = error.toString();
    return text.startsWith('Exception: ')
        ? text.substring('Exception: '.length)
        : text;
  }

  // -------------------------------------------------------------------------

  Future<void> _revoke(rust.DeviceView device) => _guard(() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          device.current
              ? AppLocalizations.of(context).signThisDeviceOutQuestion
              : AppLocalizations.of(context).removeDeviceQuestion(device.name),
        ),
        content: Text(
          device.current
              // Revoking the device in your hand is allowed — selling a phone
              // is a real reason to do it — but it must not happen by
              // accident, so the consequence is stated plainly.
              ? AppLocalizations.of(context).signThisDeviceOutDescription
              : AppLocalizations.of(context).removeDeviceDescription,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            onPressed: () => Navigator.pop(context, true),
            child: Text(
              device.current
                  ? AppLocalizations.of(context).signOut
                  : AppLocalizations.of(context).remove,
            ),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    final password = await _requestPassword(
      device.current
          ? AppLocalizations.of(context).signOut
          : AppLocalizations.of(context).removeThisDevice,
    );
    if (password == null || !mounted) return;

    await rust.revokeDevice(
      deviceId: device.id,
      password: password,
      current: device.current,
    );
    if (!mounted) return;

    if (device.current) {
      // The tokens still on this device now name a revoked session. Clearing
      // them locally keeps the app honest about its own state instead of
      // failing every cycle for the next fifteen minutes.
      if (mounted) widget.onSignedOut();
      return;
    }
    await _load();
  });

  Future<void> _signOutEverywhere() => _guard(() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).signOutEverywhereQuestion),
        content: Text(
          AppLocalizations.of(context).signOutEverywhereDescription,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(AppLocalizations.of(context).signOutEverywhere),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    final password = await _requestPassword(
      AppLocalizations.of(context).signOutEverywhere,
    );
    if (password == null || !mounted) return;

    await rust.signOutEverywhere(password: password);
    if (mounted) widget.onSignedOut();
  });

  Future<String?> _requestPassword(String action) {
    return showDialog<String>(
      context: context,
      builder: (_) => _StepUpPasswordDialog(action: action),
    );
  }

  Future<void> _createApproval() => _guard(() async {
    final password = await _requestPassword(
      AppLocalizations.of(context).approveNewDevice,
    );
    if (password == null || !mounted) return;
    final approval = await rust.createDeviceApproval(password: password);
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => AlertDialog(
        icon: const Icon(Icons.phonelink_lock_outlined),
        title: Text(AppLocalizations.of(context).deviceApprovalCode),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(AppLocalizations.of(context).deviceApprovalCodeHelp),
            const SizedBox(height: 16),
            SelectableText(
              approval.token,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              AppLocalizations.of(
                context,
              ).approvalCodeExpires(_formatTime(approval.expiresAt)),
            ),
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: () async {
              await _clipboard.copyCode(approval.token);
              if (dialogContext.mounted) {
                ScaffoldMessenger.of(dialogContext).showSnackBar(
                  SnackBar(
                    content: Text(AppLocalizations.of(dialogContext).copied),
                  ),
                );
              }
            },
            icon: const Icon(Icons.copy_outlined),
            label: Text(AppLocalizations.of(context).copy),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text(AppLocalizations.of(context).done),
          ),
        ],
      ),
    );
  });

  Future<void> _enrollRecovery() => _guard(() async {
    final values = await showDialog<(String, String)>(
      context: context,
      builder: (_) => const _RecoveryEnrollmentDialog(),
    );
    if (values == null || !mounted) return;
    await rust.enrollRecoveryAccess(
      password: values.$1,
      recoveryPhrase: values.$2,
    );
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(AppLocalizations.of(context).recoveryAccessEnabled),
      ),
    );
  });

  static String _formatTime(String raw) {
    final parsed = DateTime.tryParse(raw);
    if (parsed == null) return raw;
    final value = parsed.toLocal();
    return '${value.year}-${value.month.toString().padLeft(2, '0')}-'
        '${value.day.toString().padLeft(2, '0')} '
        '${value.hour.toString().padLeft(2, '0')}:'
        '${value.minute.toString().padLeft(2, '0')}';
  }

  Future<void> _deleteAccount() => _guard(() async {
    final password = await showDialog<String>(
      context: context,
      builder: (_) => const _DeleteAccountDialog(),
    );
    if (password == null || !mounted) return;

    final deleted = await rust.deleteAccount(password: password);
    if (!mounted) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          AppLocalizations.of(context).accountDeletedResult(deleted),
        ),
        duration: const Duration(seconds: 8),
      ),
    );
    widget.onSignedOut();
  });

  // -------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.yourDevices),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: l10n.refresh,
            onPressed: _busy ? null : _authorizeAndLoad,
          ),
        ],
      ),
      body: RefreshIndicator(onRefresh: _load, child: _content(colours)),
    );
  }

  Widget _content(ColorScheme colours) {
    final l10n = AppLocalizations.of(context);
    if (_error != null) {
      return ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text(_message(_error!)),
          const SizedBox(height: 16),
          Align(
            alignment: Alignment.centerLeft,
            child: FilledButton.tonal(
              onPressed: _authorizeAndLoad,
              child: Text(l10n.tryAgain),
            ),
          ),
        ],
      );
    }

    final devices = _devices;
    if (devices == null) {
      return const Center(child: CircularProgressIndicator());
    }

    return ListView(
      children: [
        if (_busy) const LinearProgressIndicator(),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            l10n.devicesIntroduction,
            style: TextStyle(color: colours.onSurfaceVariant),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.phonelink_lock_outlined),
          title: Text(l10n.approveNewDevice),
          subtitle: Text(l10n.approveNewDeviceDescription),
          onTap: _busy ? null : _createApproval,
        ),
        ListTile(
          leading: const Icon(Icons.key_outlined),
          title: Text(l10n.enableRecoverySignIn),
          subtitle: Text(l10n.enableRecoverySignInDescription),
          onTap: _busy ? null : _enrollRecovery,
        ),
        ListTile(
          leading: const Icon(Icons.manage_search_outlined),
          title: Text(l10n.securityActivity),
          subtitle: Text(l10n.securityActivityDescription),
          trailing: const Icon(Icons.chevron_right),
          onTap: _busy
              ? null
              : () => Navigator.push(
                  context,
                  MaterialPageRoute<void>(
                    builder: (_) => const SecurityActivityPage(),
                  ),
                ),
        ),
        const Divider(height: 24),
        for (final device in devices)
          _DeviceTile(
            device: device,
            onRevoke: _busy ? null : () => _revoke(device),
          ),
        const Divider(height: 32),
        ListTile(
          leading: const Icon(Icons.logout),
          title: Text(l10n.signOutEverywhere),
          subtitle: Text(l10n.signOutEverywhereDescriptionShort),
          onTap: _busy ? null : _signOutEverywhere,
        ),
        const Divider(),
        ListTile(
          leading: Icon(Icons.person_remove_outlined, color: colours.error),
          title: Text(
            l10n.deleteSyncAccount,
            style: TextStyle(color: colours.error),
          ),
          // The clarification belongs here, not only in the dialog. Someone
          // deciding whether to tap needs to know it will not take their codes.
          subtitle: Text(l10n.deleteSyncAccountDescription),
          onTap: _busy ? null : _deleteAccount,
        ),
        const SizedBox(height: 24),
      ],
    );
  }
}

class _StepUpPasswordDialog extends StatefulWidget {
  const _StepUpPasswordDialog({required this.action});

  final String action;

  @override
  State<_StepUpPasswordDialog> createState() => _StepUpPasswordDialogState();
}

class _RecoveryEnrollmentDialog extends StatefulWidget {
  const _RecoveryEnrollmentDialog();

  @override
  State<_RecoveryEnrollmentDialog> createState() =>
      _RecoveryEnrollmentDialogState();
}

class _RecoveryEnrollmentDialogState extends State<_RecoveryEnrollmentDialog> {
  final _password = TextEditingController();
  final _recovery = TextEditingController();

  @override
  void dispose() {
    _password.dispose();
    _recovery.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      icon: const Icon(Icons.key_outlined),
      title: Text(l10n.enableRecoverySignIn),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l10n.enableRecoverySignInHelp),
            const SizedBox(height: 16),
            TextField(
              controller: _password,
              obscureText: true,
              decoration: InputDecoration(labelText: l10n.accountPassword),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _recovery,
              obscureText: true,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: l10n.recoveryPhraseRequired,
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () =>
              Navigator.pop(context, (_password.text, _recovery.text.trim())),
          child: Text(l10n.enable),
        ),
      ],
    );
  }
}

class _StepUpPasswordDialogState extends State<_StepUpPasswordDialog> {
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
        decoration: InputDecoration(
          labelText: l10n.accountPassword,
          helperText: l10n.passwordRequiredForSecurityAction,
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

class _DeviceTile extends StatelessWidget {
  const _DeviceTile({required this.device, required this.onRevoke});

  final rust.DeviceView device;
  final VoidCallback? onRevoke;

  IconData get _icon => switch (device.platform.toLowerCase()) {
    'android' || 'ios' => Icons.smartphone,
    'windows' || 'linux' || 'macos' => Icons.computer,
    _ => Icons.devices_other,
  };

  /// "3 days ago" rather than a timestamp.
  ///
  /// Someone scanning this list is asking "is that the phone I lost last
  /// Tuesday", and a relative age answers it without arithmetic. Beyond a
  /// month the date itself is more useful than "37 days ago".
  String _lastSeen(AppLocalizations l10n) {
    final raw = device.lastSeen;
    if (raw == null) return l10n.neverSynced;

    final at = DateTime.tryParse(raw);
    if (at == null) return l10n.lastSyncedAt(raw);

    final ago = DateTime.now().difference(at.toLocal());
    if (ago.isNegative || ago.inMinutes < 2) return l10n.activeNow;
    if (ago.inHours < 1) return l10n.minutesAgo(ago.inMinutes);
    if (ago.inHours < 24) {
      return l10n.hoursAgo(ago.inHours);
    }
    if (ago.inDays < 30) {
      return l10n.daysAgo(ago.inDays);
    }
    final local = at.toLocal();
    return '${local.year}-${local.month.toString().padLeft(2, '0')}-'
        '${local.day.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return ListTile(
      leading: Icon(_icon, color: device.revoked ? colours.outline : null),
      title: Row(
        children: [
          Flexible(
            child: Text(
              device.name,
              overflow: TextOverflow.ellipsis,
              style: device.revoked
                  ? TextStyle(
                      color: colours.outline,
                      decoration: TextDecoration.lineThrough,
                    )
                  : null,
            ),
          ),
          if (device.current) ...[
            const SizedBox(width: 8),
            _Badge(text: l10n.thisDevice, colour: colours.primary),
          ],
        ],
      ),
      subtitle: Text(device.revoked ? l10n.removed : _lastSeen(l10n)),
      // A removed device keeps its row — someone checking that the lost phone
      // is really cut off needs to see it listed as cut off. A list that has
      // simply stopped mentioning it proves nothing.
      trailing: device.revoked
          ? null
          : IconButton(
              icon: const Icon(Icons.close),
              tooltip: device.current ? l10n.signOut : l10n.removeThisDevice,
              onPressed: onRevoke,
            ),
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge({required this.text, required this.colour});

  final String text;
  final Color colour;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        border: Border.all(color: colour),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(text, style: TextStyle(fontSize: 11, color: colour)),
    );
  }
}

/// Re-authentication before deleting the account (§9.5).
///
/// The password, not a confirmation box. A stolen access token is exactly the
/// situation the rest of this screen exists for, and whoever holds one must not
/// be able to destroy the account its owner is trying to save.
class _DeleteAccountDialog extends StatefulWidget {
  const _DeleteAccountDialog();

  @override
  State<_DeleteAccountDialog> createState() => _DeleteAccountDialogState();
}

class _DeleteAccountDialogState extends State<_DeleteAccountDialog> {
  final _password = TextEditingController();

  @override
  void dispose() {
    _password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return AlertDialog(
      icon: Icon(Icons.warning_amber_outlined, color: colours.error),
      title: Text(l10n.deleteSyncAccountQuestion),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l10n.deleteSyncAccountWarning),
            const SizedBox(height: 12),
            Text(l10n.deleteSyncAccountKeepsCodes),
            const SizedBox(height: 16),
            TextField(
              controller: _password,
              obscureText: true,
              autofocus: true,
              onSubmitted: (value) => Navigator.pop(context, value),
              decoration: InputDecoration(
                labelText: l10n.accountPassword,
                border: const OutlineInputBorder(),
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          style: FilledButton.styleFrom(backgroundColor: colours.error),
          onPressed: () => Navigator.pop(context, _password.text),
          child: Text(l10n.deleteAccount),
        ),
      ],
    );
  }
}
