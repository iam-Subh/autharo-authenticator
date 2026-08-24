import 'dart:async';

import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/sync.dart' as rust;
import '../services/sync_controller.dart';
import 'sync_sign_in_page.dart';

/// **Settings → Sync**: where a device is joined to an account, and where
/// OFF-05's status is shown in full.
///
/// Sync is optional (OFF-04), so nothing here nags a local-only user. The page
/// explains what turning it on would do and otherwise stays out of the way.
class SyncPage extends StatefulWidget {
  const SyncPage({super.key, required this.controller});

  final SyncController controller;

  @override
  State<SyncPage> createState() => _SyncPageState();
}

class _SyncPageState extends State<SyncPage> {
  int? _deviceCount;
  Object? _deviceCountError;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onChanged);
    unawaited(_refreshDashboard());
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onChanged);
    super.dispose();
  }

  void _onChanged() {
    if (mounted) setState(() {});
  }

  Future<void> _refreshDashboard() async {
    await widget.controller.refresh();
    if (!widget.controller.status.isSignedIn) {
      if (mounted) {
        setState(() {
          _deviceCount = null;
          _deviceCountError = null;
        });
      }
      return;
    }
    try {
      final devices = await rust.listDevices();
      if (!mounted) return;
      setState(() {
        _deviceCount = devices.where((device) => !device.revoked).length;
        _deviceCountError = null;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() => _deviceCountError = error);
    }
  }

  Future<void> _open(Widget page) async {
    await Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => page));
    await _refreshDashboard();
  }

  Future<void> _syncNow() async {
    final problem = await widget.controller.syncNow();
    await _refreshDashboard();
    if (!mounted || problem == null) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(problem)));
  }

  Future<void> _signOut() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).signOutOfSyncQuestion),
        // Says what it does *not* do. Users read "sign out" next to a vault
        // and reasonably fear losing the vault.
        content: Text(AppLocalizations.of(context).signOutOfSyncDescription),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(AppLocalizations.of(context).signOut),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    await rust.signOut();
    await _refreshDashboard();
  }

  @override
  Widget build(BuildContext context) {
    final status = widget.controller.status;
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.sync)),
      body: ListView(
        children: [
          _StatusTile(status: status),
          if (status.isConfigured)
            _SyncDashboard(
              status: status,
              deviceCount: _deviceCount,
              deviceCountError: _deviceCountError,
              busy: widget.controller.busy,
              onRetry: _syncNow,
            ),
          const Divider(),

          if (!status.isSignedIn) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: Text(l10n.syncEncryptionDescription),
            ),
            ListTile(
              leading: const Icon(Icons.cloud_upload_outlined),
              title: Text(l10n.turnOnSync),
              subtitle: Text(l10n.turnOnSyncDescription),
              onTap: () => _open(
                SyncSignInPage(
                  controller: widget.controller,
                  mode: SignInMode.register,
                ),
              ),
            ),
            ListTile(
              leading: const Icon(Icons.login_outlined),
              title: Text(l10n.signInExistingAccount),
              subtitle: Text(l10n.signInExistingAccountDescription),
              onTap: () => _open(
                SyncSignInPage(
                  controller: widget.controller,
                  mode: SignInMode.signIn,
                ),
              ),
            ),
          ] else ...[
            ListTile(
              leading: const Icon(Icons.account_circle_outlined),
              title: Text(l10n.account),
              subtitle: Text(status.email ?? l10n.unknown),
            ),
            ListTile(
              leading: const Icon(Icons.dns_outlined),
              title: Text(l10n.server),
              subtitle: Text(status.serverUrl ?? l10n.notSet),
            ),
            ListTile(
              leading: widget.controller.busy
                  ? const SizedBox(
                      width: 24,
                      height: 24,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.sync),
              title: Text(l10n.syncNow),
              onTap: widget.controller.busy ? null : _syncNow,
            ),
            const Divider(),
            ListTile(
              leading: const Icon(Icons.logout_outlined),
              title: Text(l10n.signOutOfSync),
              subtitle: Text(l10n.codesStayOnDevice),
              onTap: widget.controller.busy ? null : _signOut,
            ),
          ],
        ],
      ),
    );
  }
}

class _SyncDashboard extends StatelessWidget {
  const _SyncDashboard({
    required this.status,
    required this.deviceCount,
    required this.deviceCountError,
    required this.busy,
    required this.onRetry,
  });

  final SyncStatus status;
  final int? deviceCount;
  final Object? deviceCountError;
  final bool busy;
  final VoidCallback onRetry;

  String _lastSync(AppLocalizations l10n) {
    final value = status.lastSuccess;
    if (value == null) return l10n.noCompletedSync;
    final local = value.toLocal();
    final hour = local.hour.toString().padLeft(2, '0');
    final minute = local.minute.toString().padLeft(2, '0');
    return '${local.year}-${local.month.toString().padLeft(2, '0')}-'
        '${local.day.toString().padLeft(2, '0')} $hour:$minute';
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final pending = status.pendingKnown
        ? '${status.pending}'
        : l10n.unknownWhileLocked;
    final devices = deviceCountError != null
        ? l10n.couldNotLoad
        : deviceCount?.toString() ?? l10n.loading;

    return Card(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              l10n.synchronizationStatus,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 12),
            _DashboardRow(label: l10n.lastSync, value: _lastSync(l10n)),
            _DashboardRow(label: l10n.pendingChanges, value: pending),
            _DashboardRow(label: l10n.activeDevices, value: devices),
            _DashboardRow(
              label: l10n.server,
              value: status.serverUrl ?? l10n.notConfigured,
            ),
            if (status.lastError != null) ...[
              const SizedBox(height: 8),
              Text(
                status.lastError!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
            if (status.state == SyncState.offline) ...[
              const SizedBox(height: 12),
              FilledButton.tonalIcon(
                onPressed: busy ? null : onRetry,
                icon: const Icon(Icons.refresh),
                label: Text(l10n.retry),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _DashboardRow extends StatelessWidget {
  const _DashboardRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 116,
            child: Text(
              label,
              style: TextStyle(color: Theme.of(context).colorScheme.outline),
            ),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }
}

/// OFF-05: three states, and the time of the last successful sync.
class _StatusTile extends StatelessWidget {
  const _StatusTile({required this.status});

  final SyncStatus status;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    final (IconData icon, Color colour) = switch (status.state) {
      SyncState.off => (Icons.cloud_off_outlined, scheme.outline),
      SyncState.synced => (Icons.cloud_done_outlined, scheme.primary),
      SyncState.pending => (Icons.cloud_upload_outlined, scheme.primary),
      SyncState.offline => (Icons.cloud_off_outlined, scheme.outline),
      SyncState.signedOut => (Icons.error_outline, scheme.error),
    };

    return ListTile(
      leading: Icon(icon, color: colour),
      title: Text(switch (status.state) {
        SyncState.off => l10n.syncIsOff,
        SyncState.synced => l10n.synced,
        SyncState.pending =>
          status.pendingKnown
              ? l10n.changesWaiting(status.pending)
              : l10n.changesWaitingUnknown,
        SyncState.offline => l10n.offline,
        SyncState.signedOut => l10n.syncSessionExpired,
      }),
      // The reason, not just the state. "Not connected" alone leaves the user
      // guessing whether it is their network, the server, or the app.
      subtitle: status.lastError == null ? null : Text(status.lastError!),
    );
  }
}
