import 'package:flutter/material.dart';

import '../rust/api/vault.dart' as rust;
import '../services/clipboard_service.dart';
import '../ui/code_display.dart';
import '../ui/countdown_ring.dart';
import '../services/lock_controller.dart';
import '../services/vault_session.dart';
import '../vault_controller.dart';
import 'manual_entry_page.dart';
import 'scan_page.dart';
import 'settings_page.dart';

/// The code list (FR-07, FR-21, FR-22, FR-24).
class EntryListPage extends StatefulWidget {
  const EntryListPage({
    super.key,
    required this.controller,
    this.session,
    this.lock,
  });

  final VaultController controller;

  /// Both null in tests that drive the list on its own. The settings action is
  /// hidden rather than broken when they are, since a settings screen with no
  /// vault behind it could not do anything anyway.
  final VaultSession? session;
  final LockController? lock;

  @override
  State<EntryListPage> createState() => _EntryListPageState();
}

class _EntryListPageState extends State<EntryListPage> {
  final _clipboard = ClipboardService();
  final _searchField = TextEditingController();
  String _query = '';

  @override
  void initState() {
    super.initState();
    _searchField.addListener(() {
      if (_query != _searchField.text) {
        setState(() => _query = _searchField.text);
      }
    });
  }

  @override
  void dispose() {
    _clipboard.dispose();
    _searchField.dispose();
    super.dispose();
  }

  Future<void> _copy(rust.EntryView entry) async {
    await _clipboard.copyCode(entry.code);
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(
        const SnackBar(
          content: Text('Code copied. The clipboard clears in 30 seconds.'),
          duration: Duration(seconds: 3),
        ),
      );
  }

  Future<void> _add(Future<String?> Function() source) async {
    final uri = await source();
    if (uri == null || !mounted) return;

    try {
      final outcome = await widget.controller.addFromUri(uri);
      if (!mounted) return;

      // FR-16: a duplicate is not an error. Say which entry already holds it.
      if (outcome.duplicateOf != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('That account is already in your list.'),
          ),
        );
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Account added.')),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(_message(error))),
      );
    }
  }

  /// The core's errors are written for the user, so they are shown as-is rather
  /// than replaced with a generic failure message.
  static String _message(Object error) {
    final text = error.toString();
    return text.startsWith('Exception: ')
        ? text.substring('Exception: '.length)
        : text;
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.controller,
      builder: (context, _) {
        final entries = widget.controller.search(_query);

        return Scaffold(
          appBar: AppBar(
            title: const Text('Authenticator'),
            actions: [
              if (widget.session != null && widget.lock != null)
                IconButton(
                  icon: const Icon(Icons.settings_outlined),
                  tooltip: 'Settings',
                  onPressed: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => SettingsPage(
                        session: widget.session!,
                        lock: widget.lock!,
                      ),
                    ),
                  ),
                ),
            ],
            bottom: PreferredSize(
              preferredSize: const Size.fromHeight(56),
              child: Padding(
                padding: const EdgeInsets.fromLTRB(12, 0, 12, 8),
                child: SearchBar(
                  controller: _searchField,
                  hintText: 'Search issuer or account',
                  leading: const Icon(Icons.search),
                  padding: const WidgetStatePropertyAll(
                    EdgeInsets.symmetric(horizontal: 12),
                  ),
                ),
              ),
            ),
          ),
          body: _body(entries),
          floatingActionButton: FloatingActionButton.extended(
            onPressed: _showAddSheet,
            icon: const Icon(Icons.add),
            label: const Text('Add'),
          ),
        );
      },
    );
  }

  Widget _body(List<rust.EntryView> entries) {
    final controller = widget.controller;

    if (controller.loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (controller.error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(_message(controller.error!)),
        ),
      );
    }

    return Column(
      children: [
        // FR-40: the offset is large and could not be corrected.
        if (controller.isClockDrifting)
          MaterialBanner(
            leading: const Icon(Icons.schedule),
            content: Text(
              'This device\'s clock is off by about '
              '${controller.time.offsetSeconds.abs()} seconds. Codes may be '
              'rejected until it is corrected.',
            ),
            actions: const [SizedBox.shrink()],
          ),
        Expanded(
          child: entries.isEmpty ? _empty() : _list(entries),
        ),
      ],
    );
  }

  Widget _empty() {
    final searching = _query.trim().isNotEmpty;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              searching ? Icons.search_off : Icons.shield_outlined,
              size: 48,
              color: Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(height: 16),
            Text(
              searching
                  ? 'No entry matches that search.'
                  : 'No accounts yet.',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            if (!searching) ...[
              const SizedBox(height: 8),
              const Text(
                'Add one by scanning the QR code a service shows you, or by '
                'entering its setup key by hand.',
                textAlign: TextAlign.center,
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _list(List<rust.EntryView> entries) {
    return ListView.separated(
      // NFR-02: a builder rather than a materialised list, so 500 entries cost
      // only what is on screen.
      itemCount: entries.length,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (context, index) {
        final entry = entries[index];
        return _EntryTile(
          entry: entry,
          onCopy: () => _copy(entry),
          onAdvance: entry.kind == 'hotp'
              ? () => widget.controller.advanceHotp(entry.id)
              : null,
          onDelete: () => _confirmDelete(entry),
          onToggleFavourite: () =>
              widget.controller.setFavourite(entry.id, !entry.favourite),
        );
      },
    );
  }

  /// FR-18: "Ask for confirmation. Warn that deletion removes the entry from
  /// all devices."
  Future<void> _confirmDelete(rust.EntryView entry) async {
    final label = entry.issuer == null
        ? entry.account
        : '${entry.issuer} (${entry.account})';

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Delete $label?'),
        content: const Text(
          'This removes the entry from every device on this account. If you '
          'have not turned off two-factor authentication with the service '
          'first, you will lose access to it.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Keep'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) await widget.controller.delete(entry.id);
  }

  void _showAddSheet() {
    showModalBottomSheet<void>(
      context: context,
      builder: (sheetContext) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.qr_code_scanner),
              title: const Text('Scan a QR code'),
              onTap: () {
                Navigator.pop(sheetContext);
                _add(
                  () => Navigator.of(context).push<String>(
                    MaterialPageRoute(builder: (_) => const ScanPage()),
                  ),
                );
              },
            ),
            ListTile(
              leading: const Icon(Icons.keyboard),
              title: const Text('Enter a setup key'),
              onTap: () {
                Navigator.pop(sheetContext);
                _add(
                  () => Navigator.of(context).push<String>(
                    MaterialPageRoute(
                      builder: (_) => const ManualEntryPage(),
                    ),
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _EntryTile extends StatelessWidget {
  const _EntryTile({
    required this.entry,
    required this.onCopy,
    required this.onDelete,
    required this.onToggleFavourite,
    this.onAdvance,
  });

  final rust.EntryView entry;
  final VoidCallback onCopy;
  final VoidCallback onDelete;
  final VoidCallback onToggleFavourite;

  /// Present only for HOTP entries (FR-02).
  final VoidCallback? onAdvance;

  bool get _expiring =>
      entry.kind == 'totp' &&
      entry.remainingSeconds <= CountdownRing.warningThresholdSeconds;

  @override
  Widget build(BuildContext context) {
    final title = entry.issuer ?? entry.account;
    final subtitle = entry.issuer == null ? null : entry.account;

    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      title: Row(
        children: [
          if (entry.favourite) ...[
            const Icon(Icons.star, size: 16),
            const SizedBox(width: 4),
          ],
          Expanded(child: Text(title, overflow: TextOverflow.ellipsis)),
        ],
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (subtitle != null)
            Text(subtitle, overflow: TextOverflow.ellipsis),
          const SizedBox(height: 6),
          CodeDisplay(code: entry.code, expiring: _expiring),
        ],
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (entry.kind == 'totp')
            CountdownRing(
              remainingSeconds: entry.remainingSeconds,
              period: entry.period,
            )
          else
            IconButton(
              tooltip: 'Next code',
              icon: const Icon(Icons.refresh),
              onPressed: onAdvance,
            ),
          PopupMenuButton<String>(
            onSelected: (value) => switch (value) {
              'favourite' => onToggleFavourite(),
              'delete' => onDelete(),
              _ => null,
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                value: 'favourite',
                child: Text(
                  entry.favourite ? 'Remove from favourites' : 'Add to favourites',
                ),
              ),
              const PopupMenuItem(value: 'delete', child: Text('Delete')),
            ],
          ),
        ],
      ),
      // FR-24: "Copy a code to the clipboard with one action."
      onTap: onCopy,
    );
  }
}
