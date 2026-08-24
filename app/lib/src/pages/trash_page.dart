import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../vault_controller.dart';

class TrashPage extends StatefulWidget {
  const TrashPage({super.key, required this.controller});

  final VaultController controller;

  @override
  State<TrashPage> createState() => _TrashPageState();
}

class _TrashPageState extends State<TrashPage> {
  List<rust.TrashEntryView> _entries = const [];
  Object? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      await widget.controller.purgeExpiredTrash();
      final entries = await widget.controller.listTrash();
      if (!mounted) return;
      setState(() {
        _entries = entries;
        _error = null;
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error;
        _loading = false;
      });
    }
  }

  Future<void> _restore(rust.TrashEntryView entry) async {
    try {
      await widget.controller.restore(entry.id);
      await _load();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(AppLocalizations.of(context).entryRestored)),
      );
    } catch (error) {
      _showError(error);
    }
  }

  Future<void> _deletePermanently(rust.TrashEntryView entry) async {
    final label = entry.issuer == null
        ? entry.account
        : '${entry.issuer} (${entry.account})';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          AppLocalizations.of(context).deletePermanentlyQuestion(label),
        ),
        content: Text(
          AppLocalizations.of(context).deletePermanentlyDescription,
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
            child: Text(AppLocalizations.of(context).deletePermanently),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    try {
      await widget.controller.permanentlyDelete(entry.id);
      await _load();
    } catch (error) {
      _showError(error);
    }
  }

  void _showError(Object error) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(error.toString())));
  }

  String _retentionText(rust.TrashEntryView entry) {
    final remaining = DateTime.fromMillisecondsSinceEpoch(
      entry.purgeAt.toInt(),
    ).difference(DateTime.now());
    final l10n = AppLocalizations.of(context);
    if (remaining <= Duration.zero) return l10n.pendingPermanentDeletion;
    final days = (remaining.inHours / 24).ceil();
    return days == 1
        ? l10n.permanentlyDeletedInOneDay
        : l10n.permanentlyDeletedInDays(days);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(AppLocalizations.of(context).trash)),
      body: switch ((_loading, _error, _entries.isEmpty)) {
        (true, _, _) => const Center(child: CircularProgressIndicator()),
        (false, final error?, _) => Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(error.toString(), textAlign: TextAlign.center),
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: _load,
                  child: Text(AppLocalizations.of(context).tryAgain),
                ),
              ],
            ),
          ),
        ),
        (false, null, true) => Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Text(AppLocalizations.of(context).trashEmpty),
          ),
        ),
        _ => ListView.separated(
          itemCount: _entries.length,
          separatorBuilder: (_, _) => const Divider(height: 1),
          itemBuilder: (context, index) {
            final entry = _entries[index];
            return ListTile(
              leading: const Icon(Icons.delete_outline),
              title: Text(entry.issuer ?? entry.account),
              subtitle: Text(
                entry.issuer == null
                    ? _retentionText(entry)
                    : '${entry.account}\n${_retentionText(entry)}',
              ),
              isThreeLine: entry.issuer != null,
              trailing: PopupMenuButton<String>(
                onSelected: (value) {
                  if (value == 'restore') _restore(entry);
                  if (value == 'delete') _deletePermanently(entry);
                },
                itemBuilder: (context) => [
                  PopupMenuItem(
                    value: 'restore',
                    child: Text(AppLocalizations.of(context).restore),
                  ),
                  PopupMenuItem(
                    value: 'delete',
                    child: Text(AppLocalizations.of(context).deletePermanently),
                  ),
                ],
              ),
              onTap: () => _restore(entry),
            );
          },
        ),
      },
    );
  }
}
