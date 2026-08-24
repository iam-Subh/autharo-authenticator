import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../vault_controller.dart';

class DuplicateManagerPage extends StatefulWidget {
  const DuplicateManagerPage({super.key, required this.controller});

  final VaultController controller;

  @override
  State<DuplicateManagerPage> createState() => _DuplicateManagerPageState();
}

class _DuplicateManagerPageState extends State<DuplicateManagerPage> {
  List<List<rust.EntryView>> _groups = const [];
  Object? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      await widget.controller.refresh();
      final idGroups = await widget.controller.findDuplicateGroups();
      final byId = {
        for (final entry in widget.controller.entries) entry.id: entry,
      };
      final groups = idGroups
          .map(
            (ids) =>
                ids.map((id) => byId[id]).whereType<rust.EntryView>().toList(),
          )
          .where((group) => group.length > 1)
          .toList();
      if (!mounted) return;
      setState(() {
        _groups = groups;
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

  Future<void> _remove(rust.EntryView entry) async {
    try {
      await widget.controller.delete(entry.id);
      await _load();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(AppLocalizations.of(context).duplicateMovedToTrash),
          action: SnackBarAction(
            label: AppLocalizations.of(context).undo,
            onPressed: () async {
              await widget.controller.restore(entry.id);
              await _load();
            },
          ),
        ),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.toString())));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(AppLocalizations.of(context).duplicateAccounts),
      ),
      body: switch ((_loading, _error, _groups.isEmpty)) {
        (true, _, _) => const Center(child: CircularProgressIndicator()),
        (false, final error?, _) => Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text(error.toString(), textAlign: TextAlign.center),
          ),
        ),
        (false, null, true) => Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Text(AppLocalizations.of(context).noDuplicateSecrets),
          ),
        ),
        _ => ListView.builder(
          padding: const EdgeInsets.all(12),
          itemCount: _groups.length,
          itemBuilder: (context, groupIndex) {
            final group = _groups[groupIndex];
            return Card(
              margin: const EdgeInsets.only(bottom: 12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                    child: Text(
                      AppLocalizations.of(context).sameSecretDescription,
                    ),
                  ),
                  for (final entry in group)
                    ListTile(
                      title: Text(entry.issuer ?? entry.account),
                      subtitle: entry.issuer == null
                          ? null
                          : Text(entry.account),
                      trailing: TextButton(
                        onPressed: () => _remove(entry),
                        child: Text(AppLocalizations.of(context).moveToTrash),
                      ),
                    ),
                ],
              ),
            );
          },
        ),
      },
    );
  }
}
