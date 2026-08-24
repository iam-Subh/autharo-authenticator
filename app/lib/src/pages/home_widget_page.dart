import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../services/home_widget_service.dart';
import '../vault_controller.dart';

class HomeWidgetPage extends StatefulWidget {
  const HomeWidgetPage({super.key, required this.controller});

  final VaultController controller;

  @override
  State<HomeWidgetPage> createState() => _HomeWidgetPageState();
}

class _HomeWidgetPageState extends State<HomeWidgetPage> {
  final _service = HomeWidgetService();
  HomeWidgetStatus? _status;
  bool _busy = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final status = await _service.status();
      if (!mounted) return;
      setState(() {
        _status = status;
        _error = null;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() => _error = error);
    }
  }

  String _title(rust.EntryView entry) {
    final issuer = entry.issuer?.trim();
    if (issuer == null || issuer.isEmpty) return entry.account;
    return '$issuer — ${entry.account}';
  }

  Future<rust.EntryView?> _chooseEntry() {
    return showModalBottomSheet<rust.EntryView>(
      context: context,
      showDragHandle: true,
      builder: (context) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            ListTile(
              title: Text(AppLocalizations.of(context).selectWidgetAccount),
            ),
            for (final entry in widget.controller.entries)
              ListTile(
                leading: const Icon(Icons.key_outlined),
                title: Text(
                  entry.issuer?.trim().isNotEmpty == true
                      ? entry.issuer!.trim()
                      : entry.account,
                ),
                subtitle: entry.issuer?.trim().isNotEmpty == true
                    ? Text(entry.account)
                    : null,
                onTap: () => Navigator.pop(context, entry),
              ),
          ],
        ),
      ),
    );
  }

  Future<void> _enableOrChange() async {
    final entry = await _chooseEntry();
    if (entry == null || !mounted) return;
    setState(() => _busy = true);
    try {
      await _service.configure(
        enabled: true,
        entryId: entry.id,
        title: _title(entry),
      );
      await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _disable() async {
    setState(() => _busy = true);
    try {
      await _service.configure(enabled: false);
      await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final status = _status;
    final l10n = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.homeScreenWidget)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Icon(Icons.widgets_outlined, size: 52),
          const SizedBox(height: 16),
          Text(
            l10n.quickAccessNoExposedCodes,
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 8),
          Text(l10n.widgetDescription),
          const SizedBox(height: 24),
          if (_error != null)
            Text(
              l10n.widgetSettingReadFailed('$_error'),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            )
          else if (status == null)
            const Center(child: CircularProgressIndicator())
          else ...[
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                status.enabled ? Icons.widgets : Icons.widgets_outlined,
              ),
              title: Text(
                status.enabled ? l10n.widgetEnabled : l10n.widgetDisabled,
              ),
              subtitle: status.enabled && status.title != null
                  ? Text(status.title!)
                  : Text(l10n.noWidgetAccount),
            ),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: _busy || widget.controller.entries.isEmpty
                  ? null
                  : _enableOrChange,
              child: Text(
                status.enabled ? l10n.changeAccount : l10n.selectAccount,
              ),
            ),
            if (status.enabled)
              TextButton(
                onPressed: _busy ? null : _disable,
                child: Text(l10n.disableWidget),
              ),
            if (widget.controller.entries.isEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Text(l10n.addAccountBeforeWidget),
              ),
          ],
          const SizedBox(height: 24),
          Text(l10n.widgetLauncherInstructions),
        ],
      ),
    );
  }
}
