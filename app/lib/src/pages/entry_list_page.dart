import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../rust/api/share.dart' as share;
import '../services/appearance_preference.dart';
import '../services/clipboard_service.dart';
import '../services/code_visibility_preference.dart';
import 'edit_entry_page.dart';
import 'entry_qr_page.dart';
import 'import_help_page.dart';
import 'import_migration_page.dart';
import '../services/list_sort.dart';
import '../services/sync_controller.dart';
import '../ui/code_display.dart';
import '../ui/entry_avatar.dart';
import '../ui/folder_bar.dart';
import '../ui/countdown_ring.dart';
import '../services/lock_controller.dart';
import '../services/vault_session.dart';
import '../ui/import_file_flow.dart';
import '../ui/import_report_dialog.dart';
import '../vault_controller.dart';
import 'manual_entry_page.dart';
import 'scan_page.dart';
import 'settings_page.dart';
import 'share_entry_page.dart';

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
  // OFF-05. On the code list rather than buried in settings: a device that has
  // quietly stopped syncing looks exactly like one that is up to date, and the
  // user finds out when a code is missing on their other device.
  final _sync = SyncController();
  final _searchField = TextEditingController();

  /// FR-19: null is "All", `FolderBar.unfiledSentinel` is "Unfiled".
  String? _folder;
  String _query = '';
  final Set<String> _selectedIds = {};
  final Set<String> _revealedCodeIds = {};
  String? _detailEntryId;

  bool get _usesTwoPane => MediaQuery.sizeOf(context).width >= 900;

  @override
  void initState() {
    super.initState();
    _sync.addListener(() {
      if (mounted) setState(() {});
    });
    _sync.refresh();
    _searchField.addListener(() {
      if (_query != _searchField.text) {
        setState(() => _query = _searchField.text);
      }
    });
    CodeVisibilityPreference.hideCodesUntilTap.addListener(
      _onCodeVisibilityChanged,
    );
    AppearancePreference.listDensity.addListener(_onListDensityChanged);
  }

  void _onCodeVisibilityChanged() {
    if (CodeVisibilityPreference.hideCodesUntilTap.value) {
      _revealedCodeIds.clear();
    }
    if (mounted) setState(() {});
  }

  void _onListDensityChanged() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _clipboard.dispose();
    _searchField.dispose();
    CodeVisibilityPreference.hideCodesUntilTap.removeListener(
      _onCodeVisibilityChanged,
    );
    AppearancePreference.listDensity.removeListener(_onListDensityChanged);
    _sync.dispose();
    super.dispose();
  }

  Future<void> _copy(rust.EntryView entry) async {
    await _clipboard.copyCode(entry.code);
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(
        SnackBar(
          content: Text(AppLocalizations.of(context).codeCopied),
          duration: const Duration(seconds: 3),
        ),
      );
  }

  Future<void> _add(Future<String?> Function() source) async {
    final uri = await source();
    if (uri == null || !mounted) return;

    // FR-14: an export code opens the batch importer instead of being added
    // as one entry — it is not one, and adding it would fail with a message
    // about an unreadable URI.
    if (uri.toLowerCase().startsWith('otpauth-migration://')) {
      await Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (_) => ImportMigrationPage(
            controller: widget.controller,
            firstCode: uri,
          ),
        ),
      );
      return;
    }

    try {
      final outcome = await widget.controller.addFromUri(uri);
      if (!mounted) return;

      // FR-16: "Reject a duplicate secret and offer to open the existing
      // entry."
      //
      // The offer is the half that was missing. Telling someone the account is
      // already there, in a list of forty, and leaving them to find it is a
      // refusal dressed as help — and the entry may be under a name they do
      // not recognise, which is often *why* they tried to add it again.
      if (outcome.duplicateOf != null) {
        _showExisting(outcome.duplicateOf!);
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(AppLocalizations.of(context).accountAdded)),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(_message(error))));
    }
  }

  Future<String?> _readSetupLinkFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final value = data?.text?.trim();
    if (value == null || value.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppLocalizations.of(context).clipboardHasNoText),
          ),
        );
      }
      return null;
    }

    final lower = value.toLowerCase();
    if (!lower.startsWith('otpauth://') &&
        !lower.startsWith('otpauth-migration://')) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppLocalizations.of(context).clipboardHasNoSetupLink),
          ),
        );
      }
      return null;
    }

    return value;
  }

  /// The core's errors are written for the user, so they are shown as-is rather
  /// than replaced with a generic failure message.
  static String _message(Object error) {
    final text = error.toString();
    return text.startsWith('Exception: ')
        ? text.substring('Exception: '.length)
        : text;
  }

  void _toggleSelection(String id) {
    setState(() {
      if (!_selectedIds.add(id)) _selectedIds.remove(id);
    });
  }

  void _clearSelection() => setState(_selectedIds.clear);

  Future<void> _moveSelectionToFolder() async {
    final chosen = await showModalBottomSheet<_FolderChoice>(
      context: context,
      builder: (_) =>
          _FolderSheet(folders: widget.controller.folders, current: null),
    );
    if (chosen == null || !mounted) return;

    try {
      String? folderId = chosen.folderId;
      if (chosen.createNamed != null) {
        folderId = await widget.controller.createFolder(chosen.createNamed!);
      }
      await widget.controller.setFolderMany(_selectedIds, folderId);
      if (mounted) _clearSelection();
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(_message(error))));
      }
    }
  }

  Future<void> _toggleSelectionFavourite() async {
    final selected = widget.controller.entries
        .where((entry) => _selectedIds.contains(entry.id))
        .toList();
    final favourite = !selected.every((entry) => entry.favourite);
    try {
      await widget.controller.setFavouriteMany(_selectedIds, favourite);
      if (mounted) _clearSelection();
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(_message(error))));
      }
    }
  }

  Future<void> _deleteSelection() async {
    final count = _selectedIds.length;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).moveEntriesToTrash(count)),
        content: Text(
          AppLocalizations.of(context).moveEntriesToTrashDescription,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(AppLocalizations.of(context).moveToTrash),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    final deleted = Set<String>.from(_selectedIds);
    try {
      await widget.controller.deleteMany(deleted);
      if (!mounted) return;
      _clearSelection();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            AppLocalizations.of(context).entriesMovedToTrash(count),
          ),
          duration: const Duration(seconds: 6),
          action: SnackBarAction(
            label: AppLocalizations.of(context).undo,
            onPressed: () => widget.controller.restoreMany(deleted),
          ),
        ),
      );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(_message(error))));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.controller,
      builder: (context, _) {
        final entries = widget.controller.search(_query);
        final l10n = AppLocalizations.of(context);

        return Scaffold(
          appBar: AppBar(
            leading: _selectedIds.isEmpty
                ? null
                : IconButton(
                    tooltip: l10n.cancelSelection,
                    icon: const Icon(Icons.close),
                    onPressed: _clearSelection,
                  ),
            title: Text(
              _selectedIds.isEmpty
                  ? l10n.appTitle
                  : l10n.selectedCount(_selectedIds.length),
            ),
            actions: [
              if (_selectedIds.isNotEmpty) ...[
                IconButton(
                  tooltip: l10n.changeFavouriteStatus,
                  icon: const Icon(Icons.star_outline),
                  onPressed: _toggleSelectionFavourite,
                ),
                IconButton(
                  tooltip: l10n.moveToFolder,
                  icon: const Icon(Icons.drive_file_move_outline),
                  onPressed: _moveSelectionToFolder,
                ),
                IconButton(
                  tooltip: l10n.moveToTrash,
                  icon: const Icon(Icons.delete_outline),
                  onPressed: _deleteSelection,
                ),
              ] else ...[
                if (_sync.status.state != SyncState.off) _syncIndicator(),
                _sortMenu(),
              ],
              if (_selectedIds.isEmpty &&
                  widget.session != null &&
                  widget.lock != null)
                IconButton(
                  icon: const Icon(Icons.settings_outlined),
                  tooltip: l10n.settings,
                  onPressed: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => SettingsPage(
                        session: widget.session!,
                        lock: widget.lock!,
                        controller: widget.controller,
                      ),
                    ),
                  ),
                ),
            ],
            bottom: _selectedIds.isEmpty
                ? PreferredSize(
                    preferredSize: const Size.fromHeight(56),
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(12, 0, 12, 8),
                      child: SearchBar(
                        controller: _searchField,
                        hintText: l10n.searchAccountsNotesTags,
                        leading: const Icon(Icons.search),
                        padding: const WidgetStatePropertyAll(
                          EdgeInsets.symmetric(horizontal: 12),
                        ),
                      ),
                    ),
                  )
                : null,
          ),
          body: _body(entries),
          floatingActionButton: _selectedIds.isEmpty
              ? FloatingActionButton.extended(
                  onPressed: _showAddSheet,
                  icon: const Icon(Icons.add),
                  label: Text(AppLocalizations.of(context).add),
                )
              : null,
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

    final known = {for (final folder in controller.folders) folder.id};
    final filtered = applyFolderFilter(
      entries,
      selected: _folder,
      knownFolderIds: known,
    );

    // A filter that is selected and then emptied — the last code moved out, or
    // the folder deleted on another device — would otherwise leave the user
    // looking at an empty list with no obvious way back. Falling back to All is
    // less surprising than an empty screen.
    if (_folder != null && filtered.isEmpty && entries.isNotEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) setState(() => _folder = null);
      });
    }

    final accountPane = Column(
      children: [
        // FR-40: the offset is large and could not be corrected.
        if (controller.isClockDrifting)
          MaterialBanner(
            leading: const Icon(Icons.schedule),
            content: Text(
              AppLocalizations.of(
                context,
              ).clockOffsetWarning(controller.time.offsetSeconds.abs()),
            ),
            actions: const [SizedBox.shrink()],
          ),
        FolderBar(
          folders: controller.folders,
          selected: _folder,
          unfiledCount: countUnfiled(entries, knownFolderIds: known),
          onSelected: (value) => setState(() => _folder = value),
          onManage: _manageFolder,
        ),
        Expanded(child: filtered.isEmpty ? _empty() : _list(filtered)),
      ],
    );

    if (!_usesTwoPane) return accountPane;
    final detail = entries
        .where((entry) => entry.id == _detailEntryId)
        .firstOrNull;
    return Row(
      children: [
        SizedBox(width: 520, child: accountPane),
        const VerticalDivider(width: 1),
        Expanded(child: _tabletDetails(detail)),
      ],
    );
  }

  Widget _tabletDetails(rust.EntryView? entry) {
    if (entry == null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.touch_app_outlined, size: 48),
              const SizedBox(height: 16),
              Text(AppLocalizations.of(context).selectAccountForDetails),
            ],
          ),
        ),
      );
    }

    final hidden =
        CodeVisibilityPreference.hideCodesUntilTap.value &&
        !_revealedCodeIds.contains(entry.id);
    return ListView(
      padding: const EdgeInsets.all(32),
      children: [
        Row(
          children: [
            EntryAvatar(
              issuer: entry.issuer,
              account: entry.account,
              icon: entry.icon,
              size: 64,
            ),
            const SizedBox(width: 20),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    entry.issuer ?? entry.account,
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  if (entry.issuer != null) Text(entry.account),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 32),
        Center(
          child: CodeDisplay(
            code: entry.code,
            hidden: hidden,
            expiring:
                entry.kind != 'hotp' &&
                entry.remainingSeconds <= CountdownRing.warningThresholdSeconds,
          ),
        ),
        const SizedBox(height: 12),
        if (hidden)
          FilledButton.tonalIcon(
            onPressed: () => setState(() => _revealedCodeIds.add(entry.id)),
            icon: const Icon(Icons.visibility_outlined),
            label: Text(AppLocalizations.of(context).revealCode),
          )
        else
          FilledButton.icon(
            onPressed: () => _copy(entry),
            icon: const Icon(Icons.copy_outlined),
            label: Text(AppLocalizations.of(context).copyCode),
          ),
        if (entry.tags.isNotEmpty) ...[
          const SizedBox(height: 24),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [for (final tag in entry.tags) Chip(label: Text(tag))],
          ),
        ],
        if (entry.note.isNotEmpty) ...[
          const SizedBox(height: 24),
          Text(
            AppLocalizations.of(context).note,
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 6),
          Text(entry.note),
        ],
        const SizedBox(height: 32),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            _DetailAction(
              icon: Icons.edit_outlined,
              label: AppLocalizations.of(context).edit,
              onPressed: () => _edit(entry),
            ),
            _DetailAction(
              icon: Icons.folder_outlined,
              label: AppLocalizations.of(context).folder,
              onPressed: () => _moveToFolder(entry),
            ),
            _DetailAction(
              icon: Icons.qr_code_2_outlined,
              label: AppLocalizations.of(context).qrCode,
              onPressed: () => _showQr(entry),
            ),
            _DetailAction(
              icon: Icons.share_outlined,
              label: AppLocalizations.of(context).share,
              onPressed: () => _share(entry),
            ),
            _DetailAction(
              icon: Icons.delete_outline,
              label: AppLocalizations.of(context).delete,
              destructive: true,
              onPressed: () => _confirmDelete(entry),
            ),
          ],
        ),
      ],
    );
  }

  /// FR-19: renaming or removing a folder.
  Future<void> _manageFolder(rust.FolderView folder) async {
    final action = await showModalBottomSheet<String>(
      context: context,
      builder: (sheetContext) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              title: Text(folder.name),
              subtitle: Text(
                folder.count == 1 ? '1 account' : '${folder.count} accounts',
              ),
            ),
            const Divider(height: 1),
            ListTile(
              leading: const Icon(Icons.drive_file_rename_outline),
              title: Text(AppLocalizations.of(context).rename),
              onTap: () => Navigator.pop(sheetContext, 'rename'),
            ),
            ListTile(
              leading: const Icon(Icons.folder_delete_outlined),
              title: Text(AppLocalizations.of(context).deleteFolder),
              // Said on the button, not only in the confirmation. Someone who
              // taps expecting to lose their codes has already had the worse
              // moment by the time a dialog reassures them.
              subtitle: Text(AppLocalizations.of(context).folderAccountsKept),
              onTap: () => Navigator.pop(sheetContext, 'delete'),
            ),
          ],
        ),
      ),
    );
    if (action == null || !mounted) return;

    try {
      if (action == 'rename') {
        final name = await showDialog<String>(
          context: context,
          builder: (_) => _RenameFolderDialog(current: folder.name),
        );
        if (name == null || !mounted) return;
        await widget.controller.renameFolder(folder.id, name);
      } else {
        await widget.controller.deleteFolder(folder.id);
        if (mounted && _folder == folder.id) setState(() => _folder = null);
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(_message(error))));
      }
    }
  }

  /// FR-19: files one entry, offering to make a folder if there are none.
  Future<void> _moveToFolder(rust.EntryView entry) async {
    final controller = widget.controller;
    final chosen = await showModalBottomSheet<_FolderChoice>(
      context: context,
      builder: (_) =>
          _FolderSheet(folders: controller.folders, current: entry.folderId),
    );
    if (chosen == null || !mounted) return;

    try {
      if (chosen.createNamed != null) {
        final id = await controller.createFolder(chosen.createNamed!);
        await controller.setFolder(entry.id, id);
      } else {
        await controller.setFolder(entry.id, chosen.folderId);
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(_message(error))));
      }
    }
  }

  /// FR-17: opens the edit screen for one entry.
  Future<void> _edit(rust.EntryView entry) async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) =>
            EditEntryPage(controller: widget.controller, entry: entry),
      ),
    );
  }

  /// FR-16: points at the entry that already holds this secret.
  ///
  /// Searching for it rather than scrolling to an index: the entry may be off
  /// screen, in a collapsed group, or under a name the user does not recognise,
  /// and a search box filled in with its name both finds it and says what it is
  /// called.
  void _showExisting(String id) {
    final existing = widget.controller.entries
        .where((entry) => entry.id == id)
        .firstOrNull;

    if (existing == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(AppLocalizations.of(context).accountIsInTrash),
          action: SnackBarAction(
            label: AppLocalizations.of(context).restore,
            onPressed: () async {
              try {
                await widget.controller.restore(id);
              } catch (error) {
                if (mounted) {
                  ScaffoldMessenger.of(
                    context,
                  ).showSnackBar(SnackBar(content: Text(_message(error))));
                }
              }
            },
          ),
        ),
      );
      return;
    }

    final label = existing.issuer == null
        ? existing.account
        : '${existing.issuer} (${existing.account})';

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(AppLocalizations.of(context).alreadySavedAs(label)),
        duration: const Duration(seconds: 6),
        action: SnackBarAction(
          label: AppLocalizations.of(context).showIt,
          onPressed: () {
            // Filling the search box shows the entry and, on a long list,
            // shows it alone.
            _searchField.text = existing.account;
          },
        ),
      ),
    );
  }

  /// FR-22: the four orders, with the current one marked.
  ///
  /// A menu rather than a settings page. Sorting is something a user changes
  /// while looking at the list and changes back a moment later, and a choice
  /// that costs two screens to reach is a choice nobody makes twice.
  Widget _sortMenu() {
    // No `initialValue`. Setting it hangs every integration test in
    // `app_test.dart` — the whole file times out with "did not complete",
    // including tests that never open this menu, which reads like the
    // application crashing rather than like one widget property.
    //
    // It is not needed: the current mode is shown with a tick below, which is
    // better anyway. `initialValue` highlights the row, and a highlight is the
    // hover state on desktop and says nothing at all on a phone.
    return PopupMenuButton<SortMode>(
      icon: const Icon(Icons.sort),
      tooltip: AppLocalizations.of(context).sort,
      onSelected: (mode) async {
        if (mode == SortMode.manual) {
          await widget.controller.enableManualOrder();
        } else {
          await widget.controller.setSortMode(mode);
        }
        if (mounted) setState(() {});
      },
      itemBuilder: (context) => [
        for (final mode in SortMode.values)
          PopupMenuItem<SortMode>(
            value: mode,
            child: Row(
              children: [
                // A tick, not just a highlight: the highlight is the hover
                // state on desktop and says nothing on a phone.
                Icon(
                  mode == widget.controller.sortMode
                      ? Icons.check
                      : Icons.check_box_outline_blank,
                  size: 18,
                  color: mode == widget.controller.sortMode
                      ? Theme.of(context).colorScheme.primary
                      : Colors.transparent,
                ),
                const SizedBox(width: 12),
                Text(_sortLabel(mode)),
              ],
            ),
          ),
      ],
    );
  }

  String _sortLabel(SortMode mode) {
    final l10n = AppLocalizations.of(context);
    return switch (mode) {
      SortMode.name => l10n.nameSort,
      SortMode.issuer => l10n.issuerSort,
      SortMode.dateAdded => l10n.recentlyAddedSort,
      SortMode.manual => l10n.manualSort,
    };
  }

  String _localizedSyncSummary(SyncStatus status) {
    final l10n = AppLocalizations.of(context);
    return switch (status.state) {
      SyncState.off => l10n.syncIsOff,
      SyncState.synced => l10n.synced,
      SyncState.pending => l10n.pendingChanges,
      SyncState.offline => l10n.offline,
      SyncState.signedOut => l10n.syncSessionExpired,
    };
  }

  /// OFF-05's three states, compressed to one glyph with the detail on tap.
  ///
  /// Colour alone would fail NFR-08 and would be invisible to a colour-blind
  /// user, so the icon differs by shape as well, and the words are one tap
  /// away rather than absent.
  Widget _syncIndicator() {
    final status = _sync.status;
    final scheme = Theme.of(context).colorScheme;

    final (IconData icon, Color colour) = switch (status.state) {
      SyncState.off => (Icons.cloud_off_outlined, scheme.outline),
      SyncState.synced => (Icons.cloud_done_outlined, scheme.primary),
      SyncState.pending => (Icons.cloud_upload_outlined, scheme.primary),
      SyncState.offline => (Icons.cloud_off_outlined, scheme.outline),
      SyncState.signedOut => (Icons.error_outline, scheme.error),
    };

    final summary = _localizedSyncSummary(status);
    return IconButton(
      icon: Icon(icon, color: colour),
      tooltip: summary,
      onPressed: () {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(summary),
            action: _sync.busy
                ? null
                : SnackBarAction(
                    label: AppLocalizations.of(context).syncNow,
                    onPressed: () => _sync.syncNow(),
                  ),
          ),
        );
      },
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
                  ? AppLocalizations.of(context).noSearchResults
                  : AppLocalizations.of(context).noAccountsYet,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            if (!searching) ...[
              const SizedBox(height: 8),
              Text(
                AppLocalizations.of(context).emptyVaultDescription,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 20),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton.icon(
                    onPressed: () => _add(
                      () => Navigator.of(context).push<String>(
                        MaterialPageRoute(builder: (_) => const ScanPage()),
                      ),
                    ),
                    icon: const Icon(Icons.qr_code_scanner),
                    label: Text(AppLocalizations.of(context).scan),
                  ),
                  OutlinedButton.icon(
                    onPressed: () => _add(
                      () => Navigator.of(context).push<String>(
                        MaterialPageRoute(
                          builder: (_) => const ManualEntryPage(),
                        ),
                      ),
                    ),
                    icon: const Icon(Icons.keyboard_outlined),
                    label: Text(AppLocalizations.of(context).enterKey),
                  ),
                  OutlinedButton.icon(
                    onPressed: () => importFromFile(
                      context,
                      onImported: widget.controller.refresh,
                    ),
                    icon: const Icon(Icons.file_open_outlined),
                    label: Text(AppLocalizations.of(context).importFile),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// FR-30: hands one account to a device standing in front of the user.
  void _showQr(rust.EntryView entry) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => EntryQrPage(
          entryId: entry.id,
          title: entry.issuer == null
              ? entry.account
              : '${entry.issuer} (${entry.account})',
        ),
      ),
    );
  }

  void _share(rust.EntryView entry) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => ShareEntryPage(
          entryId: entry.id,
          title: entry.issuer == null
              ? entry.account
              : '${entry.issuer} (${entry.account})',
        ),
      ),
    );
  }

  Future<void> _importSharedLink(String link) async {
    try {
      final report = await share.importEntryShare(
        link: link,
        nowMs: widget.controller.time.nowMillis,
      );
      await widget.controller.refresh();
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (_) => ImportReportDialog(report: report),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            AppLocalizations.of(context).sharedAccountImportFailed('$error'),
          ),
        ),
      );
    }
  }

  Future<void> _chooseSharedImport() async {
    final source = await showModalBottomSheet<String>(
      context: context,
      builder: (sheetContext) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.qr_code_scanner),
              title: Text(AppLocalizations.of(context).scanShareQr),
              onTap: () => Navigator.pop(sheetContext, 'scan'),
            ),
            ListTile(
              leading: const Icon(Icons.content_paste_outlined),
              title: Text(AppLocalizations.of(context).pasteShareLink),
              onTap: () => Navigator.pop(sheetContext, 'paste'),
            ),
          ],
        ),
      ),
    );
    if (!mounted || source == null) return;
    String? link;
    if (source == 'scan') {
      link = await Navigator.of(context).push<String>(
        MaterialPageRoute(builder: (_) => const ScanPage(allowShareLink: true)),
      );
    } else {
      link = (await Clipboard.getData(Clipboard.kTextPlain))?.text?.trim();
    }
    if (!mounted || link == null || link.isEmpty) return;
    await _importSharedLink(link);
  }

  void _showNextCode(rust.EntryView entry) {
    final next = entry.nextCode;
    if (next == null) return;
    showModalBottomSheet<void>(
      context: context,
      builder: (sheetContext) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                AppLocalizations.of(context).nextCode,
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              CodeDisplay(code: next, expiring: false),
              const SizedBox(height: 12),
              Text(
                AppLocalizations.of(
                  context,
                ).availableAfterSeconds(entry.remainingSeconds),
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () {
                  Navigator.pop(sheetContext);
                  _clipboard.copyCode(next);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(
                        AppLocalizations.of(context).nextCodeCopied,
                      ),
                    ),
                  );
                },
                icon: const Icon(Icons.copy_outlined),
                label: Text(AppLocalizations.of(context).copyNextCode),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showDetails(rust.EntryView entry) {
    var revealed = !CodeVisibilityPreference.hideCodesUntilTap.value;
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (sheetContext) => StatefulBuilder(
        builder: (context, setSheetState) => SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    EntryAvatar(
                      issuer: entry.issuer,
                      account: entry.account,
                      icon: entry.icon,
                      size: 52,
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            entry.issuer ?? entry.account,
                            style: Theme.of(context).textTheme.titleLarge,
                          ),
                          if (entry.issuer != null) Text(entry.account),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 24),
                Center(
                  child: CodeDisplay(
                    code: entry.code,
                    hidden: !revealed,
                    expiring:
                        entry.kind != 'hotp' &&
                        entry.remainingSeconds <=
                            CountdownRing.warningThresholdSeconds,
                  ),
                ),
                const SizedBox(height: 8),
                if (!revealed)
                  TextButton.icon(
                    onPressed: () => setSheetState(() => revealed = true),
                    icon: const Icon(Icons.visibility_outlined),
                    label: Text(AppLocalizations.of(context).revealCode),
                  )
                else
                  FilledButton.tonalIcon(
                    onPressed: () => _copy(entry),
                    icon: const Icon(Icons.copy_outlined),
                    label: Text(AppLocalizations.of(context).copyCode),
                  ),
                if (entry.tags.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      for (final tag in entry.tags) Chip(label: Text(tag)),
                    ],
                  ),
                ],
                if (entry.note.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Text(
                    AppLocalizations.of(context).note,
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 4),
                  Text(entry.note),
                ],
                const SizedBox(height: 24),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    _DetailAction(
                      icon: Icons.edit_outlined,
                      label: AppLocalizations.of(context).edit,
                      onPressed: () {
                        Navigator.pop(sheetContext);
                        _edit(entry);
                      },
                    ),
                    _DetailAction(
                      icon: Icons.folder_outlined,
                      label: AppLocalizations.of(context).folder,
                      onPressed: () {
                        Navigator.pop(sheetContext);
                        _moveToFolder(entry);
                      },
                    ),
                    _DetailAction(
                      icon: Icons.qr_code_2_outlined,
                      label: AppLocalizations.of(context).qrCode,
                      onPressed: () {
                        Navigator.pop(sheetContext);
                        _showQr(entry);
                      },
                    ),
                    _DetailAction(
                      icon: Icons.share_outlined,
                      label: AppLocalizations.of(context).share,
                      onPressed: () {
                        Navigator.pop(sheetContext);
                        _share(entry);
                      },
                    ),
                    _DetailAction(
                      icon: Icons.delete_outline,
                      label: AppLocalizations.of(context).delete,
                      destructive: true,
                      onPressed: () {
                        Navigator.pop(sheetContext);
                        _confirmDelete(entry);
                      },
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _list(List<rust.EntryView> entries) {
    if (widget.controller.sortMode == SortMode.manual && _selectedIds.isEmpty) {
      return ReorderableListView.builder(
        buildDefaultDragHandles: false,
        itemCount: entries.length,
        onReorderItem: (oldIndex, newIndex) async {
          final reordered = [...entries];
          final moved = reordered.removeAt(oldIndex);
          reordered.insert(newIndex, moved);
          final before = newIndex == 0 ? null : reordered[newIndex - 1];
          final after = newIndex == reordered.length - 1
              ? null
              : reordered[newIndex + 1];
          try {
            await widget.controller.moveBetween(moved, before, after);
          } catch (error) {
            if (mounted) {
              ScaffoldMessenger.of(
                context,
              ).showSnackBar(SnackBar(content: Text(_message(error))));
            }
          }
        },
        itemBuilder: (context, index) {
          final entry = entries[index];
          return _buildEntryTile(
            entry,
            dragHandle: ReorderableDragStartListener(
              index: index,
              child: const Padding(
                padding: EdgeInsets.all(8),
                child: Icon(Icons.drag_handle),
              ),
            ),
          );
        },
      );
    }

    return ListView.separated(
      // NFR-02: a builder rather than a materialised list, so 500 entries cost
      // only what is on screen.
      itemCount: entries.length,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (context, index) {
        return _buildEntryTile(entries[index]);
      },
    );
  }

  Widget _buildEntryTile(rust.EntryView entry, {Widget? dragHandle}) {
    return _EntryTile(
      key: ValueKey(entry.id),
      entry: entry,
      codeHidden:
          CodeVisibilityPreference.hideCodesUntilTap.value &&
          !_revealedCodeIds.contains(entry.id),
      compact:
          AppearancePreference.listDensity.value == ListDensityChoice.compact,
      selected: _selectedIds.contains(entry.id),
      selectionMode: _selectedIds.isNotEmpty,
      dragHandle: dragHandle,
      onSelect: () => _toggleSelection(entry.id),
      onCopy: () => _usesTwoPane
          ? setState(() => _detailEntryId = entry.id)
          : _copy(entry),
      onReveal: () => setState(() {
        _revealedCodeIds.add(entry.id);
        if (_usesTwoPane) _detailEntryId = entry.id;
      }),
      onDetails: () => _showDetails(entry),
      onAdvance: entry.kind == 'hotp'
          ? () => widget.controller.advanceHotp(entry.id)
          : null,
      onEdit: () => _edit(entry),
      onMoveToFolder: () => _moveToFolder(entry),
      onShowQr: () => _showQr(entry),
      onShare: () => _share(entry),
      onShowNext: () => _showNextCode(entry),
      onDelete: () => _confirmDelete(entry),
      onToggleFavourite: () =>
          widget.controller.setFavourite(entry.id, !entry.favourite),
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
        title: Text(AppLocalizations.of(context).deleteEntryQuestion(label)),
        content: Text(AppLocalizations.of(context).deleteEntryDescription),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).keep),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(AppLocalizations.of(context).delete),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    try {
      await widget.controller.delete(entry.id);
      if (!mounted) return;
      ScaffoldMessenger.of(context)
        ..clearSnackBars()
        ..showSnackBar(
          SnackBar(
            content: Text(AppLocalizations.of(context).entryMovedToTrash),
            duration: const Duration(seconds: 6),
            action: SnackBarAction(
              label: AppLocalizations.of(context).undo,
              onPressed: () async {
                try {
                  await widget.controller.restore(entry.id);
                } catch (error) {
                  if (mounted) {
                    ScaffoldMessenger.of(
                      context,
                    ).showSnackBar(SnackBar(content: Text(_message(error))));
                  }
                }
              },
            ),
          ),
        );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(_message(error))));
      }
    }
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
              title: Text(AppLocalizations.of(context).scanQrCode),
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
              title: Text(AppLocalizations.of(context).enterSetupKey),
              onTap: () {
                Navigator.pop(sheetContext);
                _add(
                  () => Navigator.of(context).push<String>(
                    MaterialPageRoute(builder: (_) => const ManualEntryPage()),
                  ),
                );
              },
            ),
            ListTile(
              leading: const Icon(Icons.content_paste_outlined),
              title: Text(AppLocalizations.of(context).pasteSetupLink),
              subtitle: Text(
                AppLocalizations.of(context).pasteSetupLinkDescription,
              ),
              onTap: () {
                Navigator.pop(sheetContext);
                _add(_readSetupLinkFromClipboard);
              },
            ),
            const Divider(height: 1),
            ListTile(
              leading: const Icon(Icons.share_outlined),
              title: Text(AppLocalizations.of(context).importSharedAccount),
              subtitle: Text(
                AppLocalizations.of(context).importSharedAccountDescription,
              ),
              onTap: () {
                Navigator.pop(sheetContext);
                _chooseSharedImport();
              },
            ),
            const Divider(height: 1),
            // FR-15 and FR-15a. Deliberately here rather than buried in
            // settings: importing is what somebody does in their first two
            // minutes with this app, and an import they cannot find is an
            // import that does not exist.
            ListTile(
              leading: const Icon(Icons.folder_open_outlined),
              title: Text(AppLocalizations.of(context).importFromFile),
              subtitle: Text(AppLocalizations.of(context).supportedImportFiles),
              onTap: () {
                Navigator.pop(sheetContext);
                importFromFile(context, onImported: widget.controller.refresh);
              },
            ),
            // FR-15b and FR-15c. Reachable after the first run too, because
            // people move accounts across in batches over days — the one they
            // could not work out on Monday is the reason they come back.
            ListTile(
              leading: const Icon(Icons.help_outline),
              title: Text(AppLocalizations.of(context).movingFromAnotherApp),
              subtitle: Text(
                AppLocalizations.of(context).supportedMigrationApps,
              ),
              onTap: () {
                Navigator.pop(sheetContext);
                Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const ImportHelpPage()),
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
    super.key,
    required this.entry,
    required this.codeHidden,
    required this.compact,
    required this.selected,
    required this.selectionMode,
    required this.onSelect,
    required this.onCopy,
    required this.onReveal,
    required this.onDetails,
    required this.onEdit,
    required this.onMoveToFolder,
    required this.onShowQr,
    required this.onShare,
    required this.onShowNext,
    required this.onDelete,
    required this.onToggleFavourite,
    this.dragHandle,
    this.onAdvance,
  });

  final rust.EntryView entry;
  final bool codeHidden;
  final bool compact;
  final bool selected;
  final bool selectionMode;
  final VoidCallback onSelect;
  final VoidCallback onCopy;
  final VoidCallback onReveal;
  final VoidCallback onDetails;
  final VoidCallback onEdit;
  final VoidCallback onMoveToFolder;
  final VoidCallback onShowQr;
  final VoidCallback onShare;
  final VoidCallback onShowNext;
  final VoidCallback onDelete;
  final VoidCallback onToggleFavourite;
  final Widget? dragHandle;

  /// Present only for HOTP entries (FR-02).
  final VoidCallback? onAdvance;

  /// Time-based kinds: everything but HOTP, whose code changes only when the
  /// user asks. Written as "not hotp" rather than as a list, so a kind added
  /// later gets a countdown by default instead of silently getting the
  /// refresh button meant for counters.
  bool get _timeBased => entry.kind != 'hotp';

  bool get _expiring =>
      _timeBased &&
      entry.remainingSeconds <= CountdownRing.warningThresholdSeconds;

  @override
  Widget build(BuildContext context) {
    final title = entry.issuer ?? entry.account;
    final subtitle = entry.issuer == null ? null : entry.account;

    return ListTile(
      selected: selected,
      contentPadding: EdgeInsets.symmetric(
        horizontal: 16,
        vertical: compact ? 1 : 8,
      ),
      // FR-17 and FR-23. The tile is what makes forty rows tellable apart
      // while a code is running out; see `EntryAvatar` for why it is a colour
      // and a letter rather than a pack of brand logos.
      leading: selectionMode
          ? Checkbox(value: selected, onChanged: (_) => onSelect())
          : EntryAvatar(
              issuer: entry.issuer,
              account: entry.account,
              icon: entry.icon,
            ),
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
          if (subtitle != null) Text(subtitle, overflow: TextOverflow.ellipsis),
          if (entry.tags.isNotEmpty)
            Text(
              entry.tags.map((tag) => '#$tag').join('  '),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          if (entry.note.isNotEmpty)
            Text(
              entry.note,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          const SizedBox(height: 6),
          // Section 10.4 step 3: an entry whose counter is still being
          // reconciled must not show a code. The stored counter may be behind
          // the issuer's, and a code from it has already been rejected — so
          // saying why is better than showing a number that will not work.
          if (entry.awaitingReconcile)
            Row(
              children: [
                Icon(
                  Icons.sync_problem_outlined,
                  size: 16,
                  color: Theme.of(context).colorScheme.error,
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    AppLocalizations.of(context).syncCatchUpUnlock,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              ],
            )
          else
            CodeDisplay(
              code: entry.code,
              hidden: codeHidden,
              expiring: _expiring,
            ),
        ],
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (_timeBased)
            CountdownRing(
              remainingSeconds: entry.remainingSeconds,
              period: entry.period,
            )
          else
            IconButton(
              tooltip: AppLocalizations.of(context).nextCodeTooltip,
              icon: const Icon(Icons.refresh),
              onPressed: onAdvance,
            ),
          if (!selectionMode)
            PopupMenuButton<String>(
              onSelected: (value) => switch (value) {
                'details' => onDetails(),
                'edit' => onEdit(),
                'favourite' => onToggleFavourite(),
                'folder' => onMoveToFolder(),
                'qr' => onShowQr(),
                'share' => onShare(),
                'next' => onShowNext(),
                'delete' => onDelete(),
                _ => null,
              },
              itemBuilder: (context) => [
                PopupMenuItem(
                  value: 'details',
                  child: Text(AppLocalizations.of(context).viewDetails),
                ),
                // FR-17. The bridge could rename an entry for a whole stage
                // before anything in the application could reach it.
                PopupMenuItem(
                  value: 'edit',
                  child: Text(AppLocalizations.of(context).edit),
                ),
                PopupMenuItem(
                  value: 'favourite',
                  child: Text(
                    entry.favourite
                        ? AppLocalizations.of(context).removeFromFavourites
                        : AppLocalizations.of(context).addToFavourites,
                  ),
                ),
                // FR-19.
                PopupMenuItem(
                  value: 'folder',
                  child: Text(AppLocalizations.of(context).moveToFolder),
                ),
                // FR-30. Named for what it is for rather than for what it
                // shows: "Show QR code" describes the pixels, "Move to another
                // app" describes the reason anyone opens it.
                PopupMenuItem(
                  value: 'qr',
                  child: Text(AppLocalizations.of(context).moveToAnotherApp),
                ),
                PopupMenuItem(
                  value: 'share',
                  child: Text(AppLocalizations.of(context).shareEncryptedLink),
                ),
                if (entry.nextCode != null)
                  PopupMenuItem(
                    value: 'next',
                    child: Text(AppLocalizations.of(context).previewNextCode),
                  ),
                PopupMenuItem(
                  value: 'delete',
                  child: Text(AppLocalizations.of(context).delete),
                ),
              ],
            ),
          ?dragHandle,
        ],
      ),
      // FR-24: "Copy a code to the clipboard with one action."
      onTap: selectionMode ? onSelect : (codeHidden ? onReveal : onCopy),
      onLongPress: onSelect,
    );
  }
}

class _DetailAction extends StatelessWidget {
  const _DetailAction({
    required this.icon,
    required this.label,
    required this.onPressed,
    this.destructive = false,
  });

  final IconData icon;
  final String label;
  final VoidCallback onPressed;
  final bool destructive;

  @override
  Widget build(BuildContext context) {
    final colour = destructive ? Theme.of(context).colorScheme.error : null;
    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, color: colour),
      label: Text(label, style: TextStyle(color: colour)),
    );
  }
}

/// What the folder sheet returned.
///
/// A new folder and an existing one are different actions — one writes two
/// records, the other writes one — and collapsing them into a nullable string
/// would make "put it in no folder" indistinguishable from "make a folder
/// called nothing".
class _FolderChoice {
  const _FolderChoice.existing(this.folderId) : createNamed = null;
  const _FolderChoice.create(String name) : createNamed = name, folderId = null;

  final String? folderId;
  final String? createNamed;
}

/// Chooses a folder for one entry, or makes one (FR-19).
class _FolderSheet extends StatefulWidget {
  const _FolderSheet({required this.folders, required this.current});

  final List<rust.FolderView> folders;
  final String? current;

  @override
  State<_FolderSheet> createState() => _FolderSheetState();
}

class _FolderSheetState extends State<_FolderSheet> {
  final _name = TextEditingController();
  bool _creating = false;

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  void _submitNew() {
    final name = _name.text.trim();
    if (name.isEmpty) return;
    Navigator.pop(context, _FolderChoice.create(name));
  }

  @override
  Widget build(BuildContext context) {
    // Straight to the text field when there are no folders yet. The list of
    // one option — "New folder" — is a menu that exists to be dismissed.
    final creating = _creating || widget.folders.isEmpty;

    return SafeArea(
      child: Padding(
        padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom,
        ),
        child: ListView(
          shrinkWrap: true,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                creating
                    ? AppLocalizations.of(context).newFolder
                    : AppLocalizations.of(context).moveToFolder,
                style: Theme.of(context).textTheme.titleLarge,
              ),
            ),
            if (creating)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _name,
                        autofocus: true,
                        textCapitalization: TextCapitalization.sentences,
                        onSubmitted: (_) => _submitNew(),
                        decoration: InputDecoration(
                          labelText: AppLocalizations.of(context).folderName,
                          hintText: AppLocalizations.of(context).workExample,
                          border: const OutlineInputBorder(),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    FilledButton(
                      onPressed: _submitNew,
                      child: Text(AppLocalizations.of(context).create),
                    ),
                  ],
                ),
              )
            else ...[
              for (final folder in widget.folders)
                ListTile(
                  leading: const Icon(Icons.folder_outlined),
                  title: Text(folder.name),
                  trailing: widget.current == folder.id
                      ? const Icon(Icons.check)
                      : null,
                  onTap: () =>
                      Navigator.pop(context, _FolderChoice.existing(folder.id)),
                ),
              const Divider(height: 1),
              ListTile(
                leading: const Icon(Icons.folder_off_outlined),
                title: Text(AppLocalizations.of(context).noFolder),
                trailing: widget.current == null
                    ? const Icon(Icons.check)
                    : null,
                onTap: () =>
                    Navigator.pop(context, const _FolderChoice.existing(null)),
              ),
              ListTile(
                leading: const Icon(Icons.create_new_folder_outlined),
                title: Text(AppLocalizations.of(context).newFolder),
                onTap: () => setState(() => _creating = true),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Renames a folder (FR-19).
class _RenameFolderDialog extends StatefulWidget {
  const _RenameFolderDialog({required this.current});

  final String current;

  @override
  State<_RenameFolderDialog> createState() => _RenameFolderDialogState();
}

class _RenameFolderDialogState extends State<_RenameFolderDialog> {
  late final _name = TextEditingController(text: widget.current);

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  void _submit() {
    final name = _name.text.trim();
    // An empty name is rejected here rather than passed down to be refused by
    // the core. The core refuses it too — this is the message, not the rule.
    if (name.isEmpty) return;
    Navigator.pop(context, name);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(AppLocalizations.of(context).renameFolder),
      content: TextField(
        controller: _name,
        autofocus: true,
        textCapitalization: TextCapitalization.sentences,
        onSubmitted: (_) => _submit(),
        decoration: InputDecoration(
          labelText: AppLocalizations.of(context).folderName,
          border: const OutlineInputBorder(),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(AppLocalizations.of(context).cancel),
        ),
        FilledButton(
          onPressed: _submit,
          child: Text(AppLocalizations.of(context).rename),
        ),
      ],
    );
  }
}
