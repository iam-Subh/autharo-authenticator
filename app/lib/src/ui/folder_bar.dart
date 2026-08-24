import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;

/// The folder filter above the code list (FR-19).
///
/// # Why a filter row and not a folder tree
///
/// A tree makes folders a place you navigate *into*, which means the codes you
/// want are two taps away and the ones you did not file are somewhere you have
/// to remember. An authenticator is opened with a service already waiting for a
/// code — the list has to be the first thing, every time.
///
/// A row of chips keeps every code one tap from the front and makes the filter
/// a lens rather than a location. It also degrades correctly: a user with no
/// folders sees nothing at all, rather than an empty tree explaining a feature
/// they did not ask for.
///
/// # "All" is not a folder and neither is "Unfiled"
///
/// Both are always present when any folder exists. Without "Unfiled" the codes
/// a user has not sorted become invisible the moment they make their first
/// folder — and they are usually the majority, because filing is a thing people
/// start and do not finish.
class FolderBar extends StatelessWidget {
  const FolderBar({
    super.key,
    required this.folders,
    required this.selected,
    required this.onSelected,
    required this.unfiledCount,
    required this.onManage,
  });

  final List<rust.FolderView> folders;

  /// Null is "All". [unfiledSentinel] is "Unfiled". Anything else is a
  /// folder identifier.
  final String? selected;

  final ValueChanged<String?> onSelected;
  final int unfiledCount;

  /// Long-press on a folder chip. Renaming and deleting live here rather than
  /// on a settings screen because this is the only place folders are visible —
  /// a management screen for a feature whose whole interface is one row would
  /// be somewhere nobody thinks to look.
  final ValueChanged<rust.FolderView> onManage;

  /// Stands for "entries in no folder".
  ///
  /// Not a real identifier, and it cannot collide with one: folder identifiers
  /// are UUIDs, and this is not shaped like one.
  static const unfiledSentinel = 'unfiled';

  @override
  Widget build(BuildContext context) {
    // Nothing at all until the user makes a folder. An empty filter row is
    // chrome explaining a feature they have not asked for, on the screen that
    // most needs to be uncluttered.
    if (folders.isEmpty) return const SizedBox.shrink();

    return SizedBox(
      height: 48,
      child: ListView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        children: [
          _Chip(
            label: AppLocalizations.of(context).all,
            selected: selected == null,
            onTap: () => onSelected(null),
          ),
          for (final folder in folders)
            _Chip(
              label: folder.name,
              count: folder.count,
              selected: selected == folder.id,
              onTap: () => onSelected(folder.id),
              onLongPress: () => onManage(folder),
            ),
          if (unfiledCount > 0)
            _Chip(
              label: AppLocalizations.of(context).unfiled,
              count: unfiledCount,
              selected: selected == unfiledSentinel,
              onTap: () => onSelected(unfiledSentinel),
            ),
        ],
      ),
    );
  }
}

class _Chip extends StatelessWidget {
  const _Chip({
    required this.label,
    required this.selected,
    required this.onTap,
    this.count,
    this.onLongPress,
  });

  final String label;
  final bool selected;
  final VoidCallback onTap;
  final int? count;
  final VoidCallback? onLongPress;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: Center(
        // Wrapped rather than using the chip's own gesture handling, which has
        // no long-press. The tooltip is the only affordance a long-press can
        // have — without it the action is undiscoverable, which is the usual
        // fate of long-press.
        child: Tooltip(
          message: onLongPress == null
              ? ''
              : AppLocalizations.of(context).holdToManageFolder,
          child: GestureDetector(
            onLongPress: onLongPress,
            child: FilterChip(
              label: Text(count == null ? label : '$label  $count'),
              selected: selected,
              onSelected: (_) => onTap(),
              showCheckmark: false,
            ),
          ),
        ),
      ),
    );
  }
}

/// Applies the filter a [FolderBar] selected.
///
/// Kept beside the widget rather than in the list page, so the rule that an
/// entry naming a deleted folder counts as unfiled lives next to the row that
/// depends on it. Splitting them is how the two come to disagree, and the
/// symptom is codes that cannot be found under any chip.
List<rust.EntryView> applyFolderFilter(
  List<rust.EntryView> entries, {
  required String? selected,
  required Set<String> knownFolderIds,
}) {
  if (selected == null) return entries;

  bool unfiled(rust.EntryView entry) {
    final id = entry.folderId;
    return id == null || id.isEmpty || !knownFolderIds.contains(id);
  }

  if (selected == FolderBar.unfiledSentinel) {
    return entries.where(unfiled).toList();
  }
  return entries.where((entry) => entry.folderId == selected).toList();
}

/// How many entries would show under "Unfiled".
int countUnfiled(
  List<rust.EntryView> entries, {
  required Set<String> knownFolderIds,
}) => applyFolderFilter(
  entries,
  selected: FolderBar.unfiledSentinel,
  knownFolderIds: knownFolderIds,
).length;
