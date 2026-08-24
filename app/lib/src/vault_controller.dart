import 'dart:async';

import 'package:flutter/foundation.dart';

import 'rust/api/vault.dart' as rust;
import 'services/list_sort.dart';
import 'services/reference_time.dart';

/// Holds the code list and keeps it current.
///
/// One timer drives every row. A timer per row would be simpler to write and
/// would put NFR-02 (60 fps at 500 entries) out of reach, so the tick happens
/// here and the rows are rebuilt from one reference time.
///
/// The timer runs at one second. Codes only change once per period, but the
/// countdown in FR-07 changes every second, so a slower tick would make the
/// ring stutter.
class VaultController extends ChangeNotifier {
  VaultController(this._time, {this.onLocalChange});

  final ReferenceTime _time;

  /// Section 10.3's "on a change" trigger.
  ///
  /// A callback rather than a direct call into the scheduler, so this class
  /// keeps knowing nothing about sync. It is also why every write below goes
  /// through [_changed] instead of calling `refresh` directly: a write that
  /// refreshed the list without reporting itself would leave the entry on this
  /// device and nowhere else until something unrelated triggered a cycle.
  final void Function()? onLocalChange;

  Timer? _ticker;
  List<rust.EntryView> _entries = const [];
  Object? _error;
  bool _loading = true;

  List<rust.EntryView> get entries => _entries;
  Object? get error => _error;
  bool get loading => _loading;
  ReferenceTime get time => _time;

  /// FR-40: surfaced as a banner above the list.
  bool get isClockDrifting => _time.isDrifting;

  /// Refreshes the list and reports the write for section 10.3's trigger.
  ///
  /// One place, so a write added later cannot forget the second half. The
  /// order matters: the list is refreshed first, so the user sees their change
  /// immediately rather than after a network round trip they never asked to
  /// wait for (OFF-08).
  Future<void> _changed() async {
    await refresh();
    onLocalChange?.call();
  }

  /// Reads the stored sort before the first list is built, so the first frame
  /// is already in the user's order rather than jumping a moment later.
  void loadSortMode() {
    _sortMode = SortMode.fromStored(rust.listSort());
  }

  Future<void> start() async {
    final purged = await rust.purgeExpiredTrash(nowMs: _time.nowMillis);
    if (purged > 0) onLocalChange?.call();
    await refresh();
    _ticker?.cancel();
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) => refresh());
  }

  void stop() {
    _ticker?.cancel();
    _ticker = null;
  }

  /// Recomputes every code at the current reference time.
  ///
  /// This goes to Rust each tick rather than counting down in Dart. The
  /// alternative — generate once, decrement locally — drifts against the real
  /// time step and eventually shows a code that has already changed.
  Future<void> refresh() async {
    try {
      final entries = await rust.listEntries(nowUnixSeconds: _time.nowSeconds);
      // Read in the same pass, so the filter row and the rows below it can
      // never describe two different states. Fetching folders on their own
      // schedule would show a count of four beside a chip that filters to
      // three, which reads as codes having gone missing.
      _folders = await rust.listFolders();
      _error = null;
      _entries = _sorted(entries);
    } catch (error) {
      _error = error;
    } finally {
      if (_loading) _loading = false;
      notifyListeners();
    }
  }

  List<rust.FolderView> _folders = const [];

  /// FR-19: the folders, with their counts. Sorted by name in the core.
  List<rust.FolderView> get folders => _folders;

  /// FR-19: files an entry, or takes it out of a folder with null.
  Future<void> setFolder(String id, String? folderId) async {
    await rust.setEntryFolder(
      id: id,
      folderId: folderId,
      nowMs: _time.nowMillis,
    );
    await _changed();
  }

  Future<String> createFolder(String name) async {
    final id = await rust.createFolder(name: name, nowMs: _time.nowMillis);
    await _changed();
    return id;
  }

  Future<void> renameFolder(String id, String name) async {
    await rust.renameFolder(id: id, name: name, nowMs: _time.nowMillis);
    await _changed();
  }

  /// Removes the folder. Never removes what was in it — see `delete_folder`
  /// in the bridge for why the entries are unfiled instead.
  Future<void> deleteFolder(String id) async {
    await rust.deleteFolder(id: id, nowMs: _time.nowMillis);
    await _changed();
  }

  /// FR-22, with FR-20's favourites pinned above it in every mode.
  List<rust.EntryView> _sorted(List<rust.EntryView> entries) =>
      sortEntries(entries, _sortMode);

  SortMode _sortMode = SortMode.name;
  SortMode get sortMode => _sortMode;

  /// FR-22: the choice outlives the run.
  ///
  /// A sort that resets at every start does nothing, in the same way FR-33a
  /// says a lock setting that resets does nothing.
  Future<void> setSortMode(SortMode mode) async {
    if (mode == _sortMode) return;
    _sortMode = mode;
    await rust.setListSort(mode: mode.stored);
    _entries = _sorted(_entries);
    notifyListeners();
  }

  /// Moves an entry to sit between two others (FR-22's manual order).
  ///
  /// The neighbours are passed rather than an index, because the index depends
  /// on the list as displayed and the position has to be expressed as something
  /// two devices can compute independently — see [orderBetween].
  Future<void> moveBetween(
    rust.EntryView moved,
    rust.EntryView? before,
    rust.EntryView? after,
  ) async {
    final order = orderBetween(
      before?.order.isEmpty ?? true ? null : before!.order,
      after?.order.isEmpty ?? true ? null : after!.order,
    );
    await rust.setEntryOrder(
      id: moved.id,
      order: order,
      nowMs: _time.nowMillis,
    );

    // Dragging is a placement, so it switches the list to showing placements.
    // Leaving it sorted by name would put the entry straight back where it was
    // and read as the drag having failed.
    if (_sortMode != SortMode.manual) {
      await setSortMode(SortMode.manual);
    }
    await _changed();
  }

  /// FR-21: "Search entries by issuer and by account name. Match on any part of
  /// the string."
  List<rust.EntryView> search(String query) {
    final needle = query.trim().toLowerCase();
    if (needle.isEmpty) return _entries;
    return _entries.where((entry) {
      final issuer = entry.issuer?.toLowerCase() ?? '';
      return issuer.contains(needle) ||
          entry.account.toLowerCase().contains(needle) ||
          entry.note.toLowerCase().contains(needle) ||
          entry.tags.any((tag) => tag.toLowerCase().contains(needle));
    }).toList();
  }

  Future<rust.AddOutcome> addFromUri(String uri) async {
    final outcome = await rust.addFromUri(uri: uri, nowMs: _time.nowMillis);
    if (outcome.addedId != null) await _changed();
    return outcome;
  }

  Future<void> delete(String id) async {
    await rust.moveEntryToTrash(id: id, nowMs: _time.nowMillis);
    await _changed();
  }

  Future<void> restore(String id) async {
    await rust.restoreEntry(id: id, nowMs: _time.nowMillis);
    await _changed();
  }

  Future<void> permanentlyDelete(String id) async {
    await rust.deleteEntry(id: id, nowMs: _time.nowMillis);
    await _changed();
  }

  Future<List<rust.TrashEntryView>> listTrash() => rust.listTrashedEntries();

  Future<List<List<String>>> findDuplicateGroups() =>
      rust.findDuplicateGroups();

  Future<void> purgeExpiredTrash() async {
    final count = await rust.purgeExpiredTrash(nowMs: _time.nowMillis);
    if (count == 0) return;
    await _changed();
  }

  Future<void> rename(
    String id,
    String? issuer,
    String account, {
    String? icon,
    String? note,
    List<String>? tags,
  }) async {
    await rust.renameEntry(
      id: id,
      issuer: issuer,
      account: account,
      icon: icon,
      note: note,
      tags: tags,
      nowMs: _time.nowMillis,
    );
    await _changed();
  }

  Future<void> enableManualOrder() async {
    for (var index = 0; index < _entries.length; index++) {
      final entry = _entries[index];
      if (entry.order.isNotEmpty) continue;
      final order = 'm${index.toString().padLeft(8, '0')}';
      await rust.setEntryOrder(
        id: entry.id,
        order: order,
        nowMs: _time.nowMillis,
      );
    }
    await setSortMode(SortMode.manual);
    await _changed();
  }

  Future<void> deleteMany(Iterable<String> ids) async {
    for (final id in ids) {
      await rust.moveEntryToTrash(id: id, nowMs: _time.nowMillis);
    }
    await _changed();
  }

  Future<void> restoreMany(Iterable<String> ids) async {
    for (final id in ids) {
      await rust.restoreEntry(id: id, nowMs: _time.nowMillis);
    }
    await _changed();
  }

  Future<void> setFavouriteMany(Iterable<String> ids, bool favourite) async {
    for (final id in ids) {
      await rust.setFavourite(
        id: id,
        favourite: favourite,
        nowMs: _time.nowMillis,
      );
    }
    await _changed();
  }

  Future<void> setFolderMany(Iterable<String> ids, String? folderId) async {
    for (final id in ids) {
      await rust.setEntryFolder(
        id: id,
        folderId: folderId,
        nowMs: _time.nowMillis,
      );
    }
    await _changed();
  }

  Future<void> setFavourite(String id, bool favourite) async {
    await rust.setFavourite(
      id: id,
      favourite: favourite,
      nowMs: _time.nowMillis,
    );
    await _changed();
  }

  /// FR-02: advancing the counter is a deliberate act, so it returns the new
  /// code for the caller to show rather than relying on the next tick.
  Future<String> advanceHotp(String id) async {
    final code = await rust.advanceHotp(id: id, nowMs: _time.nowMillis);
    await _changed();
    return code;
  }

  @override
  void dispose() {
    stop();
    super.dispose();
  }
}
