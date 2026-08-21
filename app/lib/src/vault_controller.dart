import 'dart:async';

import 'package:flutter/foundation.dart';

import 'rust/api/vault.dart' as rust;
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
  VaultController(this._time);

  final ReferenceTime _time;

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

  Future<void> start() async {
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
      _error = null;
      _entries = _sorted(entries);
    } catch (error) {
      _error = error;
    } finally {
      if (_loading) _loading = false;
      notifyListeners();
    }
  }

  /// FR-20: favourites pin to the top. Within each group the core's HLC order
  /// (newest first) is preserved.
  List<rust.EntryView> _sorted(List<rust.EntryView> entries) {
    final favourites = entries.where((e) => e.favourite).toList();
    final rest = entries.where((e) => !e.favourite).toList();
    return [...favourites, ...rest];
  }

  /// FR-21: "Search entries by issuer and by account name. Match on any part of
  /// the string."
  List<rust.EntryView> search(String query) {
    final needle = query.trim().toLowerCase();
    if (needle.isEmpty) return _entries;
    return _entries.where((entry) {
      final issuer = entry.issuer?.toLowerCase() ?? '';
      return issuer.contains(needle) ||
          entry.account.toLowerCase().contains(needle);
    }).toList();
  }

  Future<rust.AddOutcome> addFromUri(String uri) async {
    final outcome = await rust.addFromUri(uri: uri, nowMs: _time.nowMillis);
    if (outcome.addedId != null) await refresh();
    return outcome;
  }

  Future<void> delete(String id) async {
    await rust.deleteEntry(id: id, nowMs: _time.nowMillis);
    await refresh();
  }

  Future<void> rename(String id, String? issuer, String account) async {
    await rust.renameEntry(
      id: id,
      issuer: issuer,
      account: account,
      nowMs: _time.nowMillis,
    );
    await refresh();
  }

  Future<void> setFavourite(String id, bool favourite) async {
    await rust.setFavourite(
      id: id,
      favourite: favourite,
      nowMs: _time.nowMillis,
    );
    await refresh();
  }

  /// FR-02: advancing the counter is a deliberate act, so it returns the new
  /// code for the caller to show rather than relying on the next tick.
  Future<String> advanceHotp(String id) async {
    final code = await rust.advanceHotp(id: id, nowMs: _time.nowMillis);
    await refresh();
    return code;
  }

  @override
  void dispose() {
    stop();
    super.dispose();
  }
}
