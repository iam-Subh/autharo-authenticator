import '../rust/api/vault.dart' as rust;

/// FR-22: "Sort entries by name, by issuer, by date added, and by manual
/// order."
///
/// # Favourites come first in every mode
///
/// FR-20 pins them, and that outranks the sort: a user who pinned something
/// wants it at the top, not at the top of its alphabetical group. Within the
/// favourites the chosen sort still applies.
enum SortMode {
  /// The account name — what the user typed, and what they will look for.
  name('name', 'Name'),

  /// The service. The common case for someone with forty entries.
  issuer('issuer', 'Issuer'),

  /// Newest first. Useful right after adding something.
  dateAdded('added', 'Recently added'),

  /// Wherever the user dragged it.
  manual('manual', 'My order');

  const SortMode(this.stored, this.label);

  /// Written to the metadata file. Deliberately short and stable — a stored
  /// value is a wire format, and renaming an enum should not resort everyone's
  /// list.
  final String stored;

  /// Shown in the menu.
  final String label;

  static SortMode fromStored(String? value) => SortMode.values.firstWhere(
    (mode) => mode.stored == value,
    // A value written by a newer version, or none at all. Falling back rather
    // than failing: an unreadable preference is not a reason to refuse to show
    // someone their codes.
    orElse: () => SortMode.name,
  );
}

/// Orders a list for display.
///
/// Pure, so the ordering can be tested without a vault. Sorting is the kind of
/// code that looks right and is subtly wrong — a comparator that is not
/// transitive, a null that sorts differently on two platforms, a case-sensitive
/// compare that puts `Zoho` before `apple`.
List<rust.EntryView> sortEntries(List<rust.EntryView> entries, SortMode mode) {
  final sorted = [...entries];

  sorted.sort((a, b) {
    // FR-20 first, in every mode.
    if (a.favourite != b.favourite) return a.favourite ? -1 : 1;

    final byMode = switch (mode) {
      SortMode.name => _text(a.account).compareTo(_text(b.account)),
      SortMode.issuer => _text(a.issuer ?? '').compareTo(_text(b.issuer ?? '')),
      // Newest first: someone choosing "recently added" wants what they just
      // added, not what they added in 2019.
      SortMode.dateAdded => b.createdAt.compareTo(a.createdAt),
      SortMode.manual => _manual(a).compareTo(_manual(b)),
    };
    if (byMode != 0) return byMode;

    // A total order, always. Two entries that compare equal on the chosen field
    // would otherwise swap places between rebuilds, and a list that reshuffles
    // while being read is worse than one sorted the wrong way.
    final byAccount = _text(a.account).compareTo(_text(b.account));
    if (byAccount != 0) return byAccount;
    return a.id.compareTo(b.id);
  });

  return sorted;
}

/// Case- and accent-insensitive enough for a list of service names.
///
/// Lowercased so `apple` and `Apple` sort together rather than in two blocks —
/// an ASCII compare puts every capital before every lowercase letter, which
/// reads as a broken sort.
String _text(String value) => value.trim().toLowerCase();

/// An entry with no manual position sorts after every entry that has one.
///
/// A new entry landing in the middle of a list someone arranged by hand looks
/// like the arrangement was lost. `~` is above every character the fractional
/// index below produces.
String _manual(rust.EntryView entry) =>
    entry.order.isEmpty ? '~${_text(entry.account)}' : entry.order;

/// A fractional index that sorts strictly between `before` and `after`.
///
/// # Why not an integer position
///
/// Because two devices would pick the same one. Section 10.4 resolves conflicts
/// on the whole record, so two people moving different entries to position 3
/// produce one winner and one silently discarded move. A fractional index lets
/// both insert between the same pair and both survive — which is the same
/// reason the payload stores `order` as a string.
///
/// Pass null for either end to append or prepend.
String orderBetween(String? before, String? after) {
  const first = 0x20; // space
  const last = 0x7e; // tilde

  final left = (before == null || before.isEmpty) ? '' : before;
  final right = (after == null || after.isEmpty) ? '' : after;

  final result = StringBuffer();
  var index = 0;

  while (true) {
    final leftCode = index < left.length ? left.codeUnitAt(index) : first;
    final rightCode = index < right.length ? right.codeUnitAt(index) : last + 1;

    if (rightCode - leftCode > 1) {
      // Room between them at this position.
      result.writeCharCode((leftCode + rightCode) ~/ 2);
      return result.toString();
    }

    // No room: keep the left character and look one position deeper. This is
    // what makes the index unbounded — there is always another position, so an
    // insert between two adjacent keys never fails.
    result.writeCharCode(leftCode);
    index++;
  }
}
