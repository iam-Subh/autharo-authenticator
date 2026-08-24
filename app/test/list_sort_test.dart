import 'package:authenticator/src/rust/api/vault.dart' as rust;
import 'package:authenticator/src/services/list_sort.dart';
import 'package:flutter_test/flutter_test.dart';

rust.EntryView entry({
  String id = 'id',
  String account = 'account',
  String? issuer,
  bool favourite = false,
  int createdAt = 0,
  String order = '',
}) {
  return rust.EntryView(
    id: id,
    kind: 'totp',
    issuer: issuer,
    account: account,
    code: '000000',
    nextCode: '111111',
    digits: 6,
    period: 30,
    remainingSeconds: 30,
    favourite: favourite,
    note: '',
    tags: const [],
    createdAt: createdAt,
    order: order,
    awaitingReconcile: false,
  );
}

List<String> accountsOf(List<rust.EntryView> entries) =>
    entries.map((e) => e.account).toList();

void main() {
  group('FR-22 sort modes', () {
    test('by name, ignoring case', () {
      // An ASCII compare puts every capital before every lowercase letter, so
      // `Zoho` would come before `apple` and the list reads as broken.
      final sorted = sortEntries([
        entry(id: '1', account: 'zulu'),
        entry(id: '2', account: 'Alpha'),
        entry(id: '3', account: 'mike'),
      ], SortMode.name);

      expect(accountsOf(sorted), ['Alpha', 'mike', 'zulu']);
    });

    test('by issuer, with no issuer sorting first', () {
      final sorted = sortEntries([
        entry(id: '1', account: 'a', issuer: 'Zoho'),
        entry(id: '2', account: 'b'),
        entry(id: '3', account: 'c', issuer: 'GitHub'),
      ], SortMode.issuer);

      expect(accountsOf(sorted), ['b', 'c', 'a']);
    });

    test('by date added, newest first', () {
      // Someone choosing "recently added" wants what they just added, not what
      // they added in 2019.
      final sorted = sortEntries([
        entry(id: '1', account: 'old', createdAt: 1000),
        entry(id: '2', account: 'new', createdAt: 3000),
        entry(id: '3', account: 'middle', createdAt: 2000),
      ], SortMode.dateAdded);

      expect(accountsOf(sorted), ['new', 'middle', 'old']);
    });

    test('by manual order', () {
      final sorted = sortEntries([
        entry(id: '1', account: 'third', order: 'c'),
        entry(id: '2', account: 'first', order: 'a'),
        entry(id: '3', account: 'second', order: 'b'),
      ], SortMode.manual);

      expect(accountsOf(sorted), ['first', 'second', 'third']);
    });

    test('an unplaced entry sorts after every placed one', () {
      // A new entry appearing in the middle of a list someone arranged by hand
      // looks like the arrangement was lost.
      final sorted = sortEntries([
        entry(id: '1', account: 'brand new'),
        entry(id: '2', account: 'placed', order: 'm'),
      ], SortMode.manual);

      expect(accountsOf(sorted), ['placed', 'brand new']);
    });
  });

  group('favourites', () {
    test('come first in every mode', () {
      // FR-20 outranks the sort: someone who pinned an entry wants it at the
      // top, not at the top of its alphabetical group.
      for (final mode in SortMode.values) {
        final sorted = sortEntries([
          entry(id: '1', account: 'aaa', createdAt: 9000, order: 'a'),
          entry(id: '2', account: 'zzz', favourite: true, order: 'z'),
        ], mode);

        expect(
          accountsOf(sorted).first,
          'zzz',
          reason: 'a favourite must lead in ${mode.stored}',
        );
      }
    });

    test('are sorted among themselves', () {
      final sorted = sortEntries([
        entry(id: '1', account: 'zebra', favourite: true),
        entry(id: '2', account: 'ant', favourite: true),
        entry(id: '3', account: 'bee'),
      ], SortMode.name);

      expect(accountsOf(sorted), ['ant', 'zebra', 'bee']);
    });
  });

  group('the order is total', () {
    test('entries that tie do not swap between rebuilds', () {
      // A list that reshuffles while being read is worse than one sorted the
      // wrong way. Two entries equal on the chosen field must still have a
      // fixed relative position.
      final input = [
        entry(id: 'b', account: 'same', createdAt: 5),
        entry(id: 'a', account: 'same', createdAt: 5),
      ];

      final first = sortEntries(input, SortMode.dateAdded);
      final second = sortEntries(input.reversed.toList(), SortMode.dateAdded);

      expect(first.map((e) => e.id).toList(), ['a', 'b']);
      expect(
        second.map((e) => e.id).toList(),
        ['a', 'b'],
        reason: 'the input order must not affect the result',
      );
    });

    test('sorting does not modify the list it was given', () {
      final input = [
        entry(id: '1', account: 'zulu'),
        entry(id: '2', account: 'alpha'),
      ];
      sortEntries(input, SortMode.name);
      expect(accountsOf(input), ['zulu', 'alpha']);
    });
  });

  group('the stored value is a wire format', () {
    test('every mode round-trips', () {
      for (final mode in SortMode.values) {
        expect(SortMode.fromStored(mode.stored), mode);
      }
    });

    test('an unknown or missing value falls back rather than failing', () {
      // A preference written by a newer version is not a reason to refuse to
      // show someone their codes.
      expect(SortMode.fromStored(null), SortMode.name);
      expect(SortMode.fromStored('sorted-by-vibes'), SortMode.name);
    });
  });

  group('the fractional index', () {
    test('lands strictly between its neighbours', () {
      expect(orderBetween('a', 'c').compareTo('a'), greaterThan(0));
      expect(orderBetween('a', 'c').compareTo('c'), lessThan(0));
    });

    test('works between adjacent keys, however many times', () {
      // This is the whole point of a fractional index: there is always another
      // position, so an insert between two neighbours never runs out of room.
      var low = 'a';
      var high = 'b';
      for (var i = 0; i < 50; i++) {
        final middle = orderBetween(low, high);
        expect(middle.compareTo(low), greaterThan(0), reason: 'round $i');
        expect(middle.compareTo(high), lessThan(0), reason: 'round $i');
        low = middle;
      }
    });

    test('appends and prepends', () {
      expect(orderBetween('m', null).compareTo('m'), greaterThan(0));
      expect(orderBetween(null, 'm').compareTo('m'), lessThan(0));
      expect(orderBetween(null, null), isNotEmpty);
    });

    test('two devices inserting in the same gap both survive', () {
      // The reason this is not an integer position. Section 10.4 resolves
      // conflicts on the whole record, so two people moving different entries
      // to "position 3" produce one winner and one silently discarded move.
      final fromPhone = orderBetween('a', 'b');
      final fromLaptop = orderBetween('a', fromPhone);

      expect(fromLaptop.compareTo('a'), greaterThan(0));
      expect(fromLaptop.compareTo(fromPhone), lessThan(0));
    });
  });
}
