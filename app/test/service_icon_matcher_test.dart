import 'package:authenticator/src/services/brand_icon_preference.dart';
import 'package:authenticator/src/services/service_icon_matcher.dart';
import 'package:authenticator/src/ui/entry_avatar.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:simple_icons/simple_icons.dart';

void main() {
  test('matches a service from the QR issuer', () {
    final match = ServiceIconMatcher.match(
      issuer: 'GitHub',
      account: 'alice@example.com',
    );
    expect(match?.icon, SimpleIcons.github);
  });

  test('falls back to the account email domain when the issuer is absent', () {
    final match = ServiceIconMatcher.match(
      issuer: null,
      account: 'alice@gmail.com',
    );
    expect(match?.icon, SimpleIcons.gmail);
  });

  test('normalizes punctuation and service domains', () {
    final match = ServiceIconMatcher.match(
      issuer: 'login.proton-mail.com',
      account: 'alice',
    );
    expect(match?.icon, SimpleIcons.proton);
  });

  test('does not guess an icon for an unknown issuer', () {
    final match = ServiceIconMatcher.match(
      issuer: 'Example Company VPN',
      account: 'alice@example.invalid',
    );
    expect(match, isNull);
  });

  testWidgets('the account avatar uses the detected brand icon', (
    tester,
  ) async {
    BrandIconPreference.enabled.value = true;
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: EntryAvatar(issuer: 'GitHub', account: 'alice@example.com'),
        ),
      ),
    );
    expect(find.byIcon(SimpleIcons.github), findsOneWidget);
  });

  testWidgets('a user-selected icon overrides automatic matching', (
    tester,
  ) async {
    BrandIconPreference.enabled.value = true;
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: EntryAvatar(
            issuer: 'GitHub',
            account: 'alice@example.com',
            icon: '🔐',
          ),
        ),
      ),
    );
    expect(find.byIcon(SimpleIcons.github), findsNothing);
    expect(find.text('🔐'), findsOneWidget);
  });
}
