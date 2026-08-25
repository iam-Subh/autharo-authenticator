import 'package:authenticator/src/services/brand_icon_preference.dart';
import 'package:authenticator/src/services/service_icon_matcher.dart';
import 'package:authenticator/src/ui/entry_avatar.dart';
import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
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

  test('matches brands outside the old small catalog', () {
    final match = ServiceIconMatcher.match(
      issuer: '1Password',
      account: 'alice@example.com',
    );
    expect(match?.icon, SimpleIcons.n1password);
  });

  test('matches a multi-word QR issuer', () {
    final match = ServiceIconMatcher.match(
      issuer: 'Google Cloud Platform',
      account: 'alice@example.com',
    );
    expect(match?.icon, SimpleIcons.googlecloud);
  });

  test('checks the email domain before the account name', () {
    final match = ServiceIconMatcher.match(
      issuer: null,
      account: 'github@gmail.com',
    );
    expect(match?.icon, SimpleIcons.gmail);
  });

  test('uses a real brand icon for a common Simple Icons omission', () {
    final match = ServiceIconMatcher.match(
      issuer: 'Microsoft',
      account: 'alice@outlook.com',
    );
    expect(match?.icon, FontAwesomeIcons.microsoft);
  });

  test('Google resolves to its full-colour favicon source', () {
    final match = ServiceIconMatcher.match(
      issuer: 'Google',
      account: 'alice@gmail.com',
    );
    expect(match?.domain, 'google.com');
    expect(match?.faviconUri?.host, 't0.gstatic.com');
    expect(match?.faviconUri?.queryParameters['url'], 'https://google.com');
  });

  test('the searchable picker stores a stable brand identifier', () {
    final option = ServiceIconMatcher.search(
      'google',
    ).firstWhere((option) => option.key == 'google');
    final stored = ServiceIconMatcher.selectionValue(option.key);
    expect(stored, 'brand:v1:google');
    expect(ServiceIconMatcher.fromStoredIcon(stored)?.domain, 'google.com');
  });

  test('opening the picker with an empty search does not modify constants', () {
    final options = ServiceIconMatcher.search('');
    expect(options, isNotEmpty);
    expect(options.first.key, 'google');
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
    final image = tester.widget<Image>(find.byType(Image));
    final provider = image.image as NetworkImage;
    expect(provider.url, contains('github.com'));
  });

  testWidgets('an old saved initial does not hide the Google favicon', (
    tester,
  ) async {
    BrandIconPreference.enabled.value = true;
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: EntryAvatar(
            issuer: 'Google',
            account: 'alice@gmail.com',
            icon: 'G',
          ),
        ),
      ),
    );
    final image = tester.widget<Image>(find.byType(Image));
    final provider = image.image as NetworkImage;
    expect(provider.url, contains('google.com'));
    expect(find.text('G'), findsNothing);
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
