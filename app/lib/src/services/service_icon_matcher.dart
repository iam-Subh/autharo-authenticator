import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:simple_icons/simple_icons.dart';

part 'service_icon_catalog.g.dart';
part 'service_domain_catalog.g.dart';

/// A bundled service icon selected from an OTP issuer or account domain.
class ServiceIconMatch {
  const ServiceIconMatch({
    required this.icon,
    required this.colour,
    this.domain,
  });

  /// An [IconData] or a Font Awesome [FaIconData].
  final Object icon;
  final Color colour;
  final String? domain;

  Uri? get faviconUri {
    final host = domain;
    if (host == null) return null;
    return Uri.https('t0.gstatic.com', '/faviconV2', {
      'client': 'SOCIAL',
      'type': 'FAVICON',
      'fallback_opts': 'TYPE,SIZE,URL',
      'url': 'https://$host',
      'size': '256',
    });
  }
}

class ServiceIconOption {
  const ServiceIconOption({
    required this.key,
    required this.label,
    required this.match,
  });

  final String key;
  final String label;
  final ServiceIconMatch match;
}

/// Matches an OTP issuer to a full-colour favicon and an offline icon.
///
/// The generated catalog contains every brand in the installed Simple Icons
/// package. The small override table covers common issuer names that do not
/// have a current Simple Icons brand because of trademark restrictions.
class ServiceIconMatcher {
  ServiceIconMatcher._();

  static const selectionPrefix = 'brand:v1:';

  static const _aliases = <String, String>{
    'aws': 'amazonwebservices',
    'amazonaws': 'amazonwebservices',
    'googlemail': 'gmail',
    'googleworkspace': 'google',
    'gcp': 'googlecloud',
    'icloud': 'apple',
    'office': 'microsoft',
    'office365': 'microsoft',
    'microsoft365': 'microsoft',
    'outlook': 'microsoft',
    'outlookcom': 'microsoft',
    'azure': 'microsoft',
    'azuredevops': 'microsoft',
    'amazon': 'amazonwebservices',
    'slackcom': 'slack',
    'linkedincom': 'linkedin',
    'twitter': 'x',
    'twittercom': 'x',
    'xcom': 'x',
  };

  static const _fallbackIcons = <String, ServiceIconMatch>{
    'microsoft': ServiceIconMatch(
      icon: FontAwesomeIcons.microsoft,
      colour: Color(0xff00a4ef),
    ),
    'amazonwebservices': ServiceIconMatch(
      icon: FontAwesomeIcons.aws,
      colour: Color(0xffff9900),
    ),
    'slack': ServiceIconMatch(
      icon: FontAwesomeIcons.slack,
      colour: Color(0xff4a154b),
    ),
    'linkedin': ServiceIconMatch(
      icon: FontAwesomeIcons.linkedinIn,
      colour: Color(0xff0a66c2),
    ),
  };

  static const _genericParts = <String>{
    'account',
    'accounts',
    'auth',
    'authentication',
    'authenticator',
    'code',
    'codes',
    'http',
    'https',
    'login',
    'mail',
    'otp',
    'secure',
    'security',
    'signin',
    'totp',
    'twofactor',
    '2fa',
    'www',
    'com',
    'net',
    'org',
    'co',
    'io',
    'app',
  };

  static ServiceIconMatch? match({String? issuer, required String account}) {
    return _matchOne(issuer) ?? _matchOne(account);
  }

  static ServiceIconMatch? fromStoredIcon(String value) {
    if (!value.startsWith(selectionPrefix)) return null;
    final key = value.substring(selectionPrefix.length);
    return _matchKey(key);
  }

  static String selectionValue(String key) => '$selectionPrefix$key';

  static List<ServiceIconOption> search(String query, {int limit = 32}) {
    final normalized = _normalize(query);
    const popular = <String>[
      'google',
      'microsoft',
      'apple',
      'github',
      'amazonwebservices',
      'facebook',
      'instagram',
      'linkedin',
      'slack',
      'discord',
      'dropbox',
      'proton',
      'paypal',
      'spotify',
      'telegram',
      'whatsapp',
    ];
    final List<String> keys;
    if (normalized.isEmpty) {
      keys = List<String>.of(popular);
    } else {
      keys = <String>{
        ..._serviceDomains.keys,
        ..._serviceIconCatalog.keys,
      }.where((key) => key.contains(normalized)).toList();
      keys.sort((left, right) {
        final leftStarts = left.startsWith(normalized);
        final rightStarts = right.startsWith(normalized);
        if (leftStarts != rightStarts) return leftStarts ? -1 : 1;
        return left.compareTo(right);
      });
    }
    return keys
        .take(limit)
        .map((key) {
          final match = _matchKey(key)!;
          return ServiceIconOption(
            key: key,
            label: _serviceDomains[key] ?? key,
            match: match,
          );
        })
        .toList(growable: false);
  }

  static ServiceIconMatch? _matchOne(String? value) {
    if (value == null || value.trim().isEmpty) return null;
    ServiceIconMatch? domainOnlyMatch;
    for (final candidate in _candidateKeys(value)) {
      final alias = _aliases[candidate] ?? candidate;
      final base = _fallbackIcons[alias] ?? _serviceIconCatalog[alias];
      final domain = _serviceDomains[alias] ?? _domainFromValue(value);
      if (base != null) {
        return ServiceIconMatch(
          icon: base.icon,
          colour: base.colour,
          domain: domain,
        );
      }
      if (domain != null) {
        domainOnlyMatch ??= ServiceIconMatch(
          icon: Icons.public,
          colour: const Color(0xff455a64),
          domain: domain,
        );
      }
    }
    return domainOnlyMatch;
  }

  static ServiceIconMatch? _matchKey(String key) {
    final alias = _aliases[key] ?? key;
    final base = _fallbackIcons[alias] ?? _serviceIconCatalog[alias];
    final domain = _serviceDomains[alias];
    if (base == null && domain == null) return null;
    return ServiceIconMatch(
      icon: base?.icon ?? Icons.public,
      colour: base?.colour ?? const Color(0xff455a64),
      domain: domain,
    );
  }

  static String? _domainFromValue(String value) {
    var candidate = value.trim().toLowerCase();
    final atIndex = candidate.lastIndexOf('@');
    if (atIndex >= 0) candidate = candidate.substring(atIndex + 1);
    candidate = candidate
        .replaceFirst(RegExp(r'^https?://'), '')
        .split(RegExp(r'[/?:#]'))
        .first;
    if (!RegExp(
      r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',
    ).hasMatch(candidate)) {
      return null;
    }
    const reservedSuffixes = <String>{
      '.example',
      '.invalid',
      '.localhost',
      '.test',
    };
    if (reservedSuffixes.any(candidate.endsWith)) return null;
    return candidate;
  }

  static Iterable<String> _candidateKeys(String value) sync* {
    final seen = <String>{};

    Iterable<String> add(String source) sync* {
      final normalized = _normalize(source);
      if (normalized.isEmpty) return;
      final catalogKey = RegExp(r'^\d').hasMatch(normalized)
          ? 'n$normalized'
          : normalized;
      if (seen.add(catalogKey)) yield catalogKey;
    }

    final sources = <String>[];
    final atIndex = value.lastIndexOf('@');
    if (atIndex >= 0 && atIndex + 1 < value.length) {
      // Check the email domain before the local part. A person's name can also
      // be a brand name and must not override a known domain such as gmail.com.
      sources.add(value.substring(atIndex + 1));
    }
    sources.add(value);

    for (final source in sources) {
      yield* add(source);
      final parts = source
          .toLowerCase()
          .split(RegExp(r'[^a-z0-9]+'))
          .where((part) => part.isNotEmpty && !_genericParts.contains(part))
          .toList(growable: false);

      // Try multi-word brand names before their individual words. For example,
      // "Google Cloud Platform" must resolve to Google Cloud, not Google.
      for (var width = parts.length; width >= 2; width--) {
        for (var start = 0; start + width <= parts.length; start++) {
          yield* add(parts.sublist(start, start + width).join());
        }
      }
      for (final part in parts) {
        yield* add(part);
      }
    }
  }

  static String _normalize(String value) => value
      .toLowerCase()
      .replaceAll('&', 'and')
      .replaceAll('+', 'plus')
      .replaceAll(RegExp(r'[^a-z0-9]+'), '');
}
