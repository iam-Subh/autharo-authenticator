import 'dart:convert';
import 'dart:io';

const _source = 'https://api.2fa.directory/v3/totp.json';

/// Generates the service-to-domain catalog used for full-colour favicons.
///
/// The source data uses the MIT license. Keep the 2FA Directory attribution in
/// the settings interface when this generated file is distributed.
Future<void> main() async {
  final client = HttpClient();
  final request = await client.getUrl(Uri.parse(_source));
  request.headers.set(
    HttpHeaders.userAgentHeader,
    'AuthenticationAppIconCatalog/1.0',
  );
  final response = await request.close();
  if (response.statusCode != HttpStatus.ok) {
    stderr.writeln('2FA Directory returned HTTP ${response.statusCode}.');
    exitCode = 1;
    client.close(force: true);
    return;
  }
  final body = await utf8.decoder.bind(response).join();
  client.close();
  final rows = jsonDecode(body) as List<dynamic>;
  final domains = <String, String>{};

  void add(String value, String domain) {
    final key = _normalize(value);
    if (key.isNotEmpty) domains.putIfAbsent(key, () => domain.toLowerCase());
  }

  for (final row in rows.cast<List<dynamic>>()) {
    final title = row[0] as String;
    final details = row[1] as Map<String, dynamic>;
    final domain = details['domain'] as String;
    add(title, domain);
    add(domain, domain);
    add(_domainLabel(domain), domain);
    for (final additional
        in (details['additional-domains'] as List<dynamic>? ?? const [])) {
      final additionalDomain = additional as String;
      add(additionalDomain, domain);
      add(_domainLabel(additionalDomain), domain);
    }
  }

  const manual = <String, String>{
    'Google': 'google.com',
    'Google Account': 'google.com',
    'Gmail': 'gmail.com',
    'Microsoft': 'microsoft.com',
    'Microsoft Account': 'microsoft.com',
    'Outlook': 'outlook.com',
    'Amazon': 'amazon.com',
    'Amazon Web Services': 'aws.amazon.com',
    'AWS': 'aws.amazon.com',
    'Apple': 'apple.com',
    'iCloud': 'icloud.com',
    'Slack': 'slack.com',
    'LinkedIn': 'linkedin.com',
    'Twitter': 'x.com',
    'X': 'x.com',
  };
  for (final entry in manual.entries) {
    domains[_normalize(entry.key)] = entry.value;
  }

  final entries = domains.entries.toList()
    ..sort((left, right) => left.key.compareTo(right.key));
  final output = StringBuffer()
    ..writeln("part of 'service_icon_matcher.dart';")
    ..writeln()
    ..writeln('// GENERATED FILE. DO NOT EDIT.')
    ..writeln('// Data sourced from https://2fa.directory by 2factorauth.')
    ..writeln('// Source data license: MIT.')
    ..writeln('// Run: dart run tool/generate_service_domain_catalog.dart')
    ..writeln('const _serviceDomains = <String, String>{');
  for (final entry in entries) {
    output.writeln("  '${entry.key}': '${entry.value}',");
  }
  output.writeln('};');

  final separator = Platform.pathSeparator;
  final outputFile = File(
    '${Directory.current.path}${separator}lib${separator}src${separator}services'
    '${separator}service_domain_catalog.g.dart',
  );
  outputFile.writeAsStringSync(output.toString());
  stdout.writeln('Generated ${entries.length} service domains.');
}

String _domainLabel(String domain) {
  const ignored = {'www', 'accounts', 'account', 'auth', 'login', 'secure'};
  return domain
      .toLowerCase()
      .split('.')
      .firstWhere((part) => !ignored.contains(part), orElse: () => domain);
}

String _normalize(String value) => value
    .toLowerCase()
    .replaceAll('&', 'and')
    .replaceAll('+', 'plus')
    .replaceAll(RegExp(r'[^a-z0-9]+'), '');
