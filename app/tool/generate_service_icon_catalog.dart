import 'dart:convert';
import 'dart:io';

/// Generates the runtime issuer catalog from the installed `simple_icons`
/// package. Run this after a `simple_icons` dependency update.
void main() {
  final projectDirectory = Directory.current;
  final packageConfigFile = File(
    '${projectDirectory.path}${Platform.pathSeparator}.dart_tool'
    '${Platform.pathSeparator}package_config.json',
  );
  if (!packageConfigFile.existsSync()) {
    stderr.writeln('Run flutter pub get before this generator.');
    exitCode = 1;
    return;
  }

  final packageConfig =
      jsonDecode(packageConfigFile.readAsStringSync()) as Map<String, dynamic>;
  final packages = packageConfig['packages'] as List<dynamic>;
  final simpleIconsPackage = packages.cast<Map<String, dynamic>>().firstWhere(
    (package) => package['name'] == 'simple_icons',
  );
  final packageConfigDirectory = packageConfigFile.parent.uri;
  final configuredRoot = Uri.parse(simpleIconsPackage['rootUri'] as String);
  final resolvedRoot = configuredRoot.hasScheme
      ? configuredRoot
      : packageConfigDirectory.resolveUri(configuredRoot);
  final packageRoot = resolvedRoot.path.endsWith('/')
      ? resolvedRoot
      : resolvedRoot.replace(path: '${resolvedRoot.path}/');
  final libDirectory = packageRoot.resolve(
    simpleIconsPackage['packageUri'] as String,
  );
  final iconDataFile = File.fromUri(
    libDirectory.resolve('src/icon_data.g.dart'),
  );
  final iconColorFile = File.fromUri(
    libDirectory.resolve('src/icon_color.g.dart'),
  );

  final fieldPattern = RegExp(r'static const IconData ([A-Za-z0-9_]+)\s*=');
  final colorPattern = RegExp(r'static const Color ([A-Za-z0-9_]+)\s*=');
  final fields = fieldPattern
      .allMatches(iconDataFile.readAsStringSync())
      .map((match) => match.group(1)!)
      .toList(growable: false);
  final colors = colorPattern
      .allMatches(iconColorFile.readAsStringSync())
      .map((match) => match.group(1)!)
      .toSet();

  final output = StringBuffer()
    ..writeln("part of 'service_icon_matcher.dart';")
    ..writeln()
    ..writeln('// GENERATED FILE. DO NOT EDIT.')
    ..writeln('// Run: dart run tool/generate_service_icon_catalog.dart')
    ..writeln('const _serviceIconCatalog = <String, ServiceIconMatch>{');
  for (final field in fields) {
    final color = colors.contains(field)
        ? 'SimpleIconColors.$field'
        : 'Color(0xff455a64)';
    output
      ..writeln("  '${field.toLowerCase()}': ServiceIconMatch(")
      ..writeln('    icon: SimpleIcons.$field,')
      ..writeln('    colour: $color,')
      ..writeln('  ),');
  }
  output.writeln('};');

  final outputFile = File(
    '${projectDirectory.path}${Platform.pathSeparator}lib'
    '${Platform.pathSeparator}src${Platform.pathSeparator}services'
    '${Platform.pathSeparator}service_icon_catalog.g.dart',
  );
  outputFile.writeAsStringSync(output.toString());
  stdout.writeln('Generated ${fields.length} service icons.');
}
