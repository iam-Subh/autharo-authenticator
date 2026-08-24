import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('visible widget text uses localization resources', () {
    final roots = [Directory('lib/src/pages'), Directory('lib/src/ui')];
    final directText = RegExp(r'''\b(?:const\s+)?Text\(\s*['"][A-Za-z]''');
    final directProperty = RegExp(
      r'''\b(?:labelText|helperText|hintText|tooltip|dialogTitle|actionLabel)\s*:\s*['"][A-Za-z]''',
    );
    final violations = <String>[];

    for (final root in roots) {
      for (final file in root.listSync(recursive: true).whereType<File>()) {
        if (!file.path.endsWith('.dart')) continue;
        final source = file.readAsStringSync();
        if (directText.hasMatch(source) || directProperty.hasMatch(source)) {
          violations.add(file.path);
        }
      }
    }

    expect(
      violations,
      isEmpty,
      reason: 'Move visible strings into app_en.arb and app_hi.arb.',
    );
  });
}
