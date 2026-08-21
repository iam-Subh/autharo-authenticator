import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Guards the local patch to vendored cargokit.
///
/// `app/rust_builder/cargokit/` is third-party code that ships with
/// `flutter_rust_bridge`. Its gradle plugin called `project.exec {}` from
/// inside a task action, which Gradle 9 removed, so every Android build failed.
/// It is patched here to use an injected `ExecOperations`.
///
/// The problem with that patch is that it lives in generated, vendored code.
/// Re-running `flutter_rust_bridge_codegen integrate`, or updating the package,
/// overwrites the directory and silently takes the patch with it — and the
/// symptom is a build failure with a message that says nothing about cargokit.
/// A patch that a regeneration silently reverts is a patch that will be
/// reverted, so this test fails loudly instead.
///
/// If this test fails after a deliberate cargokit update, re-apply the patch
/// rather than deleting the test. README.md describes it under
/// "Vendored cargokit".
void main() {
  final plugin = File('rust_builder/cargokit/gradle/plugin.gradle');

  group('vendored cargokit patch', () {
    test('the plugin file is still where the patch expects it', () {
      expect(
        plugin.existsSync(),
        isTrue,
        reason: 'Expected ${plugin.path}. If cargokit moved, this guard needs '
            'updating along with the patch.',
      );
    });

    test('no call site has reverted to project.exec', () {
      final offenders = <String>[];

      final lines = plugin.readAsLinesSync();
      for (var i = 0; i < lines.length; i++) {
        final line = lines[i];

        // The patch's own comments name `project.exec` when explaining what
        // was replaced, so comment lines are not call sites.
        final code = line.trimLeft();
        if (code.startsWith('//') || code.startsWith('*') || code.startsWith('/*')) {
          continue;
        }

        if (line.contains('project.exec')) {
          offenders.add('  line ${i + 1}: ${line.trim()}');
        }
      }

      expect(
        offenders,
        isEmpty,
        reason: 'project.exec was removed in Gradle 9 and Flutter ships Gradle '
            '9.1, so these call sites will fail every Android build:\n'
            '${offenders.join('\n')}\n'
            'The vendored cargokit patch has been reverted, most likely by '
            'regenerating the bridge. Re-apply it: replace project.exec with '
            'the injected execOperations service.',
      );
    });

    test('the replacement is still in place', () {
      final source = plugin.readAsStringSync();

      expect(
        source,
        contains('ExecOperations'),
        reason: 'The ExecOperations import is gone, so the patch was reverted.',
      );
      expect(
        source,
        contains('execOperations.exec'),
        reason: 'No execOperations call site remains, so the patch was '
            'reverted or the file was rewritten.',
      );
      expect(
        source,
        contains('LOCAL PATCH'),
        reason: 'The marker comment is gone. Without it the next person to '
            'read this file has no way to know it diverges from upstream.',
      );
    });
  });
}
