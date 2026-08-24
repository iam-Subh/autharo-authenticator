import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the generated bridge loads the packaged Rust library', () {
    final bridge = File('lib/src/rust/frb_generated.dart');
    expect(
      bridge.existsSync(),
      isTrue,
      reason: 'The generated bridge is missing.',
    );

    final source = bridge.readAsStringSync();
    expect(
      source,
      contains("stem: 'rust_lib_authenticator'"),
      reason:
          'Android packages librust_lib_authenticator.so. A different '
          'stem makes flutter_rust_bridge load the wrong native library.',
    );
    expect(
      source,
      isNot(contains("stem: 'UNKNOWN'")),
      reason:
          'UNKNOWN is a flutter_rust_bridge fallback. On Android it '
          'attempts to load libUNKNOWN.so and prevents application startup.',
    );
  });
}
