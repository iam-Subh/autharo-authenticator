import 'dart:convert';

import 'package:authenticator/src/services/custom_icon_data.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('custom icon data accepts only the bounded PNG form', () {
    final value = '${CustomIconData.prefix}${base64Encode([1, 2, 3])}';

    expect(CustomIconData.isCustom(value), isTrue);
    expect(CustomIconData.decode(value), [1, 2, 3]);
    expect(CustomIconData.decode('🙂'), isNull);
    expect(CustomIconData.decode('${CustomIconData.prefix}%%%'), isNull);
  });

  test('custom icon data rejects oversized stored values before decoding', () {
    final value =
        '${CustomIconData.prefix}'
        '${List.filled(CustomIconData.maxStoredCharacters, 'A').join()}';
    expect(CustomIconData.decode(value), isNull);
  });
}
