import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';

class FileSizeLimitExceeded implements Exception {
  const FileSizeLimitExceeded(this.maximumBytes);

  final int maximumBytes;
}

/// Reads a selected file without permitting an unbounded memory allocation.
Future<Uint8List> readFileWithLimit(
  PlatformFile file, {
  required int maximumBytes,
}) async {
  if (await file.length() > maximumBytes) {
    throw FileSizeLimitExceeded(maximumBytes);
  }

  final output = BytesBuilder(copy: false);
  var total = 0;
  await for (final chunk in file.readAsByteStream()) {
    total += chunk.length;
    if (total > maximumBytes) {
      throw FileSizeLimitExceeded(maximumBytes);
    }
    output.add(chunk);
  }
  return output.takeBytes();
}
