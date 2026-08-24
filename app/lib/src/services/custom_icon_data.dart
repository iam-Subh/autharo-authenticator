import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;

/// Stores a small user image inside the encrypted entry `icon` field.
///
/// The entry already passes through vault encryption, synchronization, and
/// backup. Keeping the image in that field prevents a second unencrypted file
/// store and prevents an image from becoming detached from its entry.
enum CustomIconProblem { empty, tooLarge, cannotFit }

class CustomIconException implements Exception {
  const CustomIconException(this.problem);

  final CustomIconProblem problem;
}

class CustomIconData {
  CustomIconData._();

  static const prefix = 'data:image/png;base64,';
  static const maxInputBytes = 5 * 1024 * 1024;

  // The full entry has a 3 KiB plaintext limit. This leaves room for the OTP
  // fields, note, tags, and JSON escaping.
  static const maxStoredCharacters = 1900;

  static bool isCustom(String? value) => value?.startsWith(prefix) ?? false;

  static Uint8List? decode(String? value) {
    if (!isCustom(value) || value!.length > maxStoredCharacters) return null;
    try {
      final bytes = base64Decode(value.substring(prefix.length));
      return bytes.isEmpty ? null : bytes;
    } on FormatException {
      return null;
    }
  }

  static Future<String> encode(Uint8List input) async {
    if (input.isEmpty) {
      throw const CustomIconException(CustomIconProblem.empty);
    }
    if (input.length > maxInputBytes) {
      throw const CustomIconException(CustomIconProblem.tooLarge);
    }

    for (final size in const [48, 40, 32, 24, 16]) {
      final codec = await ui.instantiateImageCodec(
        input,
        targetWidth: size,
        targetHeight: size,
        allowUpscaling: false,
      );
      try {
        final frame = await codec.getNextFrame();
        try {
          final data = await frame.image.toByteData(
            format: ui.ImageByteFormat.png,
          );
          if (data == null) continue;
          final encoded = '$prefix${base64Encode(data.buffer.asUint8List())}';
          if (encoded.length <= maxStoredCharacters) return encoded;
        } finally {
          frame.image.dispose();
        }
      } finally {
        codec.dispose();
      }
    }

    throw const CustomIconException(CustomIconProblem.cannotFit);
  }
}
