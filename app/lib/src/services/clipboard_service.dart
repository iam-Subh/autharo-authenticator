import 'dart:async';

import 'package:flutter/services.dart';

/// FR-24: "Copy a code to the clipboard with one action. Clear the clipboard
/// after 30 seconds."
///
/// Two details that are easy to get wrong:
///
/// - The clear must not wipe whatever the user copied in the meantime. The
///   timer therefore reads the clipboard back and only clears it if it still
///   holds the code this service put there.
/// - A second copy inside the window replaces the pending timer rather than
///   adding one, or the first timer would clear the second code early.
///
/// The limit is worth stating plainly: on Android 10 and later other
/// applications cannot read the clipboard unless they are in the foreground,
/// but the system clipboard history and some keyboards still retain it. The
/// clear reduces the window; it does not guarantee the code is gone.
class ClipboardService {
  ClipboardService({this.clearAfter = const Duration(seconds: 30)});

  /// FR-24 fixes this at 30 seconds. It is a constructor argument so tests do
  /// not have to wait that long.
  final Duration clearAfter;

  Timer? _pendingClear;
  String? _lastCopied;

  /// Copies [code] and schedules the clear.
  Future<void> copyCode(String code) async {
    await SensitiveClipboard.copy(code);

    _pendingClear?.cancel();
    _lastCopied = code;
    _pendingClear = Timer(clearAfter, _clearIfUnchanged);
  }

  Future<void> _clearIfUnchanged() async {
    final expected = _lastCopied;
    if (expected == null) return;

    await SensitiveClipboard.clearIfEquals(expected);
    _lastCopied = null;
  }

  /// Clears immediately, for the lock screen and for application exit. A code
  /// left on the clipboard outlives the lock timeout otherwise.
  Future<void> clearNow() async {
    _pendingClear?.cancel();
    _pendingClear = null;
    await _clearIfUnchanged();
  }

  void dispose() {
    _pendingClear?.cancel();
    _pendingClear = null;
  }
}

/// Marks copied secrets as sensitive in the Android clipboard service.
/// Android can then suppress the clipboard preview and reduce history exposure.
class SensitiveClipboard {
  static const MethodChannel _channel = MethodChannel(
    'dev.authcore.authenticator/clipboard',
  );

  static Future<void> copy(String text) =>
      _channel.invokeMethod<void>('copySensitive', {'text': text});

  static Future<void> clearIfEquals(String expected) =>
      _channel.invokeMethod<void>('clearIfEquals', {'expected': expected});
}
