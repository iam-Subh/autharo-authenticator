import 'package:flutter/services.dart';

/// Dart's half of the device slot (PRD section 9.2.4).
///
/// The wrapping key is a non-exportable Android Keystore key, so wrapping and
/// unwrapping happen in Kotlin. This class is the channel to it, and nothing
/// more — it holds no key material between calls.
///
/// # The exposure this creates
///
/// The vault key passes through Dart in the clear, once at setup and once at
/// each unlock. That is unavoidable with a non-exportable keystore key: the
/// wrap has to run in platform code, and the record cipher has to run in Rust,
/// so the key has to cross between them.
///
/// [wipe] overwrites the buffers this side owns as soon as they have been
/// handed on. It is a real reduction in the window, not a guarantee: Dart is
/// garbage collected, and the runtime may have copied a `Uint8List` before we
/// overwrite it. There is no way to do better without moving the keystore call
/// into Rust over JNI, which is recorded as a known gap in README.md.
class VaultKeystore {
  static const MethodChannel _channel =
      MethodChannel('dev.authcore.authenticator/keystore');

  /// True when this device already holds a wrapping key.
  Future<bool> hasKey() async {
    final result = await _channel.invokeMethod<bool>('hasKey');
    return result ?? false;
  }

  /// Wraps [plaintext] with the device's keystore key, creating it if needed.
  ///
  /// [requireUserAuthentication] binds the key to a biometric or device
  /// credential check, so that unwrapping cannot happen without the user
  /// present (FR-31, FR-32).
  ///
  /// The caller keeps ownership of [plaintext] and must [wipe] it afterwards;
  /// this method cannot do that safely because it does not know whether the
  /// caller still needs it.
  Future<WrappedKey> wrap(
    Uint8List plaintext, {
    required bool requireUserAuthentication,
  }) async {
    final result = await _channel.invokeMapMethod<String, Object?>('wrap', {
      'plaintext': plaintext,
      'requireUserAuthentication': requireUserAuthentication,
    });

    if (result == null) {
      throw StateError('The keystore returned nothing when wrapping the key.');
    }
    return WrappedKey(
      ciphertext: result['ciphertext']! as Uint8List,
      nonce: result['nonce']! as Uint8List,
    );
  }

  /// Unwraps what [wrap] produced.
  ///
  /// Throws if the key is gone — cleared app data, a reinstall, or on some
  /// devices a removed screen lock. That is not recoverable for a local-only
  /// vault, and the caller must say so rather than presenting an empty list.
  Future<Uint8List> unwrap(WrappedKey wrapped) async {
    final result = await _channel.invokeMethod<Uint8List>('unwrap', {
      'ciphertext': wrapped.ciphertext,
      'nonce': wrapped.nonce,
    });

    if (result == null || result.isEmpty) {
      throw StateError(
        'The keystore returned no key material. Refusing to continue: an '
        'empty key would make every entry fail to decrypt.',
      );
    }

    // Copied deliberately. The buffer the platform channel hands back is
    // unmodifiable, so it cannot be wiped; returning a copy at least gives the
    // caller something it owns and can overwrite. The channel's own buffer
    // stays until the garbage collector takes it — see the class note.
    return Uint8List.fromList(result);
  }

  /// Destroys the wrapping key (section 9.2.4, **Wipe this device**).
  Future<void> deleteKey() => _channel.invokeMethod<void>('deleteKey');

  /// Overwrites a buffer that held key material.
  ///
  /// Returns false when the buffer could not be overwritten, which happens for
  /// the unmodifiable views a platform channel returns. Callers should not
  /// treat that as fatal — the key is already where it needs to be — but it is
  /// reported rather than swallowed, because a wipe that silently does nothing
  /// is worse than no wipe at all: it reads as a guarantee that is not there.
  ///
  /// See the class documentation for what this does and does not achieve.
  static bool wipe(Uint8List buffer) {
    try {
      buffer.fillRange(0, buffer.length, 0);
      return true;
    } on UnsupportedError {
      return false;
    }
  }
}

/// A vault key as it sits in `meta.db`: ciphertext plus the nonce to open it.
class WrappedKey {
  const WrappedKey({required this.ciphertext, required this.nonce});

  final Uint8List ciphertext;
  final Uint8List nonce;
}
