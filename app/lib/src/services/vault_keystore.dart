import 'package:flutter/services.dart';

/// Dart's half of the device slot (PRD section 9.2.4).
///
/// The wrapping key is a non-exportable Android Keystore key, so wrapping and
/// unwrapping happen in Kotlin. This class is the channel to it, and nothing
/// more. Rust and Kotlin transfer protected bytes through JNI. Dart carries
/// only random one-time handles and wrapped ciphertext.
class VaultKeystore {
  static const MethodChannel _channel = MethodChannel(
    'dev.authcore.authenticator/keystore',
  );

  /// True when this device already holds a wrapping key.
  Future<bool> hasKey() async {
    final result = await _channel.invokeMethod<bool>('hasKey');
    return result ?? false;
  }

  /// Wraps the Rust secret selected by [handle] with the device keystore key.
  ///
  /// [requireUserAuthentication] binds the key to a biometric or device
  /// credential check, so that unwrapping cannot happen without the user
  /// present (FR-31, FR-32).
  ///
  /// The handle expires and can be consumed once. It contains no key material.
  Future<WrappedKey> wrapHandle(
    Uint8List handle, {
    required bool requireUserAuthentication,
  }) async {
    final result = await _channel.invokeMapMethod<String, Object?>(
      'wrapHandle',
      {
        'handle': handle,
        'requireUserAuthentication': requireUserAuthentication,
      },
    );

    if (result == null) {
      throw StateError('The keystore returned nothing when wrapping the key.');
    }
    return WrappedKey(
      ciphertext: result['ciphertext']! as Uint8List,
      nonce: result['nonce']! as Uint8List,
    );
  }

  /// Unwraps [wrapped] in Kotlin and stores the result directly in Rust.
  ///
  /// Throws if the key is gone — cleared app data, a reinstall, or on some
  /// devices a removed screen lock. That is not recoverable for a local-only
  /// vault, and the caller must say so rather than presenting an empty list.
  /// Returns a one-time handle. The returned bytes are not the vault key.
  Future<Uint8List> unwrapToHandle(WrappedKey wrapped) async {
    final result = await _channel.invokeMethod<Uint8List>('unwrapToHandle', {
      'ciphertext': wrapped.ciphertext,
      'nonce': wrapped.nonce,
    });

    if (result == null || result.length != 32) {
      throw StateError('The keystore returned an invalid vault-key handle.');
    }
    return result;
  }

  /// Destroys the wrapping key (section 9.2.4, **Wipe this device**).
  Future<void> deleteKey() => _channel.invokeMethod<void>('deleteKey');

  /// Deletes Keystore aliases that no committed slot references.
  Future<void> retainOnly(List<Uint8List> ciphertexts) =>
      _channel.invokeMethod<void>('retainOnly', {'ciphertexts': ciphertexts});
}

/// A vault key as it sits in `meta.db`: ciphertext plus the nonce to open it.
class WrappedKey {
  const WrappedKey({required this.ciphertext, required this.nonce});

  final Uint8List ciphertext;
  final Uint8List nonce;
}
