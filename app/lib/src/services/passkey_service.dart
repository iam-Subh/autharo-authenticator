import 'package:flutter/services.dart';

/// Calls Android Credential Manager with server-generated WebAuthn JSON.
///
/// This service does not validate responses. A relying-party server must
/// validate the challenge, origin, relying-party identifier, signature, and
/// signature counter before the app uses a result.
class PasskeyService {
  static const _channel = MethodChannel('dev.authcore.authenticator/passkey');

  Future<String> create(String requestJson) async {
    final response = await _channel.invokeMethod<String>('create', {
      'requestJson': requestJson,
    });
    if (response == null || response.isEmpty) {
      throw const FormatException('Credential Manager returned no response.');
    }
    return response;
  }

  Future<String> get(String requestJson) async {
    final response = await _channel.invokeMethod<String>('get', {
      'requestJson': requestJson,
    });
    if (response == null || response.isEmpty) {
      throw const FormatException('Credential Manager returned no response.');
    }
    return response;
  }
}
