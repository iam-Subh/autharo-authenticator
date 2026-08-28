import 'dart:convert';

import 'package:flutter/services.dart';

/// Calls Android Credential Manager with server-generated WebAuthn JSON.
///
/// This service does not validate responses. A relying-party server must
/// validate the challenge, origin, relying-party identifier, signature, and
/// signature counter before the app uses a result.
class PasskeyRegistrationResponse {
  const PasskeyRegistrationResponse({
    required this.credentialJson,
    required this.prfSupported,
  });

  final String credentialJson;
  final bool prfSupported;
}

class PasskeyAuthenticationResponse {
  const PasskeyAuthenticationResponse({
    required this.credentialJson,
    required this.prfResult,
  });

  /// WebAuthn response with the PRF secret removed.
  final String credentialJson;

  /// Credential-specific 32-byte secret. Keep this on the device.
  final Uint8List? prfResult;
}

class PasskeyService {
  static const _channel = MethodChannel('app.autharo.authenticator/passkey');

  Future<PasskeyRegistrationResponse> create(String requestJson) async {
    final response = await _channel.invokeMethod<String>('create', {
      'requestJson': requestJson,
    });
    if (response == null || response.isEmpty) {
      throw const FormatException('Credential Manager returned no response.');
    }
    final value = _object(response);
    final extensions = _extensions(value);
    final prf = extensions?['prf'];
    final supported = prf is Map && prf['enabled'] == true;
    return PasskeyRegistrationResponse(
      credentialJson: jsonEncode(value),
      prfSupported: supported,
    );
  }

  Future<PasskeyAuthenticationResponse> get(String requestJson) async {
    final response = await _channel.invokeMethod<String>('get', {
      'requestJson': requestJson,
    });
    if (response == null || response.isEmpty) {
      throw const FormatException('Credential Manager returned no response.');
    }
    final value = _object(response);
    final extensions = _extensions(value);
    final prf = extensions?['prf'];
    Uint8List? prfResult;
    if (prf is Map) {
      final results = prf['results'];
      if (results is Map && results['first'] is String) {
        prfResult = _decodeBase64Url(results['first'] as String);
        if (prfResult.length != 32) {
          throw const FormatException(
            'Credential Manager returned an invalid PRF result.',
          );
        }
      }
      // The PRF result can unwrap the vault key. Never send it to the server.
      prf.remove('results');
    }
    return PasskeyAuthenticationResponse(
      credentialJson: jsonEncode(value),
      prfResult: prfResult,
    );
  }

  static Map<String, dynamic> _object(String source) {
    final decoded = jsonDecode(source);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('Credential Manager returned invalid JSON.');
    }
    return decoded;
  }

  static Map<String, dynamic>? _extensions(Map<String, dynamic> value) {
    final extensions = value['clientExtensionResults'] ?? value['extensions'];
    return extensions is Map<String, dynamic> ? extensions : null;
  }

  static Uint8List _decodeBase64Url(String encoded) {
    return Uint8List.fromList(base64Url.decode(base64Url.normalize(encoded)));
  }
}
