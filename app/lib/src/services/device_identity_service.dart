import 'package:flutter/services.dart';

class DeviceIdentity {
  const DeviceIdentity({required this.name, required this.platform});

  final String name;
  final String platform;
}

/// Reads a user-visible device description from the Android platform.
class DeviceIdentityService {
  static const _channel = MethodChannel(
    'app.autharo.authenticator/device_identity',
  );

  static Future<DeviceIdentity> current() async {
    try {
      final value = await _channel.invokeMapMethod<String, Object?>(
        'description',
      );
      final name = value?['name'] as String?;
      final platform = value?['platform'] as String?;
      return DeviceIdentity(
        name: name?.trim().isNotEmpty == true ? name!.trim() : 'Android device',
        platform: platform?.trim().isNotEmpty == true
            ? platform!.trim()
            : 'android',
      );
    } on MissingPluginException {
      return const DeviceIdentity(name: 'Android device', platform: 'android');
    } on PlatformException {
      return const DeviceIdentity(name: 'Android device', platform: 'android');
    }
  }
}
