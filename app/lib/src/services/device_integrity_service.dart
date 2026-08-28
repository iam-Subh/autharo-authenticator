import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

enum RootPolicy { ignore, warn, block }

class DeviceIntegrityResult {
  const DeviceIntegrityResult({
    required this.evaluated,
    required this.indicators,
  });

  final bool evaluated;
  final List<String> indicators;
  bool get indicatorsDetected => indicators.isNotEmpty;

  static const unsupported = DeviceIntegrityResult(
    evaluated: false,
    indicators: [],
  );
}

class DeviceIntegrityService {
  static const _channel = MethodChannel(
    'app.autharo.authenticator/device_integrity',
  );

  static final policy = ValueNotifier(RootPolicy.warn);
  static final result = ValueNotifier(DeviceIntegrityResult.unsupported);

  static Future<void> load() async {
    if (!Platform.isAndroid) {
      result.value = DeviceIntegrityResult.unsupported;
      return;
    }
    final policyName = await _channel.invokeMethod<String>('getPolicy');
    policy.value = RootPolicy.values.firstWhere(
      (value) => value.name == policyName,
      orElse: () => RootPolicy.warn,
    );
    final raw = await _channel.invokeMapMethod<String, dynamic>('check');
    result.value = DeviceIntegrityResult(
      evaluated: raw?['evaluated'] == true,
      indicators: (raw?['indicators'] as List<Object?>? ?? const [])
          .whereType<String>()
          .toList(growable: false),
    );
  }

  static Future<void> setPolicy(RootPolicy value) async {
    if (Platform.isAndroid) {
      await _channel.invokeMethod<void>('setPolicy', {'policy': value.name});
    }
    policy.value = value;
  }
}
