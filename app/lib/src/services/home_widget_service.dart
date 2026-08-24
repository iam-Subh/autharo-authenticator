import 'package:flutter/services.dart';

class HomeWidgetStatus {
  const HomeWidgetStatus({required this.enabled, this.entryId, this.title});

  final bool enabled;
  final String? entryId;
  final String? title;
}

/// Configures the Android launcher widget.
///
/// The platform receives only an entry identifier and a display label. It
/// never receives an OTP secret or code.
class HomeWidgetService {
  static const _channel = MethodChannel(
    'dev.authcore.authenticator/home_widget',
  );

  Future<HomeWidgetStatus> status() async {
    final value = await _channel.invokeMapMethod<String, Object?>('status');
    return HomeWidgetStatus(
      enabled: value?['enabled'] == true,
      entryId: value?['entryId'] as String?,
      title: value?['title'] as String?,
    );
  }

  Future<void> configure({
    required bool enabled,
    String? entryId,
    String? title,
  }) {
    return _channel.invokeMethod<void>('configure', {
      'enabled': enabled,
      'entryId': entryId,
      'title': title,
    });
  }
}
