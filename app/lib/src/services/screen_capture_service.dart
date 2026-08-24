import 'package:flutter/services.dart';

/// Controls Android's screenshot and screen-recording protection.
///
/// Android stores the choice and applies it before Flutter draws the first
/// frame. This service only reads or changes that native setting.
class ScreenCaptureService {
  ScreenCaptureService({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel(_channelName);

  static const _channelName = 'dev.authcore.authenticator/screen_capture';

  final MethodChannel _channel;

  /// Returns true when Android blocks screenshots and screen recording.
  Future<bool> isBlocked() async {
    final blocked = await _channel.invokeMethod<bool>('isBlocked');
    return blocked ?? true;
  }

  /// Applies and stores the screenshot policy.
  Future<void> setBlocked(bool blocked) => _channel.invokeMethod<void>(
    'setBlocked',
    <String, Object>{'blocked': blocked},
  );
}
