import 'dart:async';
import 'dart:io';

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import '../rust/api/sync.dart' as rust;
import '../rust/frb_generated.dart';

/// Handles a data-only FCM signal when Android starts a background isolate.
///
/// The sync engine reads and writes encrypted records only. It does not open
/// the vault key or generate an OTP code. Android can stop work that exceeds
/// its background execution limit, so one bounded sync cycle runs here.
@pragma('vm:entry-point')
Future<void> firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  if (!PushNotificationService.isVaultChangeSignal(message.data)) return;
  try {
    await Firebase.initializeApp();
    await RustLib.init();
    final directory = await getApplicationSupportDirectory();
    await rust.syncInBackground(
      metaPath: '${directory.path}/meta.db',
      vaultPath: '${directory.path}/vault.db',
    );
  } catch (error) {
    // The foreground status records normal server failures. A missing local
    // account or an incomplete page-key migration is safe to retry after the
    // next unlock.
    debugPrint('Background synchronization did not complete: $error');
  }
}

/// Receives privacy-safe Firebase Cloud Messaging (FCM) change signals.
///
/// A signal contains no vault record, account name, issuer, or one-time code.
/// The normal sync client remains the only source of vault data.
class PushNotificationService {
  PushNotificationService._();

  static final PushNotificationService instance = PushNotificationService._();

  Future<void>? _startFuture;
  bool _available = false;
  String? _registeredToken;
  Future<void> Function()? _onVaultChanged;
  StreamSubscription<RemoteMessage>? _foregroundMessages;
  StreamSubscription<RemoteMessage>? _openedMessages;
  StreamSubscription<String>? _tokenChanges;

  void configure({required Future<void> Function() onVaultChanged}) {
    _onVaultChanged = onVaultChanged;
  }

  /// Initializes FCM when this Android build contains `google-services.json`.
  /// A missing Firebase configuration disables push without blocking startup.
  Future<void> start() => _startFuture ??= _start();

  Future<void> _start() async {
    if (kIsWeb || !Platform.isAndroid) return;
    try {
      await Firebase.initializeApp();
      _available = true;
      _foregroundMessages = FirebaseMessaging.onMessage.listen(_handleMessage);
      _openedMessages = FirebaseMessaging.onMessageOpenedApp.listen(
        _handleMessage,
      );
      _tokenChanges = FirebaseMessaging.instance.onTokenRefresh.listen(
        (token) => unawaited(_register(token)),
      );
      final initialMessage = await FirebaseMessaging.instance
          .getInitialMessage();
      if (initialMessage != null) _handleMessage(initialMessage);
    } catch (error) {
      _available = false;
      debugPrint('Firebase push is not configured: $error');
    }
  }

  /// Registers this Firebase installation after sync sign-in.
  ///
  /// The method does not ask for notification permission on a local-only
  /// device. The server also removes the route during sign-out or revocation.
  Future<void> refreshRegistration({required bool signedIn}) async {
    await start();
    if (!_available) return;
    final messaging = FirebaseMessaging.instance;
    if (!signedIn) {
      _registeredToken = null;
      await messaging.setAutoInitEnabled(false);
      try {
        await messaging.deleteToken();
      } catch (_) {
        // The server removes the route during sign-out. Token deletion is an
        // additional local privacy step and must not block the application.
      }
      return;
    }

    // Data-only vault-change messages do not display a notification. Android
    // notification permission must not control background synchronization.
    await messaging.setAutoInitEnabled(true);
    final token = await messaging.getToken();
    if (token != null) await _register(token);
  }

  Future<void> _register(String token) async {
    if (token.isEmpty || token == _registeredToken) return;
    try {
      await rust.setPushToken(token: token);
      _registeredToken = token;
    } catch (error) {
      // A later sync refresh or FCM token refresh retries registration.
      debugPrint('Could not register the push route: $error');
    }
  }

  void _handleMessage(RemoteMessage message) {
    if (!isVaultChangeSignal(message.data)) return;
    final callback = _onVaultChanged;
    if (callback != null) unawaited(callback());
  }

  @visibleForTesting
  static bool isVaultChangeSignal(Map<String, dynamic> data) {
    return data['type'] == 'vault_changed' && data['schema'] == '1';
  }

  Future<void> dispose() async {
    await _foregroundMessages?.cancel();
    await _openedMessages?.cancel();
    await _tokenChanges?.cancel();
  }
}
