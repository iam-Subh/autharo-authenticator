import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../rust/api/vault.dart' as rust;

class MissingAutomaticBackupPassphrase implements Exception {
  const MissingAutomaticBackupPassphrase();
}

class AutomaticBackupStatus {
  const AutomaticBackupStatus({
    required this.enabled,
    required this.available,
    this.location,
    this.lastBackup,
  });

  final bool enabled;
  final bool available;
  final String? location;
  final DateTime? lastBackup;
}

/// Creates encrypted backups in a directory selected through Android's
/// Storage Access Framework. The app keeps the newest seven files.
class AutomaticBackupService {
  static const _channel = MethodChannel(
    'dev.authcore.authenticator/automatic_backup',
  );
  static const _storage = FlutterSecureStorage();
  static const _enabledKey = 'automatic_backup.enabled';
  static const _passphraseKey = 'automatic_backup.passphrase';
  static const _lastBackupKey = 'automatic_backup.last_ms';
  static const _minimumInterval = Duration(hours: 24);
  static const _changeDelay = Duration(seconds: 30);

  Timer? _pending;
  bool _running = false;

  Future<AutomaticBackupStatus> status() async {
    final enabled = await _storage.read(key: _enabledKey) == 'true';
    final lastText = await _storage.read(key: _lastBackupKey);
    DateTime? lastBackup;
    final lastMs = int.tryParse(lastText ?? '');
    if (lastMs != null) {
      lastBackup = DateTime.fromMillisecondsSinceEpoch(lastMs);
    }

    try {
      final raw = await _channel.invokeMapMethod<String, Object?>('status');
      return AutomaticBackupStatus(
        enabled: enabled && raw?['configured'] == true,
        available: true,
        location: raw?['location'] as String?,
        lastBackup: lastBackup,
      );
    } on MissingPluginException {
      return AutomaticBackupStatus(
        enabled: false,
        available: false,
        lastBackup: lastBackup,
      );
    }
  }

  Future<bool> enable(String passphrase) async {
    final location = await _channel.invokeMethod<String>('chooseDirectory');
    if (location == null) return false;

    await _storage.write(key: _passphraseKey, value: passphrase);
    await _storage.write(key: _enabledKey, value: 'true');
    await backupNow();
    return true;
  }

  Future<bool> changeDirectory() async {
    final location = await _channel.invokeMethod<String>('chooseDirectory');
    if (location == null) return false;
    await backupNow();
    return true;
  }

  Future<void> disable() async {
    _pending?.cancel();
    _pending = null;
    await _storage.delete(key: _enabledKey);
    await _storage.delete(key: _passphraseKey);
    await _storage.delete(key: _lastBackupKey);
    await _channel.invokeMethod<void>('clearDirectory');
  }

  Future<bool> runIfDue() async {
    final current = await status();
    if (!current.enabled) return false;
    final last = current.lastBackup;
    if (last != null && DateTime.now().difference(last) < _minimumInterval) {
      return false;
    }
    await backupNow();
    return true;
  }

  void scheduleAfterChange() {
    _pending?.cancel();
    _pending = Timer(_changeDelay, () async {
      try {
        final current = await status();
        if (current.enabled) await backupNow();
      } catch (_) {
        // A later change or unlock tries again. Background backup failure must
        // not interrupt an entry edit.
      }
    });
  }

  Future<void> backupNow() async {
    if (_running) return;
    _running = true;
    try {
      final passphrase = await _storage.read(key: _passphraseKey);
      if (passphrase == null || passphrase.isEmpty) {
        throw const MissingAutomaticBackupPassphrase();
      }

      final text = await rust.exportBackup(passphrase: passphrase);
      final now = DateTime.now();
      final stamp = _fileStamp(now);
      await _channel.invokeMethod<void>('writeBackup', {
        'name': 'authenticator-auto-$stamp.json',
        'text': text,
        'keep': 7,
      });
      await _storage.write(
        key: _lastBackupKey,
        value: now.millisecondsSinceEpoch.toString(),
      );
    } finally {
      _running = false;
    }
  }

  static String _fileStamp(DateTime value) {
    String two(int part) => part.toString().padLeft(2, '0');
    return '${value.year}-${two(value.month)}-${two(value.day)}-'
        '${two(value.hour)}${two(value.minute)}${two(value.second)}';
  }

  void dispose() {
    _pending?.cancel();
    _pending = null;
  }
}
