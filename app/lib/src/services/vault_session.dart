import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';

import '../rust/api/vault.dart' as rust;
import 'appearance_preference.dart';
import 'automatic_backup_service.dart';
import 'brand_icon_preference.dart';
import 'code_visibility_preference.dart';
import 'home_widget_service.dart';
import 'lock_controller.dart';
import 'recovery_status_preference.dart';
import 'screen_capture_service.dart';
import 'vault_keystore.dart';

/// Opens, locks, and wipes the vault (PRD section 9.2.4).
///
/// Three parties are involved and none of them can do the job alone: Rust owns
/// the vault key and the records, the Android Keystore owns the wrapping key
/// and will not release it, and Dart coordinates both sides with non-secret
/// handles. Rust and Kotlin exchange vault-key bytes directly through JNI.
class VaultSession implements LockTarget, LockPolicyStore {
  VaultSession({VaultKeystore? keystore})
    : _keystore = keystore ?? VaultKeystore();

  final VaultKeystore _keystore;

  String? _vaultPath;

  /// True when [load] found and deleted a stage S2 plaintext database. The
  /// user's development entries are gone, and the interface should say so
  /// rather than present an empty list as normal.
  bool discardedLegacyVault = false;

  /// Whether the vault has been unlocked since the application started.
  @override
  bool get isOpen => rust.isVaultOpen();

  /// Prepares the metadata file and reports what this device needs next.
  ///
  /// The metadata file is unencrypted and opens without a key, which is the
  /// whole reason section 12.1 keeps it separate: it holds the wrapped key
  /// that the vault file needs.
  Future<VaultState> load() async {
    final directory = await getApplicationSupportDirectory();
    _vaultPath = '${directory.path}/vault.db';
    final metaPath = '${directory.path}/meta.db';

    // A stage S2 database stored payloads in plaintext and cannot be read by
    // this build. It is discarded rather than migrated — see the note on
    // discardLegacyVault — and this must happen before anything opens it.
    discardedLegacyVault = rust.discardLegacyVault(
      vaultPath: _vaultPath!,
      metaPath: metaPath,
    );

    final state = rust.openMeta(metaPath: metaPath);
    if (rust.wipeCleanupRequired()) {
      await _completePlatformWipe();
      return VaultState.needsSetup;
    }
    await _retireObsoleteKeystoreKeys();
    return switch (state) {
      'absent' => VaultState.needsSetup,
      'present' => VaultState.locked,
      'present_needs_pin' => VaultState.lockedNeedsPin,
      _ => throw StateError('The core reported an unknown slot state: $state'),
    };
  }

  /// First run: generates the vault key, has the keystore wrap it, and opens
  /// the vault (section 9.2.4 steps 1 to 3).
  ///
  /// [requireUserAuthentication] makes the keystore key usable only after a
  /// biometric or device credential check.
  Future<void> setUp({required bool requireUserAuthentication}) async {
    final handle = await rust.beginDeviceSetup();
    await _wrapHandleAndFinish(handle, requireUserAuthentication);
  }

  /// First run behind a PIN (section 9.2.4 step 4).
  ///
  /// Dart receives a handle for the PIN-sealed value, not the value itself.
  Future<void> setUpWithPin(
    String pin, {
    required bool requireUserAuthentication,
  }) async {
    final handle = await rust.beginDeviceSetupWithPin(pin: pin);
    await _wrapHandleAndFinish(handle, requireUserAuthentication);
  }

  /// Turns the PIN on, changes it, or removes it. The vault must be unlocked.
  ///
  /// Passing null removes the PIN. The vault key does not change, so no record
  /// is re-encrypted.
  Future<void> changePin(
    String? newPin, {
    required bool requireUserAuthentication,
  }) async {
    final handle = await rust.beginChangePin(newPin: newPin);
    // The PIN slot stays independently usable. Biometric unlock has its own
    // Keystore slot around the raw vault key, so either route can open the
    // same vault without depending on the other.
    if (requireUserAuthentication && !hasBiometricUnlock) {
      await _enableBiometricUnlock();
    }
    await _wrapHandleAndFinish(handle, false);
    if (!requireUserAuthentication) {
      await rust.clearBiometricKey();
      await _retireObsoleteKeystoreKeys();
    }
  }

  /// True when the locked screen can offer biometric unlock instead of a PIN.
  bool get hasBiometricUnlock {
    try {
      return rust.biometricKeyBlob() != null;
    } catch (_) {
      return false;
    }
  }

  Future<void> _enableBiometricUnlock() async {
    final handle = await rust.beginBiometricSetup();
    final wrapped = await _keystore.wrapHandle(
      handle,
      requireUserAuthentication: true,
    );
    await rust.finishBiometricSetup(
      wrapped: wrapped.ciphertext,
      nonce: wrapped.nonce,
    );
    await _retireObsoleteKeystoreKeys();
  }

  /// Opens the biometric slot. This path does not read or submit the PIN.
  Future<void> unlockWithBiometrics() async {
    final blob = rust.biometricKeyBlob();
    if (blob == null) {
      throw StateError('Biometric unlock is not enabled for this vault.');
    }

    final handle = await _keystore.unwrapToHandle(
      WrappedKey(
        ciphertext: Uint8List.fromList(blob.wrapped),
        nonce: Uint8List.fromList(blob.nonce),
      ),
    );
    await rust.finishBiometricOpen(
      vaultPath: _requirePath(),
      unwrapped: handle,
    );
  }

  /// True when this device has password and recovery slots for an account.
  bool get hasAccountRecovery {
    try {
      return rust.accountEmail() != null;
    } catch (_) {
      return false;
    }
  }

  /// Opens the local vault through its account password slot.
  Future<void> unlockWithAccountPassword(String password) =>
      rust.unlockWithPassword(vaultPath: _requirePath(), password: password);

  /// Opens the local vault through its 24-word recovery slot.
  Future<void> unlockWithRecoveryPhrase(String phrase) =>
      rust.unlockWithRecovery(vaultPath: _requirePath(), phrase: phrase);

  Future<void> _wrapHandleAndFinish(Uint8List handle, bool requireAuth) async {
    final wrapped = await _keystore.wrapHandle(
      handle,
      requireUserAuthentication: requireAuth,
    );
    await rust.finishDeviceSetup(
      vaultPath: _requirePath(),
      wrapped: wrapped.ciphertext,
      nonce: wrapped.nonce,
    );
    await _retireObsoleteKeystoreKeys();
  }

  Future<void> _retireObsoleteKeystoreKeys() async {
    final active = rust
        .activeKeystoreCiphertexts()
        .map(Uint8List.fromList)
        .toList(growable: false);
    await _keystore.retainOnly(active);
  }

  /// What this device's slot looks like, without attempting to open it.
  ///
  /// Lets the unlock screen decide what to offer before the user touches
  /// anything — a PIN-sealed slot cannot be opened by a fingerprint, and
  /// offering the button anyway spends FR-35 attempts on a route that could
  /// never work.
  Future<rust.WrappedKeyBlob> slotDescription() => rust.beginDeviceOpen();

  /// Unlocks through a one-time handle. The vault key does not enter Dart.
  ///
  /// [pin] is required when the slot was written with one, and rejected when
  /// it was not — the core reports the mismatch rather than guessing.
  Future<void> unlock({String? pin}) async {
    final path = _requirePath();
    final blob = await rust.beginDeviceOpen();
    if (blob.needsPin && (pin == null || pin.isEmpty)) {
      throw StateError('This vault needs a PIN to open.');
    }

    final handle = await _keystore.unwrapToHandle(
      WrappedKey(
        ciphertext: Uint8List.fromList(blob.wrapped),
        nonce: Uint8List.fromList(blob.nonce),
      ),
    );
    try {
      if (blob.needsPin) {
        await rust.finishDeviceOpenWithPin(
          vaultPath: path,
          unwrapped: handle,
          pin: pin!,
        );
      } else {
        await rust.finishDeviceOpen(vaultPath: path, unwrapped: handle);
      }
    } catch (_) {
      if (rust.wipeCleanupRequired()) {
        await _completePlatformWipe();
      }
      rethrow;
    }
  }

  /// The resolved vault file path. [load] must run first.
  String get vaultPath => _requirePath();

  /// FR-35: consecutive failed unlock attempts.
  int get failedAttempts => rust.failedUnlockAttempts();

  /// FR-33a: the lock policy lives in the unencrypted metadata file, so it can
  /// be read before the vault opens. [load] must run first.
  @override
  Future<LockPolicy> loadPolicy() async {
    final stored = rust.lockPolicy();
    return LockPolicy(
      timeout: LockTimeout.fromSeconds(stored.timeoutSeconds),
      lockOnBackground: stored.lockOnBackground,
      wipeAfterFailures: stored.wipeAfterFailures,
    );
  }

  @override
  Future<void> savePolicy(LockPolicy policy) => rust.setLockPolicy(
    timeoutSeconds: policy.timeout.seconds,
    lockOnBackground: policy.lockOnBackground,
    wipeAfterFailures: policy.wipeAfterFailures,
  );

  /// FR-31: locking zeroes the vault key. The records become unreadable until
  /// the keystore unwraps the slot again.
  @override
  void lock() => rust.lockVault();

  /// Section 9.2.4, **Wipe this device**.
  ///
  /// The records go first and the keystore key last. In that order a failure
  /// part way through leaves a device whose key still exists but whose records
  /// are gone, which is recoverable; the reverse leaves unreadable ciphertext
  /// on disk forever.
  Future<void> wipe() async {
    await rust.wipeDevice();
    await _completePlatformWipe();
  }

  Future<void> _completePlatformWipe() async {
    await _keystore.deleteKey();
    final vaultPath = _requirePath();
    for (final suffix in const ['', '-wal', '-shm', '-journal']) {
      final file = File('$vaultPath$suffix');
      if (await file.exists()) await file.delete();
    }
    await AutomaticBackupService.clearDeviceState();
    await HomeWidgetService.clearDeviceState();
    await ScreenCaptureService().resetAfterWipe();
    await const FlutterSecureStorage().deleteAll();
    await RecoveryStatusPreference.clear();
    AppearancePreference.resetAfterWipe();
    CodeVisibilityPreference.resetAfterWipe();
    BrandIconPreference.enabled.value = false;
    await rust.finishWipeCleanup();
  }

  String _requirePath() {
    final path = _vaultPath;
    if (path == null) {
      throw StateError('load() must run before the vault can be opened.');
    }
    return path;
  }
}

/// What the application must do before it can show any codes.
enum VaultState {
  /// No device slot exists. First run.
  needsSetup,

  /// A slot exists and the keystore can open it.
  locked,

  /// A slot exists and needs the user's PIN as well (section 9.2.4 step 4).
  lockedNeedsPin,
}
