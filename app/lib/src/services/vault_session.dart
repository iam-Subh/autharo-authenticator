import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import '../rust/api/vault.dart' as rust;
import 'vault_keystore.dart';

/// Opens, locks, and wipes the vault (PRD section 9.2.4).
///
/// Three parties are involved and none of them can do the job alone: Rust owns
/// the vault key and the records, the Android Keystore owns the wrapping key
/// and will not release it, and Dart is the only place that can talk to both.
/// This class is that conversation, kept in one file so the handful of moments
/// where raw key material exists are all visible together.
class VaultSession {
  VaultSession({VaultKeystore? keystore})
      : _keystore = keystore ?? VaultKeystore();

  final VaultKeystore _keystore;

  String? _vaultPath;

  /// True when [load] found and deleted a stage S2 plaintext database. The
  /// user's development entries are gone, and the interface should say so
  /// rather than present an empty list as normal.
  bool discardedLegacyVault = false;

  /// Whether the vault has been unlocked since the application started.
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
    final path = _requirePath();

    // The one moment a new vault key exists outside Rust.
    final key = Uint8List.fromList(await rust.beginDeviceSetup());
    try {
      final wrapped = await _keystore.wrap(
        key,
        requireUserAuthentication: requireUserAuthentication,
      );
      await rust.finishDeviceSetup(
        vaultPath: path,
        wrapped: wrapped.ciphertext,
        nonce: wrapped.nonce,
        // The PIN-derived second factor is not built yet; see README.md.
        withPin: false,
      );
    } finally {
      VaultKeystore.wipe(key);
    }
  }

  /// Unlocks: has the keystore unwrap the stored key and hands it to Rust.
  Future<void> unlock() async {
    final path = _requirePath();
    final blob = await rust.beginDeviceOpen();

    final unwrapped = await _keystore.unwrap(
      WrappedKey(
        ciphertext: Uint8List.fromList(blob.wrapped),
        nonce: Uint8List.fromList(blob.nonce),
      ),
    );
    try {
      await rust.finishDeviceOpen(vaultPath: path, unwrapped: unwrapped);
    } finally {
      VaultKeystore.wipe(unwrapped);
    }
  }

  /// FR-31: locking zeroes the vault key. The records become unreadable until
  /// the keystore unwraps the slot again.
  void lock() => rust.lockVault();

  /// Section 9.2.4, **Wipe this device**.
  ///
  /// The records go first and the keystore key last. In that order a failure
  /// part way through leaves a device whose key still exists but whose records
  /// are gone, which is recoverable; the reverse leaves unreadable ciphertext
  /// on disk forever.
  Future<void> wipe() async {
    await rust.wipeDevice();
    await _keystore.deleteKey();
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
