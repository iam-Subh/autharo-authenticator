import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:firebase_messaging/firebase_messaging.dart';

import 'l10n/generated/app_localizations.dart';
import 'src/pages/entry_list_page.dart';
import 'src/rust/frb_generated.dart';
import 'src/pages/unlock_page.dart';
import 'src/pages/welcome_page.dart';
import 'src/rust/api/vault.dart' as rust;
import 'src/services/lock_controller.dart';
import 'src/services/automatic_backup_service.dart';
import 'src/services/appearance_preference.dart';
import 'src/services/brand_icon_preference.dart';
import 'src/services/code_visibility_preference.dart';
import 'src/services/device_integrity_service.dart';
import 'src/services/monotonic_clock.dart';
import 'src/services/reference_time.dart';
import 'src/services/recovery_status_preference.dart';
import 'src/services/push_notification_service.dart';
import 'src/services/sync_controller.dart';
import 'src/services/sync_scheduler.dart';
import 'src/services/vault_session.dart';
import 'src/vault_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  FirebaseMessaging.onBackgroundMessage(firebaseMessagingBackgroundHandler);
  runApp(const AuthenticatorApp());
}

Future<void> _initializeServices() async {
  try {
    await DeviceIntegrityService.load();
  } catch (_) {
    // A platform check failure does not imply a compromised device. Keep the
    // warning policy and report the check as unavailable.
  }
  await RustLib.init();
  try {
    BrandIconPreference.load();
  } catch (_) {
    // Keep the privacy-safe default if metadata cannot be read.
  }
  try {
    await Future.wait([
      AppearancePreference.load(),
      CodeVisibilityPreference.load(),
      RecoveryStatusPreference.load(),
    ]);
    await AppearancePreference.loadDynamicColour();
  } catch (_) {
    // Keep the local defaults if the preference store cannot be read.
  }
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key, this.initialize = _initializeServices});

  final Future<void> Function() initialize;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([
        AppearancePreference.theme,
        AppearancePreference.useDynamicColour,
        AppearancePreference.dynamicSeed,
        AppearancePreference.language,
      ]),
      builder: (context, _) {
        final themeChoice = AppearancePreference.theme.value;
        final seed = AppearancePreference.activeSeed;
        return MaterialApp(
          onGenerateTitle: (context) => AppLocalizations.of(context).appTitle,
          debugShowCheckedModeBanner: false,
          localizationsDelegates: const [
            AppLocalizations.delegate,
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          supportedLocales: AppLocalizations.supportedLocales,
          locale: AppearancePreference.language.value.locale,
          themeMode: themeChoice.themeMode,
          theme: ThemeData(colorScheme: ColorScheme.fromSeed(seedColor: seed)),
          darkTheme: _darkTheme(
            seed: seed,
            amoled: themeChoice == AppThemeChoice.amoled,
          ),
          home: _InitializationGate(initialize: initialize),
        );
      },
    );
  }

  ThemeData _darkTheme({required Color seed, required bool amoled}) {
    final scheme = ColorScheme.fromSeed(
      seedColor: seed,
      brightness: Brightness.dark,
    );
    if (!amoled) return ThemeData(colorScheme: scheme);
    return ThemeData(
      colorScheme: scheme.copyWith(
        surface: Colors.black,
        surfaceContainer: const Color(0xFF090909),
        surfaceContainerHigh: const Color(0xFF111111),
        surfaceContainerHighest: const Color(0xFF181818),
      ),
      scaffoldBackgroundColor: Colors.black,
      canvasColor: Colors.black,
    );
  }
}

/// Draws one Flutter frame before native library and vault initialization.
///
/// Android keeps the launch screen visible until Flutter submits its first
/// frame. Starting Rust before [runApp] therefore leaves the application logo
/// on screen during dynamic-library loading. This gate replaces the launch
/// screen immediately, then starts initialization after that frame.
class _InitializationGate extends StatefulWidget {
  const _InitializationGate({required this.initialize});

  final Future<void> Function() initialize;

  @override
  State<_InitializationGate> createState() => _InitializationGateState();
}

class _InitializationGateState extends State<_InitializationGate> {
  Future<void>? _initializing;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      final initializing = widget.initialize();
      setState(() {
        _initializing = initializing;
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    final initializing = _initializing;
    if (initializing == null) return const _StartupProgress();

    return FutureBuilder<void>(
      future: initializing,
      builder: (context, snapshot) {
        if (snapshot.hasError) {
          return _StartupFailure(error: snapshot.error!);
        }
        if (snapshot.connectionState != ConnectionState.done) {
          return const _StartupProgress();
        }
        return const _DeviceIntegrityGate(child: _Bootstrap());
      },
    );
  }
}

class _DeviceIntegrityGate extends StatefulWidget {
  const _DeviceIntegrityGate({required this.child});

  final Widget child;

  @override
  State<_DeviceIntegrityGate> createState() => _DeviceIntegrityGateState();
}

class _DeviceIntegrityGateState extends State<_DeviceIntegrityGate> {
  bool _acceptedWarning = false;

  @override
  Widget build(BuildContext context) {
    final check = DeviceIntegrityService.result.value;
    final policy = DeviceIntegrityService.policy.value;
    if (!check.evaluated ||
        !check.indicatorsDetected ||
        policy == RootPolicy.ignore ||
        (policy == RootPolicy.warn && _acceptedWarning)) {
      return widget.child;
    }

    final l10n = AppLocalizations.of(context);
    final blocked = policy == RootPolicy.block;
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Icon(
              Icons.gpp_maybe_outlined,
              size: 48,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(
              l10n.rootDetectedTitle,
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 12),
            Text(
              blocked
                  ? l10n.rootBlockedDescription
                  : l10n.rootWarningDescription,
            ),
            const SizedBox(height: 16),
            for (final indicator in check.indicators)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.warning_amber_outlined),
                title: Text(switch (indicator) {
                  'test_keys' => l10n.rootIndicatorTestKeys,
                  'root_files' => l10n.rootIndicatorRootFiles,
                  _ => l10n.rootIndicatorUnknown,
                }),
              ),
            const SizedBox(height: 16),
            if (!blocked)
              FilledButton(
                onPressed: () => setState(() => _acceptedWarning = true),
                child: Text(l10n.continueLabel),
              ),
            if (blocked) ...[
              FilledButton.tonal(
                onPressed: () async {
                  await DeviceIntegrityService.setPolicy(RootPolicy.warn);
                  if (mounted) setState(() {});
                },
                child: Text(l10n.changeRootPolicyToWarn),
              ),
              const SizedBox(height: 8),
              TextButton(
                onPressed: () async {
                  await DeviceIntegrityService.setPolicy(RootPolicy.ignore);
                  if (mounted) setState(() {});
                },
                child: Text(l10n.ignoreRootWarning),
              ),
            ],
            const SizedBox(height: 12),
            Text(
              l10n.rootDetectionLimit,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

class _StartupProgress extends StatelessWidget {
  const _StartupProgress();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 16),
            Text(AppLocalizations.of(context).openingAuthenticator),
          ],
        ),
      ),
    );
  }
}

/// Opens the vault before the first screen renders.
///
/// Opens the vault before the first frame that shows a code.
///
/// The order is fixed by section 9.2.4: read the metadata file, find out
/// whether this device has a key slot, then either create one or unwrap it.
/// Only then does a vault exist to list entries from.
///
/// The database lives in the application support directory rather than the
/// documents directory: on Android the documents directory is reachable by the
/// file picker, and the vault is not a document the user should be handing to
/// other applications.
class _Bootstrap extends StatefulWidget {
  const _Bootstrap();

  @override
  State<_Bootstrap> createState() => _BootstrapState();
}

class _BootstrapState extends State<_Bootstrap> {
  late final Future<VaultController> _opening = _open();

  /// FR-47: shown once, on a device that has not been past it.
  ///
  /// Read from the core rather than kept in Flutter's preferences, so that
  /// "Wipe this device" genuinely returns the app to its first-run state
  /// instead of one that looks used and holds nothing.
  bool _needsWelcome = false;

  final _session = VaultSession();

  // One scheduler and one controller for the whole application. Per-screen
  // instances would each arm their own fifteen-minute timer, so the number of
  // cycles would depend on how many screens happened to be alive.
  // FR-37: a cycle measures the clock, so the list has to re-read the offset
  // afterwards or the correction waits for the next application start.
  late final _sync = SyncController(
    onCycleComplete: () async {
      final controller = _controller;
      if (controller == null) return;
      await controller.time.refresh();
      await controller.refresh();
    },
  );
  late final _scheduler = SyncScheduler(runner: _sync);
  final _push = PushNotificationService.instance;
  final _automaticBackup = AutomaticBackupService();
  late final _lock = LockController(
    session: _session,
    // FR-33 requires a clock that counts across device sleep; see
    // MonotonicClock for why neither the wall clock nor a Stopwatch will do.
    clock: PlatformMonotonicClock(),
    store: _session,
    onLocked: () => setState(() => _needsUnlock = true),
  );

  /// True when the vault is shut and the unlock screen should be showing.
  /// Distinct from "not yet opened": this is a vault that exists and is locked.
  bool _needsUnlock = false;
  VaultController? _controller;

  @override
  void initState() {
    super.initState();
    _push.configure(onVaultChanged: () async => _scheduler.onPushSignal());
    _lock.start();
  }

  /// Section 10.3's start-of-application trigger, once the vault is actually
  /// open. Starting the scheduler any earlier would have it firing at a core
  /// that has no vault to sync.
  Future<void> _startSync() async {
    await _sync.refresh();
    _scheduler.start();
    await _push.start();
    await _push.refreshRegistration(signedIn: _sync.status.isSignedIn);
  }

  Future<void> _runAutomaticBackupIfDue() async {
    try {
      await _automaticBackup.runIfDue();
    } catch (_) {
      // The Backup screen reports configuration errors. Startup must still
      // open the vault if a directory grant or secure-storage read fails.
    }
  }

  /// FR-33a: the stored policy, read before the vault opens. Without this the
  /// setting would reset at every start, which the requirement calls out as
  /// doing nothing at all.
  /// Never fails startup. A metadata read that goes wrong should cost the
  /// user one extra sight of the welcome screen, not an app that will not open.
  bool _welcomeSeen() {
    try {
      return rust.welcomeSeen();
    } catch (_) {
      return true;
    }
  }

  Future<void> _loadLockPolicy() async {
    try {
      await _lock.loadPolicy();
    } catch (_) {
      // A policy that cannot be read leaves the default in place: a one minute
      // timeout. Failing startup over a settings read would be worse.
    }
  }

  @override
  void dispose() {
    _scheduler.dispose();
    _automaticBackup.dispose();
    _sync.dispose();
    unawaited(_push.dispose());
    _lock.dispose();
    _controller?.dispose();
    super.dispose();
  }

  Future<VaultController> _open() async {
    switch (await _session.load()) {
      case VaultState.needsSetup:
        // First run. The keystore key is created without a biometric
        // requirement: FR-32 makes biometric unlock a choice the user makes,
        // and binding the key before they have made it would lock out a
        // device with no enrolled biometric. A PIN is offered afterwards
        // rather than demanded before the first code can be added.
        await _session.setUp(requireUserAuthentication: false);
      case VaultState.locked:
        await _session.unlock();
      case VaultState.lockedNeedsPin:
        // The unlock screen collects the PIN; nothing opens until it does.
        _needsUnlock = true;
        return _startController();
    }
    return _startController();
  }

  Future<VaultController> _startController() async {
    await _loadLockPolicy();
    // After the vault exists, so the welcome screen's three choices all lead
    // somewhere that works. Asking before setup would mean a user who picks
    // "import" lands on a picker with nowhere to put the entries.
    _needsWelcome = !_welcomeSeen();
    final time = await ReferenceTime.load();
    final controller = VaultController(
      time,
      // Section 10.3's "on a change" trigger, debounced by the scheduler so an
      // import of fifty entries produces one cycle rather than fifty.
      onLocalChange: () {
        _scheduler.onLocalChange();
        _automaticBackup.scheduleAfterChange();
      },
    );
    _controller = controller;
    // FR-22: read before the first list is built, so the first frame is already
    // in the user's order rather than jumping a moment later.
    controller.loadSortMode();
    if (!_needsUnlock) {
      await controller.start();
      await _startSync();
      unawaited(_runAutomaticBackupIfDue());
    }
    return controller;
  }

  Future<void> _afterUnlock(VaultController controller) async {
    setState(() => _needsUnlock = false);
    await controller.start();

    // Section 10.3's unlock trigger. The vault reopens many times in a
    // session, and each reopen is when a user is most likely to be looking at
    // the list and least likely to forgive it being stale.
    await _startSync();
    _scheduler.onUnlocked();
    unawaited(_runAutomaticBackupIfDue());
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<VaultController>(
      future: _opening,
      builder: (context, snapshot) {
        if (snapshot.hasError) {
          return _StartupFailure(error: snapshot.error!);
        }
        if (!snapshot.hasData) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          );
        }
        final controller = snapshot.data!;
        // Ordered deliberately: an unlock is never skipped for a welcome. On a
        // device with a PIN slot the vault is shut, and a first-run screen in
        // front of it would offer three actions that all fail.
        if (_needsUnlock) {
          return UnlockPage(
            session: _session,
            onUnlocked: () => _afterUnlock(controller),
          );
        }
        if (_needsWelcome) {
          return WelcomePage(
            session: _session,
            controller: controller,
            onDone: () => setState(() => _needsWelcome = false),
          );
        }
        return EntryListPage(
          controller: controller,
          session: _session,
          lock: _lock,
        );
      },
    );
  }
}

/// If the vault cannot be opened there is nothing useful to show, so say what
/// happened rather than presenting an empty list that looks like data loss.
class _StartupFailure extends StatelessWidget {
  const _StartupFailure({required this.error});

  final Object error;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              Icons.error_outline,
              size: 40,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(
              AppLocalizations.of(context).vaultOpenFailed,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text('$error', style: Theme.of(context).textTheme.bodyMedium),
            const SizedBox(height: 16),
            Text(AppLocalizations.of(context).vaultDataSafeAfterOpenFailure),
          ],
        ),
      ),
    );
  }
}
