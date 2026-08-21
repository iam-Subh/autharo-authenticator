import 'package:flutter/material.dart';

import 'src/pages/entry_list_page.dart';
import 'src/rust/frb_generated.dart';
import 'src/pages/unlock_page.dart';
import 'src/services/lock_controller.dart';
import 'src/services/monotonic_clock.dart';
import 'src/services/reference_time.dart';
import 'src/services/vault_session.dart';
import 'src/vault_controller.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  runApp(const AuthenticatorApp());
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Authenticator',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF3B6EA5)),
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF3B6EA5),
          brightness: Brightness.dark,
        ),
      ),
      home: const _Bootstrap(),
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

  final _session = VaultSession();
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
    _lock.start();
  }

  /// FR-33a: the stored policy, read before the vault opens. Without this the
  /// setting would reset at every start, which the requirement calls out as
  /// doing nothing at all.
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
    final time = await ReferenceTime.load();
    final controller = VaultController(time);
    _controller = controller;
    if (!_needsUnlock) await controller.start();
    return controller;
  }

  Future<void> _afterUnlock(VaultController controller) async {
    setState(() => _needsUnlock = false);
    await controller.start();
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
        if (_needsUnlock) {
          return UnlockPage(
            session: _session,
            onUnlocked: () => _afterUnlock(controller),
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
              'The vault could not be opened',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              '$error',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            const Text(
              'Your entries have not been deleted. Closing and reopening the '
              'application is safe to try.',
            ),
          ],
        ),
      ),
    );
  }
}
