import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'src/pages/entry_list_page.dart';
import 'src/rust/api/vault.dart' as rust;
import 'src/rust/frb_generated.dart';
import 'src/services/reference_time.dart';
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

  Future<VaultController> _open() async {
    final directory = await getApplicationSupportDirectory();
    rust.openVault(dbPath: '${directory.path}/vault.db');

    final time = await ReferenceTime.load();
    final controller = VaultController(time);
    await controller.start();
    return controller;
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
        return EntryListPage(controller: snapshot.data!);
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
