import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../ui/import_report_dialog.dart';
import '../vault_controller.dart';

/// FR-14: importing a Google Authenticator export.
///
/// # Why this is its own screen
///
/// A large vault exports as several QR codes, and every one must be scanned
/// before anything is imported. That makes it a task with progress rather than
/// a single action, and the camera has to stay open across it — which the
/// ordinary scan screen, whose whole job is to return one string and close, is
/// the wrong shape for.
///
/// # The failure this screen exists to prevent
///
/// Importing part two of three looks exactly like success. Entries appear, the
/// user closes the app satisfied, and finds out months later — after the old
/// phone has been wiped — that a third of their accounts never arrived. So the
/// count is on screen the whole time, the import button does not exist until
/// every part is in, and leaving early asks for confirmation.
class ImportMigrationPage extends StatefulWidget {
  const ImportMigrationPage({
    super.key,
    required this.controller,
    required this.firstCode,
  });

  final VaultController controller;

  /// The code that got the user here, so it is not scanned twice.
  final String firstCode;

  @override
  State<ImportMigrationPage> createState() => _ImportMigrationPageState();
}

class _ImportMigrationPageState extends State<ImportMigrationPage> {
  final _scanner = MobileScannerController(
    // Not `noDuplicates`: the user may need to re-point at a code the app
    // missed, and the core already treats a repeat as "already have it".
    detectionSpeed: DetectionSpeed.normal,
    formats: const [BarcodeFormat.qrCode],
  );

  int _remaining = 0;
  int _ready = 0;
  int _refused = 0;
  bool _started = false;
  bool _busy = false;
  String? _message;

  @override
  void initState() {
    super.initState();
    _consume(widget.firstCode);
  }

  @override
  void dispose() {
    _scanner.dispose();
    // An abandoned scan must not bleed into the next one. Without this, a user
    // who backs out halfway and starts again finds the app waiting for parts
    // of an export they are no longer holding.
    rust.migrationReset();
    super.dispose();
  }

  Future<void> _consume(String uri) async {
    if (_busy) return;
    setState(() => _busy = true);

    try {
      final scan = await rust.migrationScan(uri: uri);
      if (!mounted) return;

      setState(() {
        _started = true;
        _remaining = scan.remaining;
        _ready = scan.ready;
        _refused = scan.refused;
        _message = switch (true) {
          _ when scan.differentExport => AppLocalizations.of(
            context,
          ).wrongExportPart,
          _ when scan.alreadySeen => AppLocalizations.of(
            context,
          ).migrationCodeAlreadyScanned,
          _ => null,
        };
      });
    } catch (error) {
      if (mounted) setState(() => _message = '$error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _onDetect(BarcodeCapture capture) {
    for (final barcode in capture.barcodes) {
      final value = barcode.rawValue?.trim();
      if (value == null) continue;
      if (value.toLowerCase().startsWith('otpauth-migration://')) {
        _consume(value);
        return;
      }
    }
  }

  Future<void> _import() async {
    setState(() => _busy = true);
    try {
      final report = await rust.migrationFinish(
        nowMs: DateTime.now().millisecondsSinceEpoch,
      );
      await widget.controller.refresh();
      if (!mounted) return;

      await showDialog<void>(
        context: context,
        builder: (context) => ImportReportDialog(report: report),
      );
      if (mounted) Navigator.of(context).pop();
    } catch (error) {
      if (mounted) setState(() => _message = '$error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Leaving with parts outstanding throws the scan away, so it asks.
  Future<bool> _confirmLeave() async {
    if (!_started || _remaining == 0) return true;

    final leave = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).stopImportingQuestion),
        content: Text(
          AppLocalizations.of(context).partialExportScanned(_remaining),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).keepScanning),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(AppLocalizations.of(context).stop),
          ),
        ],
      ),
    );
    return leave ?? false;
  }

  @override
  Widget build(BuildContext context) {
    final complete = _started && _remaining == 0;

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) return;
        if (!await _confirmLeave()) return;
        if (!mounted) return;
        Navigator.of(this.context).pop();
      },
      child: Scaffold(
        appBar: AppBar(
          title: Text(AppLocalizations.of(context).importGoogleAuthenticator),
        ),
        body: Column(
          children: [
            Expanded(
              child: complete
                  ? const _AllScanned()
                  : MobileScanner(controller: _scanner, onDetect: _onDetect),
            ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    complete
                        ? AppLocalizations.of(context).allCodesScanned
                        : AppLocalizations.of(
                            context,
                          ).scanNextMigrationCode(_remaining),
                    style: Theme.of(context).textTheme.titleMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    AppLocalizations.of(
                      context,
                    ).migrationFoundReport(_ready, _refused),
                    textAlign: TextAlign.center,
                  ),
                  if (_message != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      _message!,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ],
                  const SizedBox(height: 16),
                  // The button does not exist until every part is in. A
                  // disabled one invites the user to look for the way to
                  // enable it; an absent one says the step is not reachable.
                  if (complete)
                    FilledButton(
                      onPressed: _busy ? null : _import,
                      child: Text(
                        AppLocalizations.of(context).importReadyCount(_ready),
                      ),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _AllScanned extends StatelessWidget {
  const _AllScanned();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Icon(
        Icons.check_circle_outline,
        size: 96,
        color: Theme.of(context).colorScheme.primary,
      ),
    );
  }
}
