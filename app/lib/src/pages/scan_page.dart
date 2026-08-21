import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// FR-10: "Scan a QR code with the camera and parse the `otpauth://` URI."
///
/// Parsing happens in the core, not here. This screen's only job is to get a
/// string off the camera and hand it back; it does a cheap prefix check first
/// so that pointing the camera at an unrelated QR code gives an immediate
/// explanation rather than a failure two screens later.
class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  final _scanner = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );

  /// The camera keeps firing after the first hit, and a second detection while
  /// the route is popping throws. One-shot guard.
  bool _handled = false;
  String? _rejected;

  @override
  void dispose() {
    _scanner.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;

    for (final barcode in capture.barcodes) {
      final value = barcode.rawValue?.trim();
      if (value == null || value.isEmpty) continue;

      final lower = value.toLowerCase();
      if (lower.startsWith('otpauth://')) {
        _handled = true;
        Navigator.of(context).pop(value);
        return;
      }

      // Google Authenticator's bulk export. The core cannot read it yet
      // (FR-14, stage S8), so say so precisely rather than "invalid code".
      if (lower.startsWith('otpauth-migration://')) {
        setState(() {
          _rejected = 'That is a Google Authenticator export code. Importing '
              'those is not supported yet — for now, add each account from its '
              'own QR code.';
        });
        return;
      }

      setState(() {
        _rejected = 'That QR code is not a two-factor setup code.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR code'),
        actions: [
          IconButton(
            tooltip: 'Torch',
            icon: const Icon(Icons.flashlight_on),
            onPressed: () => _scanner.toggleTorch(),
          ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(
            controller: _scanner,
            onDetect: _onDetect,
            errorBuilder: (context, error) => _CameraUnavailable(error: error),
          ),
          if (_rejected != null)
            Align(
              alignment: Alignment.bottomCenter,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Material(
                  color: Theme.of(context).colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(12),
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Text(
                      _rejected!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.onErrorContainer,
                      ),
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

/// A denied camera permission is the common case here, and it is recoverable —
/// FR-13 lets the user type the key instead — so the screen offers that rather
/// than dead-ending.
class _CameraUnavailable extends StatelessWidget {
  const _CameraUnavailable({required this.error});

  final MobileScannerException error;

  @override
  Widget build(BuildContext context) {
    final denied =
        error.errorCode == MobileScannerErrorCode.permissionDenied;

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.no_photography_outlined, size: 48),
            const SizedBox(height: 16),
            Text(
              denied
                  ? 'This application does not have permission to use the '
                      'camera.'
                  : 'The camera could not be started.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'You can add the account by entering its setup key instead.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Go back'),
            ),
          ],
        ),
      ),
    );
  }
}
