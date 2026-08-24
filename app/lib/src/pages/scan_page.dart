import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../l10n/generated/app_localizations.dart';

/// FR-10: "Scan a QR code with the camera and parse the `otpauth://` URI."
///
/// Parsing happens in the core, not here. This screen's only job is to get a
/// string off the camera and hand it back; it does a cheap prefix check first
/// so that pointing the camera at an unrelated QR code gives an immediate
/// explanation rather than a failure two screens later.
class ScanPage extends StatefulWidget {
  const ScanPage({super.key, this.allowShareLink = false});

  final bool allowShareLink;

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
  bool _pickingImage = false;
  String? _rejected;

  @override
  void dispose() {
    _scanner.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    _acceptCapture(capture);
  }

  bool _acceptCapture(BarcodeCapture capture) {
    if (_handled) return false;

    for (final barcode in capture.barcodes) {
      final value = barcode.rawValue?.trim();
      if (value == null || value.isEmpty) continue;

      final lower = value.toLowerCase();
      if (lower.startsWith('otpauth://')) {
        _handled = true;
        Navigator.of(context).pop(value);
        return true;
      }

      // FR-14: Google Authenticator's bulk export. Handed back like any other
      // code; the caller routes it, because a multi-code export needs a screen
      // that keeps the camera open and this one closes on the first hit.
      if (lower.startsWith('otpauth-migration://')) {
        _handled = true;
        Navigator.of(context).pop(value);
        return true;
      }

      if (widget.allowShareLink &&
          (lower.startsWith('https://') || lower.startsWith('http://'))) {
        _handled = true;
        Navigator.of(context).pop(value);
        return true;
      }

      if (mounted) {
        setState(() {
          _rejected = widget.allowShareLink
              ? AppLocalizations.of(context).notSharedAccountQr
              : AppLocalizations.of(context).notOtpSetupQr;
        });
      }
    }

    return false;
  }

  Future<void> _pickImage() async {
    if (_handled || _pickingImage) return;
    final dialogTitle = AppLocalizations.of(context).chooseQrImage;

    setState(() {
      _pickingImage = true;
      _rejected = null;
    });

    try {
      await _scanner.stop();
      final picked = await FilePicker.pickFile(
        dialogTitle: dialogTitle,
        type: FileType.image,
      );
      if (picked == null || !mounted) return;

      final path = picked.path;
      if (path == null) {
        setState(() {
          _rejected = AppLocalizations.of(context).selectedImageUnavailable;
        });
        return;
      }

      final capture = await _scanner.analyzeImage(path);
      if (!mounted || _handled) return;

      if (capture == null || !_acceptCapture(capture)) {
        if (mounted && _rejected == null) {
          setState(() {
            _rejected = widget.allowShareLink
                ? AppLocalizations.of(context).noSharedQrInImage
                : AppLocalizations.of(context).noOtpQrInImage;
          });
        }
      }
    } catch (_) {
      if (mounted && !_handled) {
        setState(() {
          _rejected = AppLocalizations.of(context).imageScanFailed;
        });
      }
    } finally {
      if (mounted && !_handled) {
        try {
          await _scanner.start();
        } catch (_) {
          // The camera error widget reports camera start failures.
        }
        if (mounted) setState(() => _pickingImage = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(AppLocalizations.of(context).scanQrCodeTitle),
        actions: [
          IconButton(
            tooltip: AppLocalizations.of(context).chooseImage,
            icon: _pickingImage
                ? const SizedBox.square(
                    dimension: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.photo_library_outlined),
            onPressed: _pickingImage ? null : _pickImage,
          ),
          IconButton(
            tooltip: AppLocalizations.of(context).torch,
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
    final denied = error.errorCode == MobileScannerErrorCode.permissionDenied;

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
                  ? AppLocalizations.of(context).cameraPermissionRequired
                  : AppLocalizations.of(context).cameraStartFailed,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              AppLocalizations.of(context).manualEntryAlternative,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(AppLocalizations.of(context).goBack),
            ),
          ],
        ),
      ),
    );
  }
}
