import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;

/// Shows one entry as a QR code, to move it to another app (FR-30).
///
/// # Why a QR code and not a file
///
/// The backup file in FR-26 moves everything and needs the other application to
/// understand a format. This moves one account to a device standing in front of
/// you — a second phone, a desktop client — with no file, no cloud, and no
/// account in common. It is the oldest transfer path in this ecosystem and the
/// one that always works.
///
/// # What is on the screen, and why it is treated as a secret
///
/// The QR code *is* the secret. Anyone who photographs it has permanent access
/// to that account, and unlike a password there is nothing to change afterwards
/// — the only remedy is removing two-factor authentication at the service and
/// setting it up again.
///
/// So this screen assumes it is being read over a shoulder:
///
/// - The code is hidden behind a tap, not shown on arrival. Opening the wrong
///   menu item on a train should not expose an account.
/// - The secret in text form is behind a second tap, because a user who needs
///   to type it into a desktop client is doing something deliberate.
///
/// Screenshots are blocked when the user enables the Android screenshot
/// protection setting. `MainActivity` then sets `FLAG_SECURE` for the
/// whole application at `onCreate`, per §9.4, which also blanks the recent-apps
/// thumbnail. Nothing is done here for it, because a per-screen toggle over the
/// top could only weaken a flag that is already on — and a shoulder beside you
/// is what this screen actually has to defend against.
class EntryQrPage extends StatefulWidget {
  const EntryQrPage({super.key, required this.entryId, required this.title});

  final String entryId;

  /// What to call the account on screen. Passed in rather than re-read: the
  /// caller already has it, and this screen should ask the core for exactly one
  /// thing — the secret.
  final String title;

  @override
  State<EntryQrPage> createState() => _EntryQrPageState();
}

class _EntryQrPageState extends State<EntryQrPage> {
  String? _uri;
  Object? _error;
  bool _revealed = false;
  bool _showText = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final uri = await rust.exportEntryUri(id: widget.entryId);
      if (mounted) setState(() => _uri = uri);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  String? get _secret {
    final uri = _uri;
    if (uri == null) return null;
    return Uri.tryParse(uri)?.queryParameters['secret'];
  }

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: Text(AppLocalizations.of(context).moveThisAccount)),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text(
              widget.title,
              style: Theme.of(context).textTheme.titleLarge,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            Center(child: _body(colours)),
            const SizedBox(height: 24),
            Card(
              color: colours.errorContainer,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      Icons.warning_amber_outlined,
                      color: colours.onErrorContainer,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        AppLocalizations.of(context).qrSecretWarning,
                        style: TextStyle(color: colours.onErrorContainer),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            if (_revealed && _uri != null) ...[
              const SizedBox(height: 16),
              TextButton.icon(
                icon: Icon(
                  _showText ? Icons.visibility_off : Icons.text_fields,
                ),
                label: Text(
                  _showText
                      ? AppLocalizations.of(context).hideSetupKey
                      : AppLocalizations.of(context).showSetupKey,
                ),
                onPressed: () => setState(() => _showText = !_showText),
              ),
              if (_showText) _SetupKey(secret: _secret ?? ''),
            ],
          ],
        ),
      ),
    );
  }

  Widget _body(ColorScheme colours) {
    if (_error != null) {
      return Text('$_error', textAlign: TextAlign.center);
    }
    final uri = _uri;
    if (uri == null) {
      return const Padding(
        padding: EdgeInsets.all(48),
        child: CircularProgressIndicator(),
      );
    }

    if (!_revealed) {
      return _Hidden(onReveal: () => setState(() => _revealed = true));
    }

    return Container(
      // A white quiet zone regardless of theme. A QR code rendered dark-on-dark
      // scans on nothing, and the one moment this screen matters is the moment
      // another phone's camera is pointed at it.
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
      ),
      child: QrImageView(
        data: uri,
        version: QrVersions.auto,
        size: 240,
        backgroundColor: Colors.white,
        // High correction, because this is photographed off a screen at an
        // angle, often with a reflection across it.
        errorCorrectionLevel: QrErrorCorrectLevel.H,
      ),
    );
  }
}

class _Hidden extends StatelessWidget {
  const _Hidden({required this.onReveal});

  final VoidCallback onReveal;

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    return InkWell(
      onTap: onReveal,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        width: 272,
        height: 272,
        decoration: BoxDecoration(
          color: colours.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.qr_code_2, size: 64, color: colours.onSurfaceVariant),
            const SizedBox(height: 12),
            Text(
              AppLocalizations.of(context).tapToShow,
              style: TextStyle(color: colours.onSurfaceVariant),
            ),
            const SizedBox(height: 4),
            Text(
              AppLocalizations.of(context).checkScreenPrivacy,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

/// The Base32 secret, for typing into something with no camera.
class _SetupKey extends StatelessWidget {
  const _SetupKey({required this.secret});

  final String secret;

  /// Groups of four, which is how every service prints a setup key and the only
  /// way a 32-character Base32 string can be typed without losing your place.
  String get _grouped {
    final buffer = StringBuffer();
    for (var i = 0; i < secret.length; i += 4) {
      if (i > 0) buffer.write(' ');
      buffer.write(secret.substring(i, (i + 4).clamp(0, secret.length)));
    }
    return buffer.toString();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: 8),
      child: SelectableText(
        _grouped,
        textAlign: TextAlign.center,
        style: Theme.of(context).textTheme.titleMedium?.copyWith(
          fontFamily: 'monospace',
          letterSpacing: 1.2,
        ),
      ),
    );
  }
}
