import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/share.dart' as share;
import '../services/clipboard_service.dart';
import '../services/security_elevation.dart';

class ShareEntryPage extends StatefulWidget {
  const ShareEntryPage({super.key, required this.entryId, required this.title});

  final String entryId;
  final String title;

  @override
  State<ShareEntryPage> createState() => _ShareEntryPageState();
}

class _ShareEntryPageState extends State<ShareEntryPage> {
  final _clipboard = ClipboardService();
  int _expirySeconds = 3600;
  bool _oneTime = true;
  bool _busy = false;
  share.ShareLinkView? _created;
  Object? _error;

  @override
  void dispose() {
    _clipboard.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final authorized = await authorizeScope(
        context,
        scope: shareWriteScope,
        action: AppLocalizations.of(context).shareAccount,
      );
      if (!authorized || !mounted) return;
      final created = await share.createEntryShare(
        id: widget.entryId,
        expiresInSeconds: _expirySeconds,
        oneTime: _oneTime,
      );
      if (mounted) setState(() => _created = created);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copy() async {
    final link = _created?.link;
    if (link == null) return;
    await _clipboard.copyCode(link);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(AppLocalizations.of(context).shareLinkCopied)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final created = _created;
    final l10n = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.shareAccount)),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Text(widget.title, style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          Text(l10n.shareEncryptionDescription),
          const SizedBox(height: 20),
          if (created == null) ...[
            DropdownButtonFormField<int>(
              initialValue: _expirySeconds,
              decoration: InputDecoration(
                labelText: l10n.linkExpiresAfter,
                border: const OutlineInputBorder(),
              ),
              items: [
                DropdownMenuItem(value: 300, child: Text(l10n.fiveMinutes)),
                DropdownMenuItem(value: 3600, child: Text(l10n.oneHour)),
                DropdownMenuItem(value: 21600, child: Text(l10n.sixHours)),
                DropdownMenuItem(
                  value: 86400,
                  child: Text(l10n.twentyFourHours),
                ),
              ],
              onChanged: _busy
                  ? null
                  : (value) => setState(() => _expirySeconds = value ?? 3600),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(l10n.deleteAfterFirstDownload),
              subtitle: Text(l10n.oneTimeShareDescription),
              value: _oneTime,
              onChanged: _busy
                  ? null
                  : (value) => setState(() => _oneTime = value),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(
                  l10n.shareCreationFailed('$_error'),
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            FilledButton.icon(
              onPressed: _busy ? null : _create,
              icon: _busy
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.lock_outline),
              label: Text(l10n.createEncryptedLink),
            ),
            const SizedBox(height: 12),
            Text(l10n.shareSignInDescription),
          ] else ...[
            Center(
              child: Container(
                padding: const EdgeInsets.all(12),
                color: Colors.white,
                child: QrImageView(
                  data: created.link,
                  size: 260,
                  backgroundColor: Colors.white,
                  errorCorrectionLevel: QrErrorCorrectLevel.M,
                ),
              ),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _copy,
              icon: const Icon(Icons.copy_outlined),
              label: Text(l10n.copyShareLink),
            ),
            const SizedBox(height: 12),
            Text(l10n.expiresAt(created.expiresAt)),
            const SizedBox(height: 16),
            Card(
              color: Theme.of(context).colorScheme.errorContainer,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Text(
                  l10n.shareLinkWarning,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onErrorContainer,
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
