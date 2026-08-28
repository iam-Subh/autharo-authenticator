import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../rust/api/sync.dart' as sync_api;
import '../services/automatic_backup_service.dart';
import '../services/bounded_file_reader.dart';
import '../services/localized_error.dart';
import '../ui/import_report_dialog.dart';
import '../vault_controller.dart';
import 'recovery_key_page.dart';

/// Backup, restore, and a fresh recovery phrase (FR-26 to FR-29, FR-36).
///
/// # Why this screen exists at all
///
/// Microsoft Authenticator will not export its secrets. The stated reason is
/// security; the effect is that leaving it means retyping every account by
/// hand. An authenticator holds the keys to everything its user owns, and one
/// that makes those hard to move is holding them hostage.
///
/// So this app can be left. That is a product decision as much as a feature,
/// and it is the reason the plain export in FR-27 exists despite being the most
/// dangerous thing in the application.
///
/// # The two dangers, and which one this screen is shaped around
///
/// A backup can leak, or it can fail to exist. Both are real, and they pull in
/// opposite directions: the safest backup is the one nobody made.
///
/// Leaking is the one users can see afterwards, so it gets the warnings — the
/// plain export is behind a double confirmation, and its filename says what it
/// is. Failing to exist is the one that actually loses the vault, so nothing
/// here is hidden behind an expert-mode toggle, and the encrypted backup is one
/// tap and a passphrase.
class BackupPage extends StatefulWidget {
  const BackupPage({super.key, required this.controller});

  final VaultController controller;

  @override
  State<BackupPage> createState() => _BackupPageState();
}

const _maximumBackupBytes = 32 * 1024 * 1024;

class _BackupPageState extends State<BackupPage> {
  bool _busy = false;
  final _automaticBackup = AutomaticBackupService();
  AutomaticBackupStatus? _automaticStatus;

  @override
  void initState() {
    super.initState();
    _readAutomaticBackup();
  }

  @override
  void dispose() {
    _automaticBackup.dispose();
    super.dispose();
  }

  Future<void> _readAutomaticBackup() async {
    final status = await _automaticBackup.status();
    if (mounted) setState(() => _automaticStatus = status);
  }

  /// The date in the filename, so a folder of backups sorts and reads.
  String get _stamp {
    final now = DateTime.now();
    final month = now.month.toString().padLeft(2, '0');
    final day = now.day.toString().padLeft(2, '0');
    return '${now.year}-$month-$day';
  }

  Future<void> _guard(Future<void> Function() body) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await body();
    } on MissingAutomaticBackupPassphrase {
      if (mounted) {
        _say(AppLocalizations.of(context).automaticBackupPassphraseMissing);
      }
    } catch (error) {
      if (mounted) _say(localizedError(AppLocalizations.of(context), error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _say(String message) {
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _setAutomaticBackup(bool enabled) => _guard(() async {
    final l10n = AppLocalizations.of(context);
    if (!enabled) {
      await _automaticBackup.disable();
      await _readAutomaticBackup();
      return;
    }

    final passphrase = await showDialog<String>(
      context: context,
      builder: (_) => const _PassphraseDialog(automatic: true),
    );
    if (passphrase == null || !mounted) return;

    final configured = await _automaticBackup.enable(passphrase);
    if (!mounted) return;
    await _readAutomaticBackup();
    _say(
      configured
          ? l10n.automaticBackupOnMessage
          : l10n.automaticBackupCancelled,
    );
  });

  Future<void> _changeAutomaticDirectory() => _guard(() async {
    final message = AppLocalizations.of(context).backupDirectoryChanged;
    final changed = await _automaticBackup.changeDirectory();
    if (!mounted) return;
    await _readAutomaticBackup();
    if (changed) _say(message);
  });

  Future<void> _runAutomaticBackup() => _guard(() async {
    final message = AppLocalizations.of(context).automaticBackupSaved;
    await _automaticBackup.backupNow();
    await _readAutomaticBackup();
    if (mounted) _say(message);
  });

  String _automaticSummary(AutomaticBackupStatus status) {
    final l10n = AppLocalizations.of(context);
    if (!status.available) return l10n.automaticBackupAndroidOnly;
    if (!status.enabled) return l10n.automaticBackupOffStatus;
    final location = status.location ?? l10n.selectedDirectory;
    final last = status.lastBackup;
    if (last == null) return l10n.automaticBackupOnDirectory(location);
    final month = last.month.toString().padLeft(2, '0');
    final day = last.day.toString().padLeft(2, '0');
    final hour = last.hour.toString().padLeft(2, '0');
    final minute = last.minute.toString().padLeft(2, '0');
    return l10n.automaticBackupLast(
      '${last.year}-$month-$day $hour:$minute',
      location,
    );
  }

  // -------------------------------------------------------------------------
  // FR-26: the encrypted backup
  // -------------------------------------------------------------------------

  Future<void> _exportEncrypted() => _guard(() async {
    final passphrase = await showDialog<String>(
      context: context,
      builder: (_) => const _PassphraseDialog(),
    );
    if (passphrase == null || !mounted) return;

    final text = await rust.exportBackup(passphrase: passphrase);
    await _save('authenticator-backup-$_stamp.json', text);
  });

  // -------------------------------------------------------------------------
  // FR-27: the plain export, behind two confirmations
  // -------------------------------------------------------------------------

  Future<void> _exportPlain() => _guard(() async {
    if (!await confirmPlainExport(context) || !mounted) return;

    final text = await rust.exportBackup();
    // The filename carries the warning out of the app with the file. Once it
    // is in a downloads folder this is the only thing left that says what it
    // holds.
    await _save('authenticator-UNPROTECTED-$_stamp.json', text);
  });

  Future<void> _save(String name, String text) async {
    final saved = await FilePicker.saveFile(
      dialogTitle: AppLocalizations.of(context).saveBackup,
      fileName: name,
      bytes: utf8.encode(text),
      mimeType: 'application/json',
    );
    if (!mounted) return;
    // A null result is the user cancelling, which is not a failure and must
    // not be reported as one.
    _say(
      saved == null
          ? AppLocalizations.of(context).backupCancelled
          : AppLocalizations.of(context).backupSaved,
    );
  }

  // -------------------------------------------------------------------------
  // FR-28: reading one back
  // -------------------------------------------------------------------------

  Future<String?> _pickBackupText(String dialogTitle) async {
    final picked = await FilePicker.pickFile(dialogTitle: dialogTitle);
    if (picked == null || !mounted) return null;
    try {
      return utf8.decode(
        await readFileWithLimit(picked, maximumBytes: _maximumBackupBytes),
      );
    } on FormatException {
      if (mounted) _say(AppLocalizations.of(context).notApplicationBackup);
      return null;
    } on FileSizeLimitExceeded {
      if (mounted) _say(AppLocalizations.of(context).notApplicationBackup);
      return null;
    }
  }

  Future<String?> _backupPassphrase(String text) async {
    if (!rust.backupNeedsPassphrase(text: text)) return null;
    if (!mounted) return null;
    return showDialog<String>(
      context: context,
      builder: (_) => const _AskPassphraseDialog(),
    );
  }

  Future<void> _restore() => _guard(() async {
    final text = await _pickBackupText(
      AppLocalizations.of(context).chooseBackupFile,
    );
    if (text == null || !mounted) return;

    // Asked before the passphrase prompt, so a plain backup never demands one
    // and an encrypted one never spends time deriving a key from an empty
    // string before saying what it actually needed.
    final needs = rust.backupNeedsPassphrase(text: text);
    final passphrase = await _backupPassphrase(text);
    if (needs && passphrase == null || !mounted) return;

    final report = await rust.importBackup(
      text: text,
      passphrase: passphrase,
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
    if (!mounted) return;

    await widget.controller.refresh();
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (_) => ImportReportDialog(report: report),
    );
  });

  /// Proves that a backup opens and contains usable records. It does not call
  /// the import API and therefore cannot modify the vault.
  Future<void> _verifyBackup() => _guard(() async {
    final text = await _pickBackupText(
      AppLocalizations.of(context).chooseBackupToTest,
    );
    if (text == null || !mounted) return;
    final needs = rust.backupNeedsPassphrase(text: text);
    final passphrase = await _backupPassphrase(text);
    if (needs && passphrase == null || !mounted) return;

    final report = await rust.verifyBackup(text: text, passphrase: passphrase);
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) {
        final l10n = AppLocalizations.of(context);
        return AlertDialog(
          icon: const Icon(Icons.verified_outlined),
          title: Text(l10n.backupTestPassed),
          content: Text(
            l10n.backupTestResult(
              report.entryCount,
              report.folderCount,
              report.wasEncrypted ? l10n.encrypted : l10n.notEncrypted,
            ),
          ),
          actions: [
            FilledButton(
              onPressed: () => Navigator.pop(context),
              child: Text(l10n.done),
            ),
          ],
        );
      },
    );
  });

  // -------------------------------------------------------------------------
  // FR-29: a recovery phrase the user can write down again
  // -------------------------------------------------------------------------

  Future<void> _newRecoveryPhrase() => _guard(() async {
    final password = await showDialog<String>(
      context: context,
      builder: (_) => const _ReauthenticateDialog(),
    );
    if (password == null || !mounted) return;

    final view = await rust.rotateRecoveryPhrase(password: password);
    if (!mounted) return;

    await Navigator.push<void>(
      context,
      MaterialPageRoute(
        builder: (context) => RecoveryKeyPage(
          phrase: view.phrase,
          confirmIndices: view.confirmIndices
              .map((index) => index.toInt())
              .toList(),
          onConfirmed: () => Navigator.pop(context),
        ),
      ),
    );
    await sync_api.commitRecoveryPhrase(
      password: password,
      recoveryPhrase: view.phrase,
    );
  });

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.backup)),
      body: ListView(
        children: [
          if (_busy) const LinearProgressIndicator(),
          _SectionHeader(l10n.automaticBackup),
          SwitchListTile(
            secondary: const Icon(Icons.history_outlined),
            title: Text(l10n.automaticEncryptedBackups),
            subtitle: Text(
              _automaticStatus == null
                  ? l10n.readingBackupSettings
                  : _automaticSummary(_automaticStatus!),
            ),
            value: _automaticStatus?.enabled ?? false,
            onChanged:
                _busy ||
                    _automaticStatus == null ||
                    !_automaticStatus!.available
                ? null
                : _setAutomaticBackup,
          ),
          if (_automaticStatus?.enabled == true) ...[
            ListTile(
              leading: const Icon(Icons.create_new_folder_outlined),
              title: Text(l10n.changeBackupDirectory),
              enabled: !_busy,
              onTap: _changeAutomaticDirectory,
            ),
            ListTile(
              leading: const Icon(Icons.backup_outlined),
              title: Text(l10n.backUpNow),
              enabled: !_busy,
              onTap: _runAutomaticBackup,
            ),
          ],
          const Divider(),
          _SectionHeader(l10n.backUp),
          ListTile(
            leading: const Icon(Icons.lock_outline),
            title: Text(l10n.encryptedBackup),
            subtitle: Text(l10n.encryptedBackupDescription),
            enabled: !_busy,
            onTap: _exportEncrypted,
          ),
          ListTile(
            leading: Icon(Icons.warning_amber_outlined, color: colours.error),
            title: Text(l10n.unprotectedExport),
            subtitle: Text(l10n.unprotectedExportDescription),
            enabled: !_busy,
            onTap: _exportPlain,
          ),
          const Divider(),
          _SectionHeader(l10n.restore),
          ListTile(
            leading: const Icon(Icons.verified_outlined),
            title: Text(l10n.testBackup),
            subtitle: Text(l10n.testBackupDescription),
            enabled: !_busy,
            onTap: _verifyBackup,
          ),
          ListTile(
            leading: const Icon(Icons.restore_outlined),
            title: Text(l10n.restoreFromBackup),
            subtitle: Text(l10n.restoreFromBackupDescription),
            enabled: !_busy,
            onTap: _restore,
          ),
          const Divider(),
          _SectionHeader(l10n.recoveryPhrase),
          ListTile(
            leading: const Icon(Icons.key_outlined),
            title: Text(l10n.getNewRecoveryPhrase),
            subtitle: Text(l10n.getNewRecoveryPhraseDescription),
            enabled: !_busy,
            onTap: _newRecoveryPhrase,
          ),
        ],
      ),
    );
  }
}

/// FR-27's double confirmation, in front of the plain-text export.
///
/// Returns true only if the user got through both dialogs.
///
/// # Why this is a function and not two lines inside the page
///
/// It is the one gate in this application standing between a tap and every
/// secret the user owns in a readable file. A test has to be able to reach it
/// without an unlocked vault behind it, because a test that needs a vault is a
/// test nobody runs on every commit — and this is exactly the code that must
/// not quietly lose a confirmation during some later refactor.
///
/// Public for that reason, and used by the page rather than copied by it, so
/// the tested gate and the shipped gate cannot drift apart.
Future<bool> confirmPlainExport(BuildContext context) async {
  final warned = await showDialog<bool>(
    context: context,
    builder: (_) => const _PlainWarningDialog(),
  );
  if (warned != true || !context.mounted) return false;

  // The second confirmation, and deliberately not another "are you sure". A
  // user who taps through one dialog taps through two identical ones; the
  // point is to interrupt the reflex, which means asking for something that
  // cannot be done without having read the screen.
  final typed = await showDialog<bool>(
    context: context,
    builder: (_) => const _TypeToConfirmDialog(),
  );
  return typed == true;
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.titleSmall?.copyWith(
          color: Theme.of(context).colorScheme.primary,
        ),
      ),
    );
  }
}

/// Sets the passphrase for an encrypted backup.
///
/// Typed twice, because a mistyped one is not discovered until the day the
/// backup is needed and there is nothing anyone can do about it then. This is
/// the one place in the app where confirming a field is not friction — the file
/// leaves the device and the passphrase is not stored with it.
class _PassphraseDialog extends StatefulWidget {
  const _PassphraseDialog({this.automatic = false});

  final bool automatic;

  @override
  State<_PassphraseDialog> createState() => _PassphraseDialogState();
}

class _PassphraseDialogState extends State<_PassphraseDialog> {
  final _first = TextEditingController();
  final _second = TextEditingController();
  String? _error;

  /// Short enough not to be a wall, long enough that the Argon2id cost is
  /// doing work rather than covering for a four-character passphrase.
  static const _minimum = 10;

  @override
  void dispose() {
    _first.dispose();
    _second.dispose();
    super.dispose();
  }

  void _submit() {
    final value = _first.text;
    if (value.length < _minimum) {
      setState(
        () => _error = AppLocalizations.of(context).minimumCharacters(_minimum),
      );
      return;
    }
    if (value != _second.text) {
      setState(
        () => _error = AppLocalizations.of(context).passphrasesDifferent,
      );
      return;
    }
    Navigator.pop(context, value);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.choosePassphrase),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l10n.backupPassphraseWarning),
            if (widget.automatic) ...[
              const SizedBox(height: 8),
              Text(l10n.automaticPassphraseStorage),
            ],
            const SizedBox(height: 16),
            TextField(
              controller: _first,
              obscureText: true,
              autofocus: true,
              decoration: InputDecoration(
                labelText: l10n.passphrase,
                border: const OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _second,
              obscureText: true,
              onSubmitted: (_) => _submit(),
              decoration: InputDecoration(
                labelText: l10n.typeAgain,
                border: const OutlineInputBorder(),
                errorText: _error,
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: _submit,
          child: Text(widget.automatic ? l10n.turnOn : l10n.backUp),
        ),
      ],
    );
  }
}

/// Asks for the passphrase of a backup being restored.
class _AskPassphraseDialog extends StatefulWidget {
  const _AskPassphraseDialog();

  @override
  State<_AskPassphraseDialog> createState() => _AskPassphraseDialogState();
}

class _AskPassphraseDialogState extends State<_AskPassphraseDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.thisBackupIsEncrypted),
      content: TextField(
        controller: _controller,
        obscureText: true,
        autofocus: true,
        onSubmitted: (value) => Navigator.pop(context, value),
        decoration: InputDecoration(
          labelText: l10n.backupPassphrase,
          border: const OutlineInputBorder(),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _controller.text),
          child: Text(l10n.restore),
        ),
      ],
    );
  }
}

/// The first of FR-27's two confirmations: what the file is.
class _PlainWarningDialog extends StatelessWidget {
  const _PlainWarningDialog();

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      icon: Icon(
        Icons.warning_amber_outlined,
        color: Theme.of(context).colorScheme.error,
      ),
      title: Text(l10n.thisFileProtectsNothing),
      content: SingleChildScrollView(child: Text(l10n.plainExportWarning)),
      actions: [
        FilledButton(
          onPressed: () => Navigator.pop(context, false),
          child: Text(l10n.useEncryptedBackup),
        ),
        TextButton(
          onPressed: () => Navigator.pop(context, true),
          child: Text(l10n.continueAnyway),
        ),
      ],
    );
  }
}

/// The second confirmation, which cannot be tapped through.
///
/// Two identical "are you sure" dialogs are one dialog with an extra tap: the
/// reflex that got past the first gets past the second. Asking the user to type
/// a word is the cheapest thing that requires having read the screen.
class _TypeToConfirmDialog extends StatefulWidget {
  const _TypeToConfirmDialog();

  @override
  State<_TypeToConfirmDialog> createState() => _TypeToConfirmDialogState();
}

class _TypeToConfirmDialogState extends State<_TypeToConfirmDialog> {
  static const _word = 'EXPORT';
  final _controller = TextEditingController();
  bool _matches = false;

  @override
  void initState() {
    super.initState();
    _controller.addListener(() {
      final matches = _controller.text.trim().toUpperCase() == _word;
      if (matches != _matches) setState(() => _matches = matches);
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.typeExportToContinue),
      content: TextField(
        controller: _controller,
        autofocus: true,
        autocorrect: false,
        enableSuggestions: false,
        textCapitalization: TextCapitalization.characters,
        decoration: const InputDecoration(border: OutlineInputBorder()),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, false),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: _matches ? () => Navigator.pop(context, true) : null,
          child: Text(l10n.exportPlainText),
        ),
      ],
    );
  }
}

/// FR-29's re-authentication.
class _ReauthenticateDialog extends StatefulWidget {
  const _ReauthenticateDialog();

  @override
  State<_ReauthenticateDialog> createState() => _ReauthenticateDialogState();
}

class _ReauthenticateDialogState extends State<_ReauthenticateDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.enterAccountPassword),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l10n.rotateRecoveryWarning),
            const SizedBox(height: 16),
            TextField(
              controller: _controller,
              obscureText: true,
              autofocus: true,
              onSubmitted: (value) => Navigator.pop(context, value),
              decoration: InputDecoration(
                labelText: l10n.accountPassword,
                border: const OutlineInputBorder(),
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _controller.text),
          child: Text(l10n.continueAction),
        ),
      ],
    );
  }
}
