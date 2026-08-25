import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../services/bounded_file_reader.dart';
import 'import_report_dialog.dart';

const _maximumImportBytes = 32 * 1024 * 1024;

/// Picking an export file and importing it (FR-15, FR-15a, FR-15d).
///
/// # Why this is a flow and not a screen
///
/// There is nothing to look at. The user picks a file, may be asked for a
/// password, and sees a report. A screen in the middle of that would be a page
/// whose only content is a button that opens the system picker — a step that
/// exists to be dismissed.
///
/// The QR migration in FR-14 does have its own screen, and for a real reason:
/// a large Google export is several codes, and every one must be scanned before
/// anything is imported. That is a task with progress. This is not.
///
/// # The application is never asked for
///
/// Aegis and 2FAS both write JSON with a distinctive shape, so the file says
/// what it is. A menu asking the user to choose first can only be redundant or
/// wrong — and when it is wrong, a perfectly good export is reported as
/// unreadable to somebody who has had this app installed for four minutes.
///
/// The detection lives in Rust, where it is tested, rather than being repeated
/// here against a copy of the same rules.
Future<void> importFromFile(
  BuildContext context, {
  required Future<void> Function() onImported,
}) async {
  final picked = await FilePicker.pickFile(
    dialogTitle: AppLocalizations.of(context).chooseExportFile,
  );
  if (picked == null || !context.mounted) return;

  final String text;
  try {
    text = utf8.decode(
      await readFileWithLimit(picked, maximumBytes: _maximumImportBytes),
    );
  } on FormatException catch (_) {
    // Not text at all — a photograph, a database, a zip. Reported as the wrong
    // file rather than as a decoding failure, which is the same fact in
    // language nobody can act on.
    if (context.mounted) {
      _say(context, AppLocalizations.of(context).unreadableExport);
    }
    return;
  } on FileSizeLimitExceeded {
    if (context.mounted) {
      _say(context, AppLocalizations.of(context).unreadableExport);
    }
    return;
  }
  if (!context.mounted) return;

  // Identified before anything else, so the password prompt can name the
  // application it belongs to and can be skipped entirely for a plain file.
  final rust.DetectedFileView detected;
  try {
    detected = rust.detectImportFile(text: text);
  } catch (error) {
    if (context.mounted) _say(context, '$error');
    return;
  }

  String? password;
  if (detected.encrypted) {
    password = await showDialog<String>(
      context: context,
      builder: (_) => _PasswordDialog(source: detected.source),
    );
    if (password == null || !context.mounted) return;
  }

  final rust.ImportReportView report;
  try {
    report = await rust.importFile(
      text: text,
      password: password,
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
  } catch (error) {
    if (context.mounted) _say(context, '$error');
    return;
  }

  await onImported();
  if (!context.mounted) return;

  await showDialog<void>(
    context: context,
    builder: (_) => ImportReportDialog(report: report),
  );
}

void _say(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..clearSnackBars()
    ..showSnackBar(SnackBar(content: Text(message)));
}

/// Asks for the password of an encrypted export, naming the app it came from.
///
/// "Enter a password" leaves someone guessing which of their passwords is
/// wanted. Naming the application answers it, and the answer is already known
/// by the time this is shown.
class _PasswordDialog extends StatefulWidget {
  const _PasswordDialog({required this.source});

  final String source;

  @override
  State<_PasswordDialog> createState() => _PasswordDialogState();
}

class _PasswordDialogState extends State<_PasswordDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final own = widget.source == 'backup';
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(
        own
            ? l10n.thisBackupIsEncrypted
            : l10n.encryptedSourceExport(widget.source),
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            own
                ? l10n.enterBackupPassphrase
                : l10n.enterSourceExportPassword(widget.source),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _controller,
            obscureText: true,
            autofocus: true,
            onSubmitted: (value) => Navigator.pop(context, value),
            decoration: InputDecoration(
              labelText: AppLocalizations.of(context).password,
              border: const OutlineInputBorder(),
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(AppLocalizations.of(context).cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _controller.text),
          child: Text(AppLocalizations.of(context).importAction),
        ),
      ],
    );
  }
}
