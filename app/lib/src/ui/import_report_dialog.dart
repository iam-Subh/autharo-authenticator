import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;

/// FR-15d: names every refused entry and why.
///
/// "One entry was invalid" is not something a user can act on. The common case
/// the requirement calls out is an HOTP entry with no counter, which the user
/// can supply by hand — but only if they are told which account needs it.
///
/// Shared by every import path — the QR migration in FR-14 and the backup files
/// in FR-28 — rather than restated per screen. A user restoring a backup onto a
/// device that already holds some of the accounts hits the duplicate line here
/// just as often as someone moving from another app, and the two should not
/// drift into saying different things about the same outcome.
class ImportReportDialog extends StatelessWidget {
  const ImportReportDialog({super.key, required this.report});

  final rust.ImportReportView report;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(AppLocalizations.of(context).importedCount(report.imported)),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            if (report.duplicates > 0)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(
                  AppLocalizations.of(
                    context,
                  ).duplicatesSkipped(report.duplicates),
                ),
              ),
            if (report.refused.isNotEmpty) ...[
              Text(
                AppLocalizations.of(
                  context,
                ).couldNotImportCount(report.refused.length),
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: 8),
              for (final item in report.refused)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        item.label.isEmpty
                            ? AppLocalizations.of(context).unnamedEntry
                            : item.label,
                        style: const TextStyle(fontWeight: FontWeight.bold),
                      ),
                      Text(item.reason),
                    ],
                  ),
                ),
              const SizedBox(height: 8),
              Text(AppLocalizations.of(context).addSkippedManually),
            ],
          ],
        ),
      ),
      actions: [
        FilledButton(
          onPressed: () => Navigator.pop(context),
          child: Text(AppLocalizations.of(context).done),
        ),
      ],
    );
  }
}
