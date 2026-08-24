import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../ui/import_file_flow.dart';
import 'scan_page.dart';

/// How to get accounts out of every other authenticator (FR-15b, FR-15c).
///
/// # Why a help screen is a feature and not documentation
///
/// Two of the largest authenticators cannot export at all. Microsoft
/// Authenticator has no export of any kind, and Authy removed its desktop
/// application specifically to close the route people were using. There is no
/// parser to write for either: the data cannot be got at.
///
/// The honest response is not to leave those users staring at a picker that
/// will never accept anything they have. It is to tell them what actually works
/// — which is re-enrolling account by account at each service — and to be
/// straight that it is tedious rather than pretending otherwise.
///
/// A user who is told "no export file found" concludes this app is broken. A
/// user who is told "Microsoft does not let anything read its codes; here is
/// what to do instead" knows where they stand, and roughly half of them do it.
///
/// # Aegis is out of proportion to its size
///
/// It imports from about ten other applications, including Authy and Microsoft
/// Authenticator on a rooted device. So "install Aegis, import into it, export
/// from it" is a real path out of applications that have no export of their
/// own, and worth naming even though Aegis's own user base is small.
class ImportHelpPage extends StatelessWidget {
  const ImportHelpPage({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(AppLocalizations.of(context).bringAccountsAcross),
      ),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: [
          _Header(l10n.directImports),

          _Route(
            icon: Icons.qr_code_scanner,
            app: 'Google Authenticator',
            steps: l10n.googleImportSteps.split('\n'),
            action: l10n.scanExportCode,
            onAction: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ScanPage()),
            ),
          ),

          _Route(
            icon: Icons.folder_open_outlined,
            app: 'Aegis Authenticator',
            steps: l10n.aegisImportSteps.split('\n'),
            action: l10n.chooseFile,
            onAction: () => importFromFile(context, onImported: () async {}),
          ),

          _Route(
            icon: Icons.folder_open_outlined,
            app: '2FAS',
            steps: l10n.twoFasImportSteps.split('\n'),
            action: l10n.chooseFile,
            onAction: () => importFromFile(context, onImported: () async {}),
          ),

          _Route(
            icon: Icons.folder_open_outlined,
            app: 'Ente Auth',
            steps: l10n.enteImportSteps.split('\n'),
            action: l10n.chooseFile,
            onAction: () => importFromFile(context, onImported: () async {}),
          ),

          _Route(
            icon: Icons.folder_open_outlined,
            app: 'Proton Authenticator',
            steps: l10n.protonImportSteps.split('\n'),
            action: l10n.chooseFile,
            onAction: () => importFromFile(context, onImported: () async {}),
          ),

          _Route(
            icon: Icons.folder_open_outlined,
            app: 'Bitwarden',
            steps: l10n.bitwardenImportSteps.split('\n'),
            action: l10n.chooseFile,
            onAction: () => importFromFile(context, onImported: () async {}),
          ),

          _Route(
            icon: Icons.folder_open_outlined,
            app: 'Standard Notes Authenticator',
            steps: l10n.standardNotesImportSteps.split('\n'),
            action: l10n.chooseFile,
            onAction: () => importFromFile(context, onImported: () async {}),
          ),

          const Divider(height: 32),
          _Header(l10n.appsWithoutExport),

          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Text(
              l10n.appsWithoutExportDescription,
              style: TextStyle(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),

          _Route(
            icon: Icons.block,
            app: 'Microsoft Authenticator',
            steps: l10n.microsoftImportSteps.split('\n'),
            action: l10n.scanQrCodeTitle,
            onAction: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const ScanPage()),
            ),
          ),

          _Route(
            icon: Icons.block,
            app: 'Authy',
            steps: l10n.authyImportSteps.split('\n'),
            action: null,
            onAction: null,
          ),

          const Divider(height: 32),
          _Header(l10n.otherAuthenticators),

          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Text(
              l10n.otherAuthenticatorHelp,
              style: TextStyle(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),

          ListTile(
            leading: const Icon(Icons.keyboard),
            title: Text(AppLocalizations.of(context).typeSetupKeyManually),
            subtitle: Text(AppLocalizations.of(context).setupKeyAvailable),
            onTap: () => Navigator.pop(context),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _Header extends StatelessWidget {
  const _Header(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.titleSmall?.copyWith(
          color: Theme.of(context).colorScheme.primary,
        ),
      ),
    );
  }
}

/// One application, its steps, and the button that starts the work.
///
/// Collapsed by default. Eight applications' worth of steps unfurled at once is
/// a wall nobody reads, and the user only cares about the one they are leaving.
class _Route extends StatelessWidget {
  const _Route({
    required this.icon,
    required this.app,
    required this.steps,
    required this.action,
    required this.onAction,
  });

  final IconData icon;
  final String app;
  final List<String> steps;

  /// Null where there is nothing this app can do — Authy's case, where every
  /// route runs through somewhere else. A disabled button would imply the
  /// feature exists and is unavailable.
  final String? action;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    return ExpansionTile(
      leading: Icon(icon),
      title: Text(app),
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      expandedCrossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (var i = 0; i < steps.length; i++)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(
                  width: 24,
                  child: Text(
                    '${i + 1}.',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ),
                Expanded(child: Text(steps[i])),
              ],
            ),
          ),
        if (action != null) ...[
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: FilledButton.tonal(
              onPressed: onAction,
              child: Text(action!),
            ),
          ),
        ],
      ],
    );
  }
}
