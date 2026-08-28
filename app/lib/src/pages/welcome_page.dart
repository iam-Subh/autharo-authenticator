import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../services/vault_session.dart';
import '../services/localized_error.dart';
import '../vault_controller.dart';
import 'create_account_page.dart';
import 'import_help_page.dart';

/// The first thing a new user sees (FR-47).
///
/// # Why there is a screen here at all
///
/// Nobody starts an authenticator empty. Everyone arriving here already has one
/// — with somewhere between five and fifty accounts in it — and the only
/// question that matters in the first minute is *how do my accounts get from
/// there to here*. An app that opens on an empty list with a plus button has
/// answered a different question, and a good share of the people who see it
/// close it and go back to the app they were trying to leave.
///
/// So the three things it can do are on the screen, named, before anything
/// else happens.
///
/// # Why "no account" is offered first and offered honestly
///
/// Sync is the feature this project spent the most on, and putting it first
/// would be the natural instinct. It is the wrong one. A user who has to create
/// an account before they can see a single code has been asked to trust a
/// stranger with the keys to everything they own, before being shown anything
/// that earns it.
///
/// Local-only is a real mode here, not a downgrade: the vault is encrypted
/// either way, the codes work either way, and sync can be turned on later
/// without re-adding anything. That is worth saying on the screen, because
/// every other authenticator that offers this choice makes the local option
/// feel like a mistake.
class WelcomePage extends StatefulWidget {
  const WelcomePage({
    super.key,
    required this.session,
    required this.controller,
    required this.onDone,
  });

  final VaultSession session;
  final VaultController controller;

  /// Called once the user has chosen. The vault already exists by this point —
  /// setup happened before this screen — so every path here is additive and
  /// none of them can fail in a way that leaves the app unusable.
  final VoidCallback onDone;

  @override
  State<WelcomePage> createState() => _WelcomePageState();
}

class _WelcomePageState extends State<WelcomePage> {
  bool _busy = false;

  Future<void> _finish() async {
    // Recorded before leaving, so a user who gets here and force-quits is not
    // shown the same screen forever. It is a one-time introduction, not a
    // gate — everything it offers is reachable afterwards from Settings.
    try {
      await rust.markWelcomeSeen();
    } catch (_) {
      // Not worth failing the first run over. The cost of losing this flag is
      // that the screen appears once more.
    }
    if (mounted) widget.onDone();
  }

  Future<void> _guard(Future<void> Function() body) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await body();
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context)
          ..clearSnackBars()
          ..showSnackBar(
            SnackBar(
              content: Text(
                localizedError(AppLocalizations.of(context), error),
              ),
            ),
          );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _createAccount() => _guard(() async {
    final created = await Navigator.push<bool>(
      context,
      MaterialPageRoute(
        builder: (_) => CreateAccountPage(session: widget.session),
      ),
    );
    // Backing out of sign-up returns here rather than dropping the user into
    // the app, so the other two choices are still in front of them.
    if (created == true) await _finish();
  });

  Future<void> _import() => _guard(() async {
    await Navigator.push<void>(
      context,
      MaterialPageRoute(builder: (_) => const ImportHelpPage()),
    );
    // Deliberately not finishing here. Importing may take several goes — a
    // file, then a QR code, then three accounts typed by hand — and throwing
    // the user out of this screen after the first one would hide the rest.
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colours = theme.colorScheme;

    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(24, 48, 24, 24),
          children: [
            Icon(Icons.shield_outlined, size: 64, color: colours.primary),
            const SizedBox(height: 24),
            Text(
              AppLocalizations.of(context).welcomeTitle,
              style: theme.textTheme.headlineSmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            Text(
              AppLocalizations.of(context).welcomeDescription,
              style: TextStyle(color: colours.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 40),

            _Choice(
              icon: Icons.download_outlined,
              title: AppLocalizations.of(context).bringMyAccountsAcross,
              body: AppLocalizations.of(context).bringAccountsSources,
              onTap: _busy ? null : _import,
            ),
            const SizedBox(height: 12),
            _Choice(
              icon: Icons.cloud_outlined,
              title: AppLocalizations.of(context).setUpSync,
              body: AppLocalizations.of(context).setUpSyncDescription,
              onTap: _busy ? null : _createAccount,
            ),
            const SizedBox(height: 12),
            _Choice(
              icon: Icons.phone_android_outlined,
              title: AppLocalizations.of(context).useOnThisPhone,
              body: AppLocalizations.of(context).useOnThisPhoneDescription,
              onTap: _busy ? null : _finish,
            ),

            const SizedBox(height: 32),
            Text(
              AppLocalizations.of(context).changeLaterInSettings,
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Center(
              child: TextButton(
                onPressed: _busy ? null : _finish,
                child: Text(AppLocalizations.of(context).skipForNow),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// One of the three, sized so all three fit above the fold on a small phone.
///
/// They are cards rather than a list because the choice is between three peers.
/// A list with the first item styled as primary would be this screen making the
/// decision, which is the thing it exists not to do.
class _Choice extends StatelessWidget {
  const _Choice({
    required this.icon,
    required this.title,
    required this.body,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String body;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: theme.colorScheme.primary),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title, style: theme.textTheme.titleMedium),
                    const SizedBox(height: 4),
                    Text(
                      body,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
