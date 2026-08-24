import 'dart:async';

import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../services/clipboard_service.dart';
import '../services/recovery_status_preference.dart';

/// Shows the 24-word recovery key once, then makes the user prove they wrote
/// it down (FR-29, FR-55, and section 9.2.3 step 4).
///
/// # Why the confirmation is not ceremony
///
/// This is the only moment the phrase exists outside the vault. It is not
/// stored, it cannot be shown again, and without it a user who loses every
/// device loses every code — section 16.4 says plainly that the server cannot
/// help, because it cannot decrypt the vault.
///
/// So the three-word check is the last chance to catch someone who tapped past
/// the screen. The positions are chosen at random by the core, which is what
/// makes the check work: fixed positions would teach the user three words
/// rather than the phrase.
class RecoveryKeyPage extends StatefulWidget {
  const RecoveryKeyPage({
    super.key,
    required this.phrase,
    required this.confirmIndices,
    required this.onConfirmed,
  });

  /// The 24 words, space separated. Held only for the life of this screen.
  final String phrase;

  /// Zero-based positions the user must type back.
  final List<int> confirmIndices;

  final VoidCallback onConfirmed;

  @override
  State<RecoveryKeyPage> createState() => _RecoveryKeyPageState();
}

class _RecoveryKeyPageState extends State<RecoveryKeyPage> {
  final _clipboard = ClipboardService(clearAfter: const Duration(minutes: 2));
  bool _confirming = false;
  bool _acknowledged = false;
  late final List<TextEditingController> _answers = List.generate(
    widget.confirmIndices.length,
    (_) => TextEditingController(),
  );
  String? _error;

  List<String> get _words => widget.phrase.split(' ');

  @override
  void dispose() {
    unawaited(_clipboard.clearNow());
    _clipboard.dispose();
    for (final controller in _answers) {
      controller.dispose();
    }
    super.dispose();
  }

  Future<void> _check() async {
    for (var i = 0; i < widget.confirmIndices.length; i++) {
      final expected = _words[widget.confirmIndices[i]];
      // Trimmed and lowercased: BIP-39 words are lowercase, and a trailing
      // space from a keyboard suggestion is not a wrong answer.
      if (_answers[i].text.trim().toLowerCase() != expected) {
        setState(
          () => _error = AppLocalizations.of(
            context,
          ).incorrectRecoveryWord(widget.confirmIndices[i] + 1),
        );
        return;
      }
    }
    await _clipboard.clearNow();
    await RecoveryStatusPreference.markConfirmed();
    widget.onConfirmed();
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      // Leaving without confirming would create an account whose recovery key
      // the user has not recorded, which is the state this screen exists to
      // prevent.
      canPop: false,

      // The handler is not optional. `canPop: false` on its own tells the
      // framework the route refuses to pop and then does nothing about the
      // attempt — and under Android's predictive back the system finishes the
      // activity instead, so the *application closes* on a screen whose whole
      // purpose is to stop the user leaving.
      //
      // Losing the app here is the worst possible moment: the account exists
      // on the server, the recovery key was displayed once, and it is now
      // gone. Refusing the back gesture and saying why is the entire point.
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppLocalizations.of(context).writeRecoveryFirst),
            duration: const Duration(seconds: 5),
          ),
        );
      },
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            _confirming
                ? AppLocalizations.of(context).confirmRecoveryKey
                : AppLocalizations.of(context).yourRecoveryKey,
          ),
          automaticallyImplyLeading: false,
        ),
        body: _confirming ? _buildConfirm(context) : _buildShow(context),
      ),
    );
  }

  Widget _buildShow(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Card(
          color: Theme.of(context).colorScheme.errorContainer,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  Icons.warning_amber_outlined,
                  color: Theme.of(context).colorScheme.onErrorContainer,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    AppLocalizations.of(context).recoveryKeyWarning,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.onErrorContainer,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 24),
        _WordGrid(words: _words),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: () async {
            await _clipboard.copyCode(widget.phrase);
            if (!context.mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(
                  AppLocalizations.of(context).copiedClipboardTwoMinutes,
                ),
              ),
            );
          },
          icon: const Icon(Icons.copy),
          label: Text(AppLocalizations.of(context).copyToClipboard),
        ),
        const SizedBox(height: 8),
        Text(
          AppLocalizations.of(context).paperSaferThanClipboard,
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        CheckboxListTile(
          value: _acknowledged,
          onChanged: (value) => setState(() => _acknowledged = value ?? false),
          title: Text(AppLocalizations.of(context).recoveryWrittenDown),
          contentPadding: EdgeInsets.zero,
        ),
        const SizedBox(height: 8),
        FilledButton(
          onPressed: _acknowledged
              ? () => setState(() => _confirming = true)
              : null,
          child: Text(AppLocalizations.of(context).continueAction),
        ),
      ],
    );
  }

  Widget _buildConfirm(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text(AppLocalizations.of(context).confirmRecoveryInstructions),
        const SizedBox(height: 24),
        for (var i = 0; i < widget.confirmIndices.length; i++) ...[
          TextField(
            controller: _answers[i],
            autofocus: i == 0,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(
              labelText: AppLocalizations.of(
                context,
              ).wordPosition(widget.confirmIndices[i] + 1),
              border: const OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
        ],
        if (_error != null) ...[
          Text(
            _error!,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
          const SizedBox(height: 16),
        ],
        FilledButton(
          onPressed: _check,
          child: Text(AppLocalizations.of(context).confirm),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: () => setState(() {
            _confirming = false;
            _error = null;
          }),
          child: Text(AppLocalizations.of(context).showWordsAgain),
        ),
      ],
    );
  }
}

/// The words, numbered. Numbered because the confirmation asks for positions,
/// and counting down an unnumbered list of 24 is how people mis-transcribe.
class _WordGrid extends StatelessWidget {
  const _WordGrid({required this.words});

  final List<String> words;

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: words.length,
      gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
        maxCrossAxisExtent: 180,
        childAspectRatio: 4,
        crossAxisSpacing: 8,
        mainAxisSpacing: 8,
      ),
      itemBuilder: (context, index) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          border: Border.all(
            color: Theme.of(context).colorScheme.outlineVariant,
          ),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            SizedBox(
              width: 26,
              child: Text(
                '${index + 1}',
                style: TextStyle(color: Theme.of(context).colorScheme.outline),
              ),
            ),
            Expanded(
              child: Text(
                words[index],
                style: const TextStyle(fontWeight: FontWeight.w500),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
