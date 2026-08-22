import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

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
    for (final controller in _answers) {
      controller.dispose();
    }
    super.dispose();
  }

  void _check() {
    for (var i = 0; i < widget.confirmIndices.length; i++) {
      final expected = _words[widget.confirmIndices[i]];
      // Trimmed and lowercased: BIP-39 words are lowercase, and a trailing
      // space from a keyboard suggestion is not a wrong answer.
      if (_answers[i].text.trim().toLowerCase() != expected) {
        setState(() => _error = 'That is not the word at position '
            '${widget.confirmIndices[i] + 1}. Check your list and try again.');
        return;
      }
    }
    widget.onConfirmed();
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      // Leaving without confirming would create an account whose recovery key
      // the user has not recorded, which is the state this screen exists to
      // prevent.
      canPop: false,
      child: Scaffold(
        appBar: AppBar(
          title: Text(_confirming ? 'Confirm your recovery key' : 'Your recovery key'),
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
                    'These 24 words are the only way back into your codes if '
                    'you lose every device. They are shown once. We cannot '
                    'show them again and we cannot recover them for you — your '
                    'codes are encrypted with a key we never see.',
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
            await Clipboard.setData(ClipboardData(text: widget.phrase));
            if (!context.mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text(
                  'Copied. Paste it somewhere safe, then clear your clipboard.',
                ),
              ),
            );
          },
          icon: const Icon(Icons.copy),
          label: const Text('Copy to clipboard'),
        ),
        const SizedBox(height: 8),
        Text(
          'Writing them on paper is safer than the clipboard. A clipboard is '
          'readable by other applications and may sync to your other devices.',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        CheckboxListTile(
          value: _acknowledged,
          onChanged: (value) => setState(() => _acknowledged = value ?? false),
          title: const Text('I have written these words down'),
          contentPadding: EdgeInsets.zero,
        ),
        const SizedBox(height: 8),
        FilledButton(
          onPressed: _acknowledged
              ? () => setState(() => _confirming = true)
              : null,
          child: const Text('Continue'),
        ),
      ],
    );
  }

  Widget _buildConfirm(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const Text(
          'Type these words from your list. This checks that you really wrote '
          'them down, while there is still time to go back.',
        ),
        const SizedBox(height: 24),
        for (var i = 0; i < widget.confirmIndices.length; i++) ...[
          TextField(
            controller: _answers[i],
            autofocus: i == 0,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(
              labelText: 'Word ${widget.confirmIndices[i] + 1}',
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
          child: const Text('Confirm'),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: () => setState(() {
            _confirming = false;
            _error = null;
          }),
          child: const Text('Show the words again'),
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
          border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
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
