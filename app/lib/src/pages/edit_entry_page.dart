import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../services/custom_icon_data.dart';
import '../services/bounded_file_reader.dart';
import '../services/localized_error.dart';
import '../services/service_icon_matcher.dart';
import '../ui/entry_avatar.dart';
import '../ui/form_page.dart';
import '../vault_controller.dart';

/// FR-17: "Edit the issuer, the account name, and the icon of an entry. Do not
/// allow an edit of the secret."
///
/// # Why the secret is not on this screen at all
///
/// Not disabled, not read-only behind a confirmation — absent.
///
/// A secret is the account. Changing it does not rename anything; it silently
/// points the entry at a different service, and the codes it then produces are
/// wrong in a way nothing detects. The user sees an entry with the right name
/// producing rejected codes, and the original secret is gone.
///
/// A greyed-out field invites someone to look for the way to enable it. An
/// absent one says the operation does not exist. If a secret really has changed,
/// the service issued a new one, and the honest action is to delete the entry
/// and scan the new code.
///
/// # The icon
///
/// Every entry gets a full-colour service favicon when its issuer or account
/// domain matches the catalog. This screen also supports another service icon,
/// an emoji, or a custom image as an explicit override.
class EditEntryPage extends StatefulWidget {
  const EditEntryPage({
    super.key,
    required this.controller,
    required this.entry,
  });

  final VaultController controller;
  final rust.EntryView entry;

  @override
  State<EditEntryPage> createState() => _EditEntryPageState();
}

class _EditEntryPageState extends State<EditEntryPage> {
  late final _issuer = TextEditingController(text: widget.entry.issuer ?? '');
  late final _account = TextEditingController(text: widget.entry.account);
  late final _note = TextEditingController(text: widget.entry.note);
  late final _tags = TextEditingController(text: widget.entry.tags.join(', '));

  late String? _icon = widget.entry.icon;

  bool _busy = false;
  String? _problem;

  @override
  void initState() {
    super.initState();
    _issuer.addListener(_refreshIconPreview);
    _account.addListener(_refreshIconPreview);
  }

  void _refreshIconPreview() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _issuer.dispose();
    _account.dispose();
    _note.dispose();
    _tags.dispose();
    super.dispose();
  }

  /// Read from the controllers, not the widget tree.
  ///
  /// A field that scrolls out of a list is disposed, and a validator that never
  /// runs reports success — which is how a form once passed while checking
  /// nothing.
  String? _firstProblem() {
    if (_account.text.trim().isEmpty) {
      return AppLocalizations.of(context).accountNameRequired;
    }
    if (_note.text.characters.length > 512) {
      return AppLocalizations.of(context).noteTooLong;
    }
    final tags = _parsedTags();
    if (tags.length > 20) return AppLocalizations.of(context).tooManyTags;
    if (tags.any((tag) => tag.characters.length > 32)) {
      return AppLocalizations.of(context).tagTooLong;
    }
    return null;
  }

  List<String> _parsedTags() => _tags.text
      .split(',')
      .map((tag) => tag.trim())
      .where((tag) => tag.isNotEmpty)
      .toList();

  Future<void> _save() async {
    final problem = _firstProblem();
    if (problem != null) {
      setState(() => _problem = problem);
      return;
    }

    setState(() {
      _busy = true;
      _problem = null;
    });

    try {
      final issuer = _issuer.text.trim();
      await widget.controller.rename(
        widget.entry.id,
        // Empty means no issuer, not an issuer named "". The list shows the
        // account alone in that case.
        issuer.isEmpty ? null : issuer,
        _account.text.trim(),
        icon: _icon,
        note: _note.text,
        tags: _parsedTags(),
      );
      if (mounted) Navigator.of(context).pop();
    } catch (error) {
      if (mounted) {
        setState(
          () => _problem = localizedError(AppLocalizations.of(context), error),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return FormPage(
      title: l10n.editEntry,
      actionLabel: l10n.save,
      busy: _busy,
      errorMessage: _problem,
      onAction: _busy ? null : _save,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: Text(l10n.renameSyncDescription),
        ),
        TextField(
          controller: _issuer,
          decoration: InputDecoration(
            labelText: l10n.service,
            hintText: l10n.issuerExample,
            helperText: l10n.optional,
          ),
          textCapitalization: TextCapitalization.words,
          enabled: !_busy,
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _account,
          decoration: InputDecoration(
            labelText: l10n.account,
            hintText: l10n.accountExample,
          ),
          autocorrect: false,
          enabled: !_busy,
          onSubmitted: (_) => _busy ? null : _save(),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _note,
          minLines: 2,
          maxLines: 5,
          maxLength: 512,
          decoration: InputDecoration(
            labelText: l10n.note,
            helperText: l10n.encryptedEntryOptional,
            border: OutlineInputBorder(),
          ),
          enabled: !_busy,
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _tags,
          decoration: InputDecoration(
            labelText: l10n.tags,
            helperText: l10n.tagsHelper,
            hintText: l10n.tagsExample,
            border: OutlineInputBorder(),
          ),
          enabled: !_busy,
        ),
        const SizedBox(height: 24),
        _IconPicker(
          issuer: _issuer.text.trim().isEmpty ? null : _issuer.text.trim(),
          account: _account.text.trim(),
          icon: _icon,
          enabled: !_busy,
          onChanged: (value) => setState(() => _icon = value),
        ),
        const SizedBox(height: 24),
        // Says why the secret is not here, where someone looking for it will
        // be looking. Leaving it unexplained reads as an oversight.
        Card(
          child: ListTile(
            leading: const Icon(Icons.lock_outline),
            title: Text(l10n.secretCannotBeChanged),
            subtitle: Text(l10n.secretCannotBeChangedDescription),
          ),
        ),
      ],
    );
  }
}

/// Picks a service favicon, emoji, or custom image for an entry.
class _IconPicker extends StatefulWidget {
  const _IconPicker({
    required this.issuer,
    required this.account,
    required this.icon,
    required this.enabled,
    required this.onChanged,
  });

  final String? issuer;
  final String account;
  final String? icon;
  final bool enabled;
  final ValueChanged<String?> onChanged;

  @override
  State<_IconPicker> createState() => _IconPickerState();
}

class _IconPickerState extends State<_IconPicker> {
  final _search = TextEditingController();
  static final List<String> _recent = [];
  bool _pickingImage = false;
  String? _imageProblem;

  static const _suggestions = <(String, String)>[
    ('\u{1F4BC}', 'work briefcase business'),
    ('\u{1F3E0}', 'home house personal'),
    ('\u{1F3E6}', 'bank finance savings'),
    ('\u{1F4E7}', 'mail email inbox'),
    ('\u{1F6D2}', 'shop cart store'),
    ('\u{1F3AE}', 'game gaming controller'),
    ('\u{2601}\u{FE0F}', 'cloud server hosting'),
    ('\u{1F511}', 'key password security'),
    ('\u{1F465}', 'people team social'),
    ('\u{1F4B0}', 'money finance wallet'),
    ('\u{1F4BB}', 'computer laptop developer'),
    ('\u{1F4F1}', 'phone mobile'),
    ('\u{1F6E1}\u{FE0F}', 'shield security protection'),
    ('\u{1F512}', 'lock private'),
    ('\u{1F310}', 'web globe internet'),
    ('\u{1F4E6}', 'package delivery'),
    ('\u{1F3EB}', 'school education'),
    ('\u{1F3E5}', 'health hospital medical'),
    ('\u{1F3AE}', 'games entertainment'),
    ('\u{1F3B5}', 'music audio'),
    ('\u{1F3AC}', 'video film streaming'),
    ('\u{1F4F7}', 'photo camera'),
    ('\u{1F4AC}', 'chat message'),
    ('\u{1F4C8}', 'trading chart analytics'),
    ('\u{1FA99}', 'coin crypto finance'),
    ('\u{1F6D2}', 'shopping ecommerce'),
    ('\u{2708}\u{FE0F}', 'travel flight'),
    ('\u{1F697}', 'car transport'),
    ('\u{1F4A1}', 'idea smart home'),
    ('\u{2699}\u{FE0F}', 'settings service tools'),
  ];

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  void _select(String emoji) {
    _recent
      ..remove(emoji)
      ..insert(0, emoji);
    if (_recent.length > 8) _recent.removeLast();
    widget.onChanged(widget.icon == emoji ? null : emoji);
    setState(() {});
  }

  void _selectBrand(ServiceIconOption option) {
    final value = ServiceIconMatcher.selectionValue(option.key);
    widget.onChanged(widget.icon == value ? null : value);
    setState(() {});
  }

  Future<void> _pickImage() async {
    if (_pickingImage || !widget.enabled) return;
    setState(() {
      _pickingImage = true;
      _imageProblem = null;
    });
    try {
      final picked = await FilePicker.pickFile(
        dialogTitle: AppLocalizations.of(context).chooseCustomIcon,
        type: FileType.image,
      );
      if (picked == null || !mounted) return;
      final bytes = await readFileWithLimit(
        picked,
        maximumBytes: CustomIconData.maxInputBytes,
      );
      final encoded = await CustomIconData.encode(bytes);
      if (!mounted) return;
      widget.onChanged(encoded);
    } on FileSizeLimitExceeded {
      if (mounted) {
        setState(
          () => _imageProblem = AppLocalizations.of(context).imageTooLarge,
        );
      }
    } on CustomIconException catch (error) {
      if (mounted) {
        final l10n = AppLocalizations.of(context);
        setState(
          () => _imageProblem = switch (error.problem) {
            CustomIconProblem.empty => l10n.imageFileEmpty,
            CustomIconProblem.tooLarge => l10n.imageTooLarge,
            CustomIconProblem.cannotFit => l10n.imageCannotFitEntry,
          },
        );
      }
    } catch (_) {
      if (mounted) {
        setState(
          () => _imageProblem = AppLocalizations.of(context).imageCouldNotOpen,
        );
      }
    } finally {
      if (mounted) setState(() => _pickingImage = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final query = _search.text.trim().toLowerCase();
    final matches = _suggestions
        .where((choice) => query.isEmpty || choice.$2.contains(query))
        .toList();
    final brandMatches = ServiceIconMatcher.search(query);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(l10n.icon, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 4),
        Text(
          l10n.iconDescription,
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            // The live tile, so the choice is visible rather than described.
            EntryAvatar(
              issuer: widget.issuer,
              account: widget.account,
              icon: widget.icon,
              size: 48,
              forceServiceIcons: true,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: TextField(
                controller: _search,
                enabled: widget.enabled,
                onChanged: (_) => setState(() {}),
                decoration: InputDecoration(
                  labelText: l10n.searchIcons,
                  hintText: l10n.searchIconsHint,
                  prefixIcon: const Icon(Icons.search),
                  border: const OutlineInputBorder(),
                ),
              ),
            ),
          ],
        ),
        if (_recent.isNotEmpty && query.isEmpty) ...[
          const SizedBox(height: 12),
          Text(l10n.recent, style: Theme.of(context).textTheme.labelLarge),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final emoji in _recent)
                _Swatch(
                  label: emoji,
                  selected: widget.icon == emoji,
                  onTap: widget.enabled ? () => _select(emoji) : null,
                ),
            ],
          ),
        ],
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: widget.enabled && !_pickingImage ? _pickImage : null,
          icon: _pickingImage
              ? const SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.image_outlined),
          label: Text(l10n.chooseCustomImage),
        ),
        if (_imageProblem != null) ...[
          const SizedBox(height: 8),
          Text(
            _imageProblem!,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        ],
        const SizedBox(height: 12),
        if (matches.isEmpty && brandMatches.isEmpty)
          Text(l10n.noIconMatches)
        else ...[
          if (brandMatches.isNotEmpty)
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final option in brandMatches)
                  _BrandSwatch(
                    option: option,
                    selected:
                        widget.icon ==
                        ServiceIconMatcher.selectionValue(option.key),
                    onTap: widget.enabled ? () => _selectBrand(option) : null,
                  ),
              ],
            ),
          if (brandMatches.isNotEmpty && matches.isNotEmpty)
            const SizedBox(height: 12),
          if (matches.isNotEmpty)
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final choice in matches)
                  _Swatch(
                    label: choice.$1,
                    selected: widget.icon == choice.$1,
                    onTap: widget.enabled ? () => _select(choice.$1) : null,
                  ),
              ],
            ),
        ],
        if (widget.icon != null) ...[
          const SizedBox(height: 8),
          TextButton.icon(
            icon: const Icon(Icons.close, size: 18),
            label: Text(l10n.useAutomaticLetter),
            onPressed: widget.enabled ? () => widget.onChanged(null) : null,
          ),
        ],
      ],
    );
  }
}

class _BrandSwatch extends StatelessWidget {
  const _BrandSwatch({
    required this.option,
    required this.selected,
    required this.onTap,
  });

  final ServiceIconOption option;
  final bool selected;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final value = ServiceIconMatcher.selectionValue(option.key);
    return Tooltip(
      message: option.label,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.all(2),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: selected ? colours.primary : Colors.transparent,
              width: 2,
            ),
          ),
          child: EntryAvatar(
            issuer: option.label,
            account: option.label,
            icon: value,
            size: 36,
            forceServiceIcons: true,
          ),
        ),
      ),
    );
  }
}

class _Swatch extends StatelessWidget {
  const _Swatch({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        width: 40,
        height: 40,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(8),
          color: selected
              ? colours.primaryContainer
              : colours.surfaceContainerHighest,
          border: selected
              ? Border.all(color: colours.primary, width: 2)
              : null,
        ),
        child: Text(label, style: const TextStyle(fontSize: 20)),
      ),
    );
  }
}
