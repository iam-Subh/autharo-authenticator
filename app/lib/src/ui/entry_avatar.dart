import 'package:flutter/material.dart';

import '../services/brand_icon_preference.dart';
import '../services/custom_icon_data.dart';
import '../services/service_icon_matcher.dart';

/// The tile at the start of every row in the code list (FR-17, FR-23).
///
/// # Why this is not an icon pack
///
/// FR-23's icon pack means shipping a few hundred brand logos. Every one of
/// them is somebody's trademark, licensed on terms that differ per brand, and
/// the sets that circulate for this purpose are assembled without permission —
/// which is a problem that arrives at release, not at build time, and arrives
/// as a store takedown rather than a bug report.
///
/// It also fails at exactly the moment it matters. A pack covers the fifty
/// services everyone has heard of; a real vault is full of the other kind — a
/// company VPN, a bank in one country, a self-hosted mail server. Those get the
/// blank placeholder, and the blank placeholder is where the user's eye stops.
///
/// # What actually solves the problem
///
/// The job is *telling forty rows apart at a glance while a code is expiring*.
/// A colour and a letter do that, and they do it for every entry rather than
/// for the famous ones.
///
/// The colour is derived from the issuer, so it is stable: the same account is
/// the same colour on every device, after a restore, and after a re-import,
/// without anything being stored or synced to make it so. Two accounts at the
/// same service share a colour, which is correct — they belong together.
///
/// A user who wants something specific can set an emoji instead, and that
/// *is* stored, syncs with the entry, and survives export.
class EntryAvatar extends StatelessWidget {
  const EntryAvatar({
    super.key,
    required this.issuer,
    required this.account,
    this.icon,
    this.size = 40,
  });

  /// What the entry calls itself. Drives both the letter and the colour.
  final String? issuer;

  /// Used only when there is no issuer, so an entry is never blank.
  final String account;

  /// The user's own choice, if they made one. An emoji, a small encrypted PNG,
  /// or empty.
  final String? icon;

  final double size;

  /// The name the tile is built from.
  String get _source {
    final chosen = issuer?.trim();
    if (chosen != null && chosen.isNotEmpty) return chosen;
    return account.trim();
  }

  /// The first letter, or the first character of anything that has no letters
  /// in it — a Cyrillic or CJK name must still produce a tile rather than a
  /// blank one.
  String get _monogram {
    final source = _source;
    if (source.isEmpty) return '?';
    // Skips leading punctuation, which is common in self-hosted service names
    // ("[work] mail") and would otherwise give every one of them the same
    // bracket.
    for (final rune in source.runes) {
      final character = String.fromCharCode(rune);
      if (character.trim().isEmpty) continue;
      if (RegExp(r'[\p{L}\p{N}]', unicode: true).hasMatch(character)) {
        return character.toUpperCase();
      }
    }
    return source.characters.isEmpty ? '?' : source[0].toUpperCase();
  }

  /// A stable hue from the name.
  ///
  /// FNV-1a over the code units. Any stable hash works; this one is four lines
  /// and has no dependency. What matters is that it is computed the same way
  /// everywhere and never stored — a colour written into the entry would have
  /// to sync, conflict, and migrate, for a decoration.
  ///
  /// Case is folded first, so "GitHub" and "github" from two different
  /// exporters do not land as two different colours for the same service.
  int get _hue {
    var hash = 0x811c9dc5;
    for (final unit in _source.toLowerCase().codeUnits) {
      hash ^= unit;
      hash = (hash * 0x01000193) & 0xffffffff;
    }
    return hash % 360;
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<bool>(
      valueListenable: BrandIconPreference.enabled,
      builder: (context, useServiceIcons, _) =>
          _buildAvatar(context, useServiceIcons: useServiceIcons),
    );
  }

  Widget _buildAvatar(BuildContext context, {required bool useServiceIcons}) {
    final dark = Theme.of(context).brightness == Brightness.dark;

    // Fixed saturation and lightness rather than a free-running palette: the
    // hue carries the identity, and letting the other two vary produces tiles
    // that are unreadable at one end of the range and washed out at the other.
    // The dark-theme pair is not the light one inverted — a tile that passes
    // contrast on white fails on black.
    final fallbackBackground = HSLColor.fromAHSL(
      1,
      _hue.toDouble(),
      dark ? 0.35 : 0.55,
      dark ? 0.30 : 0.86,
    ).toColor();
    final fallbackForeground = HSLColor.fromAHSL(
      1,
      _hue.toDouble(),
      dark ? 0.55 : 0.65,
      dark ? 0.82 : 0.28,
    ).toColor();

    final chosen = icon?.trim() ?? '';
    final customImage = CustomIconData.decode(chosen);
    final serviceIcon = chosen.isEmpty && useServiceIcons
        ? ServiceIconMatcher.match(issuer: issuer, account: account)
        : null;
    final background = serviceIcon?.colour ?? fallbackBackground;
    final foreground = serviceIcon == null
        ? fallbackForeground
        : ThemeData.estimateBrightnessForColor(background) == Brightness.dark
        ? Colors.white
        : Colors.black;

    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(size / 4),
      ),
      clipBehavior: Clip.antiAlias,
      // Excluded from semantics: the row already announces the issuer and the
      // account, and a screen reader saying "G" before it is noise.
      child: ExcludeSemantics(
        child: customImage != null
            ? Image.memory(
                customImage,
                width: size,
                height: size,
                fit: BoxFit.cover,
                filterQuality: FilterQuality.medium,
                gaplessPlayback: true,
                errorBuilder: (_, _, _) => Text(
                  _monogram,
                  style: TextStyle(
                    fontSize: size * 0.42,
                    fontWeight: FontWeight.w600,
                    color: foreground,
                  ),
                ),
              )
            : serviceIcon == null
            ? Text(
                chosen.isNotEmpty && !CustomIconData.isCustom(chosen)
                    ? chosen
                    : _monogram,
                style: TextStyle(
                  fontSize: size * (chosen.isNotEmpty ? 0.5 : 0.42),
                  fontWeight: FontWeight.w600,
                  color: foreground,
                ),
              )
            : Icon(serviceIcon.icon, size: size * 0.55, color: foreground),
      ),
    );
  }
}
