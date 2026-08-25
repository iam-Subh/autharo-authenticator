import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../services/brand_icon_preference.dart';
import '../services/custom_icon_data.dart';
import '../services/service_icon_matcher.dart';

/// The tile at the start of every row in the code list (FR-17, FR-23).
///
/// The app first uses the QR issuer to select a bundled service icon. It uses
/// the account domain if the QR issuer does not match. This process does not
/// send the issuer or account name to an icon server.
///
/// An unknown service gets a stable colour and letter. A user-selected emoji
/// or encrypted image always overrides the automatic icon.
class EntryAvatar extends StatelessWidget {
  const EntryAvatar({
    super.key,
    required this.issuer,
    required this.account,
    this.icon,
    this.size = 40,
    this.forceServiceIcons = false,
  });

  /// What the entry calls itself. Drives both the letter and the colour.
  final String? issuer;

  /// Used only when there is no issuer, so an entry is never blank.
  final String account;

  /// The user's own choice, if they made one. An emoji, a small encrypted PNG,
  /// or empty.
  final String? icon;

  final double size;

  /// Shows the automatic preview in the icon picker even when the list-level
  /// service-icon preference is off.
  final bool forceServiceIcons;

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
      builder: (context, useServiceIcons, _) => _buildAvatar(
        context,
        useServiceIcons: forceServiceIcons || useServiceIcons,
      ),
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

    final storedChoice = icon?.trim() ?? '';
    // Older builds could persist the generated first letter as if it were a
    // user choice. Treat a matching one-letter value as automatic so existing
    // Google entries do not stay on the old blue "G" tile.
    final chosen =
        storedChoice.characters.length == 1 &&
            storedChoice.toUpperCase() == _monogram
        ? ''
        : storedChoice;
    final customImage = CustomIconData.decode(chosen);
    final selectedServiceIcon = ServiceIconMatcher.fromStoredIcon(chosen);
    final serviceIcon =
        selectedServiceIcon ??
        (chosen.isEmpty && useServiceIcons
            ? ServiceIconMatcher.match(issuer: issuer, account: account)
            : null);
    final background = serviceIcon?.faviconUri != null
        ? Colors.white
        : serviceIcon?.colour ?? fallbackBackground;
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
            : _serviceVisual(serviceIcon, foreground),
      ),
    );
  }

  Widget _serviceVisual(ServiceIconMatch match, Color foreground) {
    final favicon = match.faviconUri;
    if (favicon == null) return _serviceGlyph(match, foreground);
    return Padding(
      padding: EdgeInsets.all(size * 0.14),
      child: Image.network(
        favicon.toString(),
        width: size * 0.72,
        height: size * 0.72,
        fit: BoxFit.contain,
        filterQuality: FilterQuality.medium,
        gaplessPlayback: true,
        errorBuilder: (_, _, _) => _serviceGlyph(match, foreground),
      ),
    );
  }

  Widget _serviceGlyph(ServiceIconMatch match, Color foreground) {
    return match.icon is FaIconData
        ? FaIcon(match.icon as FaIconData, size: size * 0.55, color: foreground)
        : Icon(match.icon as IconData, size: size * 0.55, color: foreground);
  }
}
