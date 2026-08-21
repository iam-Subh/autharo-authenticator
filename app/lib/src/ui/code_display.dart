import 'package:flutter/material.dart';

/// Renders a one-time code.
///
/// Two things matter here beyond looking tidy:
///
/// - Tabular figures. Without them the code shifts sideways every time a digit
///   changes, which reads as flicker on a row that updates once a second.
/// - Grouping. A 6-digit code splits 3-3 and an 8-digit code splits 4-4, which
///   is how the issuing services print them. A 7-digit code splits 4-3.
///
/// FR-25 allows the digits to be hidden until the user taps the entry, so the
/// hidden state is part of this widget rather than something the caller fakes
/// by passing a different string.
class CodeDisplay extends StatelessWidget {
  const CodeDisplay({
    super.key,
    required this.code,
    this.hidden = false,
    this.expiring = false,
  });

  /// The code as the core generated it, digits only.
  final String code;

  /// FR-25: hide the digits until the user asks for them.
  final bool hidden;

  /// FR-07: the code is about to change.
  final bool expiring;

  static String group(String code) {
    if (code.length <= 6) {
      final half = (code.length / 2).ceil();
      return '${code.substring(0, half)} ${code.substring(half)}';
    }
    // 7 digits split 4-3, 8 digits split 4-4.
    return '${code.substring(0, 4)} ${code.substring(4)}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colours = theme.colorScheme;

    final style = theme.textTheme.headlineSmall?.copyWith(
      fontFeatures: const [FontFeature.tabularFigures()],
      letterSpacing: 1.5,
      color: expiring ? colours.error : colours.onSurface,
    );

    if (hidden) {
      return Semantics(
        label: 'Code hidden. Activate to show.',
        excludeSemantics: true,
        child: Text('••• •••', style: style),
      );
    }

    return Semantics(
      // NFR-08: a screen reader should read the digits one at a time rather
      // than as a single large number.
      label: code.split('').join(' '),
      excludeSemantics: true,
      child: Text(group(code), style: style),
    );
  }
}
