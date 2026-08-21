import 'dart:math' as math;

import 'package:flutter/material.dart';

/// FR-07: "Show a countdown indicator for each TOTP entry. Change the indicator
/// colour when 5 seconds remain."
///
/// The ring is driven by a value the caller supplies rather than by an internal
/// timer, so that every row on screen advances from the same reference time.
/// One timer for the whole list keeps NFR-02 reachable at 500 entries; a timer
/// per row would not.
class CountdownRing extends StatelessWidget {
  const CountdownRing({
    super.key,
    required this.remainingSeconds,
    required this.period,
    this.size = 28,
    this.strokeWidth = 3,
  });

  /// Seconds until the current code expires, from 1 up to [period].
  final int remainingSeconds;

  /// The entry's period in seconds.
  final int period;

  final double size;
  final double strokeWidth;

  /// FR-07: the threshold at which the indicator changes colour.
  static const int warningThresholdSeconds = 5;

  bool get _isExpiring => remainingSeconds <= warningThresholdSeconds;

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final progress = period <= 0 ? 0.0 : remainingSeconds / period;

    return Semantics(
      // NFR-08: a ring conveys nothing to a screen reader on its own.
      label: 'Code expires in $remainingSeconds seconds',
      excludeSemantics: true,
      child: SizedBox(
        width: size,
        height: size,
        child: Stack(
          alignment: Alignment.center,
          children: [
            CustomPaint(
              size: Size.square(size),
              painter: _RingPainter(
                progress: progress.clamp(0.0, 1.0),
                strokeWidth: strokeWidth,
                trackColour: colours.surfaceContainerHighest,
                progressColour: _isExpiring ? colours.error : colours.primary,
              ),
            ),
            Text(
              '$remainingSeconds',
              style: Theme.of(context).textTheme.labelSmall?.copyWith(
                color: _isExpiring ? colours.error : colours.onSurfaceVariant,
                fontFeatures: const [FontFeature.tabularFigures()],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _RingPainter extends CustomPainter {
  const _RingPainter({
    required this.progress,
    required this.strokeWidth,
    required this.trackColour,
    required this.progressColour,
  });

  final double progress;
  final double strokeWidth;
  final Color trackColour;
  final Color progressColour;

  @override
  void paint(Canvas canvas, Size size) {
    final centre = Offset(size.width / 2, size.height / 2);
    final radius = (size.shortestSide - strokeWidth) / 2;

    final track = Paint()
      ..color = trackColour
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth;
    canvas.drawCircle(centre, radius, track);

    if (progress <= 0) return;

    final arc = Paint()
      ..color = progressColour
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;
    canvas.drawArc(
      Rect.fromCircle(center: centre, radius: radius),
      -math.pi / 2,
      -2 * math.pi * progress,
      false,
      arc,
    );
  }

  @override
  bool shouldRepaint(_RingPainter old) =>
      old.progress != progress ||
      old.progressColour != progressColour ||
      old.trackColour != trackColour ||
      old.strokeWidth != strokeWidth;
}
