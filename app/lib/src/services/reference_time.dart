import '../rust/api/vault.dart' as rust;

/// FR-38: "Store the offset between device time and reference time. Apply the
/// offset in the TOTP calculation."
/// FR-39: "Never change the system clock."
/// OFF-07: apply the stored offset when no time server can be reached.
///
/// Every code in the application is generated from [nowSeconds] here. Nothing
/// else may call `DateTime.now()` for the purpose of generating a code — if two
/// call sites read the clock separately, a row and its countdown can land in
/// different time steps and the user sees a code that is already expiring.
class ReferenceTime {
  ReferenceTime._(this._offsetSeconds);

  /// Loads the offset the core has stored for this device.
  static Future<ReferenceTime> load() async {
    final offset = await rust.timeOffsetSeconds();
    return ReferenceTime._(offset);
  }

  int _offsetSeconds;

  /// FR-40: the threshold past which the user is warned.
  static const int warnAboveSeconds = 10;

  /// Seconds to add to the device clock to get the reference time.
  int get offsetSeconds => _offsetSeconds;

  /// FR-40: "Show a warning when the offset is larger than 10 seconds and the
  /// application cannot correct it."
  bool get isDrifting => _offsetSeconds.abs() > warnAboveSeconds;

  /// The corrected time, in seconds since the epoch.
  int get nowSeconds =>
      DateTime.now().millisecondsSinceEpoch ~/ 1000 + _offsetSeconds;

  /// Local wall-clock milliseconds, for `updated_at` and for the HLC.
  ///
  /// This is deliberately *not* offset-corrected. The HLC's ordering comes from
  /// its counter and device identifier, and `updated_at` is display-only, so
  /// neither wants a value that jumps when the offset is re-measured.
  int get nowMillis => DateTime.now().millisecondsSinceEpoch;

  /// Re-reads the offset a sync cycle measured (FR-37).
  ///
  /// The offset is measured in Rust, from the `Date` header of requests the
  /// cycle was making anyway, and written to the store. Without this the
  /// correction would not reach the code list until the next application
  /// start — which is a long time to keep showing codes a service rejects.
  Future<void> refresh() async {
    _offsetSeconds = await rust.timeOffsetSeconds();
  }

  Future<void> setOffsetSeconds(int offset) async {
    await rust.setTimeOffsetSeconds(offset: offset);
    _offsetSeconds = offset;
  }
}
