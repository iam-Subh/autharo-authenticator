import 'package:flutter/foundation.dart';

import '../rust/api/sync.dart' as rust;
import 'sync_scheduler.dart';

/// The three states OFF-05 requires, and what each one tells the user.
///
/// Derived from the facts the core reports, never stored. A stored state goes
/// stale the moment anything happens without writing it back, and the one thing
/// a status indicator must not do is confidently report the wrong answer — a
/// user who has been told "synced" does not check again.
enum SyncState {
  /// No account on this device. Sync is optional (OFF-04), so this is not a
  /// problem to report — it is a feature the user has not asked for.
  off,

  /// Everything this device holds has reached the server.
  synced,

  /// Local changes are waiting. Normal, and not an error: a device that is
  /// offline for a week is still working correctly.
  pending,

  /// The last attempt failed. Distinct from `pending` because the cause is
  /// different and so is what the user can do about it.
  offline,

  /// The session has expired or been revoked. The only state that needs the
  /// user to act, which is why it is not folded into `offline`.
  signedOut,
}

/// A snapshot of where sync stands.
@immutable
class SyncStatus {
  const SyncStatus({
    required this.state,
    this.serverUrl,
    this.email,
    this.pending = 0,
    this.pendingKnown = false,
    this.lastSuccess,
    this.lastError,
  });

  const SyncStatus.off() : this(state: SyncState.off);

  final SyncState state;
  final String? serverUrl;
  final String? email;
  final int pending;

  /// False while the vault is locked: the outbox is inside the encrypted
  /// database. "Nothing waiting" and "cannot tell" must not look the same.
  final bool pendingKnown;

  final DateTime? lastSuccess;
  final String? lastError;

  bool get isConfigured => serverUrl != null;
  bool get isSignedIn =>
      state != SyncState.off && state != SyncState.signedOut;

  /// One line for the code list, in the user's terms rather than the system's.
  String get summary => switch (state) {
    SyncState.off => 'Not syncing',
    SyncState.synced =>
      lastSuccess == null ? 'Synced' : 'Synced ${_ago(lastSuccess!)}',
    SyncState.pending => pendingKnown
        ? '$pending waiting to sync'
        : 'Waiting to sync',
    SyncState.offline => 'Not connected',
    SyncState.signedOut => 'Signed out — sign in to keep syncing',
  };

  static String _ago(DateTime at) {
    final gap = DateTime.now().difference(at);
    if (gap.inSeconds < 60) return 'just now';
    if (gap.inMinutes < 60) return '${gap.inMinutes} min ago';
    if (gap.inHours < 24) return '${gap.inHours} h ago';
    return '${gap.inDays} d ago';
  }
}

/// Reads the sync state and runs cycles, without blocking the interface
/// (OFF-08).
class SyncController extends ChangeNotifier implements SyncRunner {
  SyncController({this.onCycleComplete});

  /// Run after every cycle, successful or not.
  ///
  /// Used for FR-37: the cycle measures the device clock from the `Date`
  /// header of requests it was making anyway, and writes the offset to the
  /// store. Something has to tell the code list to re-read it, or the
  /// correction would not appear until the next application start — which is a
  /// long time to keep showing codes a service rejects.
  ///
  /// Called on failure too, because a failed cycle still measures: the request
  /// reached the server far enough to get a response.
  final Future<void> Function()? onCycleComplete;

  SyncStatus _status = const SyncStatus.off();
  bool _busy = false;

  SyncStatus get status => _status;
  bool get busy => _busy;

  /// Re-reads the state. Cheap and local: it touches no network.
  Future<void> refresh() async {
    try {
      final view = rust.syncStatus();
      _status = derive(view);
    } catch (_) {
      // Reading the status must never be the thing that breaks a screen. A
      // vault that is not open yet throws here, and "not syncing" is the
      // honest answer in that case.
      _status = const SyncStatus.off();
    }
    notifyListeners();
  }

  /// Runs one cycle. Returns null when it succeeded, or a message to show.
  ///
  /// `force` is true when a person asked. OFF-06's backoff exists to stop
  /// automatic retries hammering a failing server; applying it to a button the
  /// user just pressed would mean an app that visibly does nothing, which is
  /// indistinguishable from one that is broken.
  Future<String?> syncNow({bool force = true}) async {
    if (_busy) return null;
    _busy = true;
    notifyListeners();

    String? problem;
    try {
      final run = await rust.syncNow(force: force);
      if (run.needsSignIn) {
        problem = 'This device has been signed out. Sign in to keep syncing.';
      }
      // A skipped attempt is not a failure and must not be reported as one.
      // It is also not a success: leaving it silent would have the caller
      // believe a cycle ran.
    } catch (error) {
      problem = '$error';
    } finally {
      _busy = false;
      await onCycleComplete?.call();
      await refresh();
    }
    return problem;
  }

  /// Runs a cycle only if OFF-06's schedule allows it. For automatic triggers.
  @override
  Future<void> syncIfDue() => syncNow(force: false);

  /// Whether there is an account to sync with (OFF-04).
  @override
  bool get isSignedIn => _status.isSignedIn;

  /// Turns what the core reports into what the user is shown.
  ///
  /// Public so it can be tested without a device, a vault, or a server. The
  /// ordering below is the whole of the logic and it is easy to get subtly
  /// wrong — a stale error outranking a fresh success would leave the app
  /// reporting an outage that ended an hour ago.
  @visibleForTesting
  static SyncStatus derive(rust.SyncStatusView view) {
    final lastSuccess = view.lastSuccessMs == null
        ? null
        : DateTime.fromMillisecondsSinceEpoch(view.lastSuccessMs!);

    // Order matters. Signed out outranks everything, because nothing else can
    // make progress until it is fixed. A pending count outranks an old error,
    // because the error may already have been overtaken.
    final SyncState state;
    if (view.serverUrl == null || view.email == null) {
      state = SyncState.off;
    } else if (!view.signedIn) {
      state = SyncState.signedOut;
    } else if (view.lastError != null) {
      state = SyncState.offline;
    } else if (view.pendingKnown && view.pending > 0) {
      state = SyncState.pending;
    } else {
      state = SyncState.synced;
    }

    return SyncStatus(
      state: state,
      serverUrl: view.serverUrl,
      email: view.email,
      pending: view.pending,
      pendingKnown: view.pendingKnown,
      lastSuccess: lastSuccess,
      lastError: view.lastError,
    );
  }
}
