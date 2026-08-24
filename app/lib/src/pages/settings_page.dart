import 'package:flutter/material.dart';

import '../../l10n/generated/app_localizations.dart';
import '../rust/api/vault.dart' as rust;
import '../services/appearance_preference.dart';
import '../services/lock_controller.dart';
import '../services/brand_icon_preference.dart';
import '../services/code_visibility_preference.dart';
import '../services/screen_capture_service.dart';
import '../services/recovery_status_preference.dart';
import '../services/sync_controller.dart';
import '../services/vault_session.dart';
import '../vault_controller.dart';
import 'backup_page.dart';
import 'create_account_page.dart';
import 'devices_page.dart';
import 'duplicate_manager_page.dart';
import 'home_widget_page.dart';
import 'set_pin_page.dart';
import 'sync_page.dart';
import 'trash_page.dart';

/// The lock settings (FR-31 to FR-36).
///
/// FR-33 says to *offer* the timeout choices, so they need somewhere to live.
/// Without this screen the policy in `meta` would be written once and never
/// changed, and the PIN screen would be unreachable.
class SettingsPage extends StatefulWidget {
  const SettingsPage({
    super.key,
    required this.session,
    required this.lock,
    required this.controller,
  });

  final VaultSession session;
  final LockController lock;

  /// Passed through so a restore can refresh the code list behind this screen.
  final VaultController controller;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  bool _hasPin = false;
  bool _busy = false;
  bool _blockScreenshots = true;
  bool _screenCaptureBusy = true;
  bool _displayPreferenceBusy = false;

  String _timeoutLabel(BuildContext context, LockTimeout timeout) {
    final l10n = AppLocalizations.of(context);
    return switch (timeout) {
      LockTimeout.immediately => l10n.immediately,
      LockTimeout.after15Seconds => l10n.after15Seconds,
      LockTimeout.after1Minute => l10n.after1Minute,
      LockTimeout.after5Minutes => l10n.after5Minutes,
      LockTimeout.after15Minutes => l10n.after15Minutes,
      LockTimeout.never => l10n.never,
    };
  }

  String? _accountEmail;
  final _sync = SyncController();
  final _screenCapture = ScreenCaptureService();

  String get _syncSummary {
    final l10n = AppLocalizations.of(context);
    return switch (_sync.status.state) {
      SyncState.off => l10n.syncIsOff,
      SyncState.synced => l10n.synced,
      SyncState.pending => l10n.pendingChanges,
      SyncState.offline => l10n.offline,
      SyncState.signedOut => l10n.syncSessionExpired,
    };
  }

  @override
  void initState() {
    super.initState();
    _readSlot();
    _readAccount();
    _readScreenCapturePolicy();
    _sync.addListener(_onSyncChanged);
    _sync.refresh();
  }

  void _onSyncChanged() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _sync.removeListener(_onSyncChanged);
    _sync.dispose();
    super.dispose();
  }

  void _readAccount() {
    try {
      setState(() => _accountEmail = rust.accountEmail());
    } catch (_) {
      // A device with no account, or a metadata file that cannot be read.
      // Neither is a reason to fail the screen.
    }
  }

  Future<void> _readScreenCapturePolicy() async {
    try {
      final blocked = await _screenCapture.isBlocked();
      if (!mounted) return;
      setState(() {
        _blockScreenshots = blocked;
        _screenCaptureBusy = false;
      });
    } catch (_) {
      if (!mounted) return;
      // Keep the secure default if the platform cannot report its state.
      setState(() => _screenCaptureBusy = false);
    }
  }

  Future<void> _setScreenCapturePolicy(bool blocked) async {
    if (!blocked) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(AppLocalizations.of(context).allowScreenCaptureQuestion),
          content: Text(AppLocalizations.of(context).allowScreenCaptureWarning),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(AppLocalizations.of(context).cancel),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: Text(AppLocalizations.of(context).allow),
            ),
          ],
        ),
      );
      if (confirmed != true || !mounted) return;
    }
    setState(() => _screenCaptureBusy = true);
    try {
      await _screenCapture.setBlocked(blocked);
      if (!mounted) return;
      setState(() => _blockScreenshots = blocked);
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            AppLocalizations.of(context).screenshotSettingFailed('$error'),
          ),
        ),
      );
    } finally {
      if (mounted) setState(() => _screenCaptureBusy = false);
    }
  }

  Future<void> _setCodeVisibility(bool hide) async {
    setState(() => _displayPreferenceBusy = true);
    try {
      await CodeVisibilityPreference.setHideCodesUntilTap(hide);
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            AppLocalizations.of(context).codeVisibilitySettingFailed('$error'),
          ),
        ),
      );
    } finally {
      if (mounted) setState(() => _displayPreferenceBusy = false);
    }
  }

  Future<void> _chooseTheme() async {
    final chosen = await showDialog<AppThemeChoice>(
      context: context,
      builder: (context) => SimpleDialog(
        title: Text(AppLocalizations.of(context).applicationTheme),
        children: [
          for (final choice in AppThemeChoice.values)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(context, choice),
              child: Row(
                children: [
                  Icon(
                    choice == AppearancePreference.theme.value
                        ? Icons.check
                        : Icons.check_box_outline_blank,
                    color: choice == AppearancePreference.theme.value
                        ? Theme.of(context).colorScheme.primary
                        : Colors.transparent,
                  ),
                  const SizedBox(width: 12),
                  Text(switch (choice) {
                    AppThemeChoice.system => AppLocalizations.of(
                      context,
                    ).useDeviceSetting,
                    AppThemeChoice.light => AppLocalizations.of(
                      context,
                    ).lightTheme,
                    AppThemeChoice.dark => AppLocalizations.of(
                      context,
                    ).darkTheme,
                    AppThemeChoice.amoled => AppLocalizations.of(
                      context,
                    ).amoledTheme,
                  }),
                ],
              ),
            ),
        ],
      ),
    );
    if (chosen == null || !mounted) return;

    setState(() => _displayPreferenceBusy = true);
    try {
      await AppearancePreference.setTheme(chosen);
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            AppLocalizations.of(context).themeSettingFailed('$error'),
          ),
        ),
      );
    } finally {
      if (mounted) setState(() => _displayPreferenceBusy = false);
    }
  }

  Future<void> _chooseListDensity() async {
    final chosen = await showDialog<ListDensityChoice>(
      context: context,
      builder: (context) => SimpleDialog(
        title: Text(AppLocalizations.of(context).accountListSpacing),
        children: [
          for (final choice in ListDensityChoice.values)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(context, choice),
              child: Row(
                children: [
                  _SelectionMark(
                    selected: choice == AppearancePreference.listDensity.value,
                  ),
                  const SizedBox(width: 12),
                  Text(switch (choice) {
                    ListDensityChoice.comfortable => AppLocalizations.of(
                      context,
                    ).comfortableDensity,
                    ListDensityChoice.compact => AppLocalizations.of(
                      context,
                    ).compactDensity,
                  }),
                ],
              ),
            ),
        ],
      ),
    );
    if (chosen == null || !mounted) return;

    setState(() => _displayPreferenceBusy = true);
    try {
      await AppearancePreference.setListDensity(chosen);
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            AppLocalizations.of(context).listSpacingSettingFailed('$error'),
          ),
        ),
      );
    } finally {
      if (mounted) setState(() => _displayPreferenceBusy = false);
    }
  }

  Future<void> _chooseLanguage() async {
    final l10n = AppLocalizations.of(context);
    final chosen = await showDialog<AppLanguageChoice>(
      context: context,
      builder: (context) => SimpleDialog(
        title: Text(l10n.language),
        children: [
          for (final choice in AppLanguageChoice.values)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(context, choice),
              child: Row(
                children: [
                  _SelectionMark(
                    selected: choice == AppearancePreference.language.value,
                  ),
                  const SizedBox(width: 12),
                  Text(switch (choice) {
                    AppLanguageChoice.system => l10n.useDeviceLanguage,
                    AppLanguageChoice.english => l10n.english,
                    AppLanguageChoice.hindi => l10n.hindi,
                  }),
                ],
              ),
            ),
        ],
      ),
    );
    if (chosen == null || !mounted) return;
    await AppearancePreference.setLanguage(chosen);
  }

  /// Asks the core whether this device's slot uses a PIN, rather than keeping
  /// a separate flag that could drift from what is actually stored.
  Future<void> _readSlot() async {
    try {
      final blob = await rust.beginDeviceOpen();
      if (!mounted) return;
      setState(() => _hasPin = blob.needsPin);
    } catch (_) {
      // A slot that cannot be read is not a reason to fail the screen; the
      // rest of the settings still work.
    }
  }

  Future<void> _setPolicy(LockPolicy policy) async {
    setState(() => _busy = true);
    await widget.lock.setPolicy(policy);
    if (!mounted) return;
    setState(() => _busy = false);
  }

  Future<void> _openPinPage() async {
    final changed = await Navigator.push<bool>(
      context,
      MaterialPageRoute(
        builder: (_) =>
            SetPinPage(session: widget.session, hasExistingPin: _hasPin),
      ),
    );
    if (changed == true) await _readSlot();
  }

  /// FR-36: an unlock is required before a destructive action. The vault is
  /// already unlocked to reach this screen, so the confirmation is what stands
  /// in the way — and it says plainly what cannot be undone.
  Future<void> _wipe() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context).wipeThisDeviceQuestion),
        content: Text(AppLocalizations.of(context).wipeThisDeviceWarning),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(AppLocalizations.of(context).cancel),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            onPressed: () => Navigator.pop(context, true),
            child: Text(AppLocalizations.of(context).wipe),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    await widget.session.wipe();
    if (!mounted) return;
    Navigator.of(context).popUntil((route) => route.isFirst);
  }

  @override
  Widget build(BuildContext context) {
    final policy = widget.lock.policy;
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.settings)),
      body: ListView(
        children: [
          _SectionHeader(l10n.applicationLock),
          ListTile(
            leading: const Icon(Icons.pin_outlined),
            title: Text(_hasPin ? l10n.changePin : l10n.setPin),
            subtitle: Text(
              _hasPin ? l10n.pinRequiredDescription : l10n.pinNotSetDescription,
            ),
            onTap: _busy ? null : _openPinPage,
          ),
          ListTile(
            leading: const Icon(Icons.timer_outlined),
            title: Text(l10n.lockAfter),
            subtitle: Text(_timeoutLabel(context, policy.timeout)),
            onTap: _busy ? null : _chooseTimeout,
          ),
          SwitchListTile(
            secondary: const Icon(Icons.visibility_off_outlined),
            title: Text(l10n.lockWhenLeaving),
            subtitle: Text(l10n.lockWhenLeavingDescription),
            value: policy.lockOnBackground,
            onChanged: _busy
                ? null
                : (value) =>
                      _setPolicy(policy.copyWith(lockOnBackground: value)),
          ),
          // FR-35. Placed after the ordinary lock settings and never
          // presented as a recommendation: it is the only setting in this app
          // that can destroy the vault, and it is off unless asked for.
          ListTile(
            leading: Icon(
              policy.wipeAfterFailures == null
                  ? Icons.shield_outlined
                  : Icons.gpp_maybe_outlined,
              color: policy.wipeAfterFailures == null
                  ? null
                  : Theme.of(context).colorScheme.error,
            ),
            title: Text(l10n.wipeAfterFailedAttempts),
            subtitle: Text(
              policy.wipeAfterFailures == null
                  ? l10n.wipeAttemptsOff
                  : l10n.wipeAttemptsOn(policy.wipeAfterFailures!),
            ),
            onTap: _busy ? null : _chooseWipeThreshold,
          ),
          ListTile(
            leading: const Icon(Icons.lock_outline),
            title: Text(l10n.lockNow),
            onTap: _busy
                ? null
                : () {
                    widget.lock.lockNow();
                    Navigator.of(context).popUntil((route) => route.isFirst);
                  },
          ),
          const Divider(),
          _SectionHeader(l10n.sync),
          if (_accountEmail == null)
            ListTile(
              leading: const Icon(Icons.cloud_outlined),
              title: Text(l10n.createAccount),
              subtitle: Text(l10n.createAccountDescription),
              onTap: _busy
                  ? null
                  : () async {
                      final created = await Navigator.push<bool>(
                        context,
                        MaterialPageRoute(
                          builder: (_) =>
                              CreateAccountPage(session: widget.session),
                        ),
                      );
                      if (created == true) _readAccount();
                    },
            )
          else ...[
            ListTile(
              leading: const Icon(Icons.cloud_done_outlined),
              title: Text(l10n.account),
              subtitle: Text(_accountEmail!),
            ),
            ValueListenableBuilder<bool>(
              valueListenable: RecoveryStatusPreference.confirmed,
              builder: (context, confirmed, _) => ListTile(
                leading: Icon(
                  confirmed
                      ? Icons.verified_user_outlined
                      : Icons.warning_amber_outlined,
                  color: confirmed ? null : Theme.of(context).colorScheme.error,
                ),
                title: Text(l10n.recoveryPhrase),
                subtitle: Text(
                  confirmed
                      ? l10n.recoveryConfirmed
                      : l10n.recoveryNotConfirmed,
                ),
                trailing: const Icon(Icons.chevron_right),
                onTap: _busy
                    ? null
                    : () => Navigator.push(
                        context,
                        MaterialPageRoute<void>(
                          builder: (_) =>
                              BackupPage(controller: widget.controller),
                        ),
                      ),
              ),
            ),
            // §9.5. Beneath the account it belongs to, because "I lost my
            // phone" sends people looking for their account first — a devices
            // entry filed anywhere else is one they will not find at the
            // moment they need it.
            ListTile(
              leading: const Icon(Icons.devices_outlined),
              title: Text(l10n.yourDevices),
              subtitle: Text(l10n.yourDevicesDescription),
              onTap: _busy
                  ? null
                  : () async {
                      await Navigator.of(context).push(
                        MaterialPageRoute<void>(
                          builder: (deviceContext) => DevicesPage(
                            // Back to Settings, which re-reads the account on
                            // return. Leaving the user on a device list that
                            // can no longer load would show them an error for
                            // something that worked exactly as asked.
                            onSignedOut: () =>
                                Navigator.of(deviceContext).pop(),
                          ),
                        ),
                      );
                      if (mounted) _readAccount();
                    },
            ),
          ],
          const Divider(),
          _SectionHeader(l10n.sync),
          ListTile(
            leading: const Icon(Icons.cloud_outlined),
            title: Text(l10n.sync),
            subtitle: Text(_syncSummary),
            onTap: _busy
                ? null
                : () async {
                    await Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => SyncPage(controller: _sync),
                      ),
                    );
                    if (mounted) setState(() {});
                  },
          ),
          const Divider(),
          _SectionHeader(l10n.dataManagement),
          ListTile(
            leading: const Icon(Icons.delete_outline),
            title: Text(l10n.trash),
            subtitle: Text(l10n.trashDescription),
            onTap: _busy
                ? null
                : () => Navigator.push(
                    context,
                    MaterialPageRoute<void>(
                      builder: (_) => TrashPage(controller: widget.controller),
                    ),
                  ),
          ),
          ListTile(
            leading: const Icon(Icons.content_copy_outlined),
            title: Text(l10n.duplicateAccounts),
            subtitle: Text(l10n.duplicateAccountsDescription),
            onTap: _busy
                ? null
                : () => Navigator.push(
                    context,
                    MaterialPageRoute<void>(
                      builder: (_) =>
                          DuplicateManagerPage(controller: widget.controller),
                    ),
                  ),
          ),
          const Divider(),
          _SectionHeader(l10n.backup),
          ListTile(
            leading: const Icon(Icons.save_outlined),
            title: Text(l10n.backupAndRestore),
            subtitle: Text(l10n.backupAndRestoreDescription),
            onTap: _busy
                ? null
                : () => Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => BackupPage(controller: widget.controller),
                    ),
                  ),
          ),
          const Divider(),
          _SectionHeader(l10n.appearanceAndPrivacy),
          ValueListenableBuilder<AppLanguageChoice>(
            valueListenable: AppearancePreference.language,
            builder: (context, language, _) => ListTile(
              leading: const Icon(Icons.language_outlined),
              title: Text(l10n.language),
              subtitle: Text(switch (language) {
                AppLanguageChoice.system => l10n.useDeviceLanguage,
                AppLanguageChoice.english => l10n.english,
                AppLanguageChoice.hindi => l10n.hindi,
              }),
              onTap: _displayPreferenceBusy ? null : _chooseLanguage,
            ),
          ),
          ValueListenableBuilder<AppThemeChoice>(
            valueListenable: AppearancePreference.theme,
            builder: (context, choice, _) => ListTile(
              leading: const Icon(Icons.contrast_outlined),
              title: Text(l10n.theme),
              subtitle: Text(switch (choice) {
                AppThemeChoice.system => l10n.useDeviceSetting,
                AppThemeChoice.light => l10n.lightTheme,
                AppThemeChoice.dark => l10n.darkTheme,
                AppThemeChoice.amoled => l10n.amoledTheme,
              }),
              onTap: _displayPreferenceBusy ? null : _chooseTheme,
            ),
          ),
          ValueListenableBuilder<ListDensityChoice>(
            valueListenable: AppearancePreference.listDensity,
            builder: (context, density, _) => ListTile(
              leading: const Icon(Icons.density_medium_outlined),
              title: Text(l10n.accountListSpacing),
              subtitle: Text(switch (density) {
                ListDensityChoice.comfortable => l10n.comfortableDensity,
                ListDensityChoice.compact => l10n.compactDensity,
              }),
              onTap: _displayPreferenceBusy ? null : _chooseListDensity,
            ),
          ),
          if (Theme.of(context).platform == TargetPlatform.android)
            ValueListenableBuilder<bool>(
              valueListenable: AppearancePreference.useDynamicColour,
              builder: (context, enabled, _) => SwitchListTile(
                secondary: const Icon(Icons.palette_outlined),
                title: Text(l10n.useDeviceColours),
                subtitle: Text(
                  AppearancePreference.dynamicSeed.value == null
                      ? l10n.usesApplicationColour
                      : l10n.usesMaterialYouColour,
                ),
                value: enabled,
                onChanged: _displayPreferenceBusy
                    ? null
                    : (value) async {
                        setState(() => _displayPreferenceBusy = true);
                        try {
                          await AppearancePreference.setUseDynamicColour(value);
                        } finally {
                          if (mounted) {
                            setState(() => _displayPreferenceBusy = false);
                          }
                        }
                      },
              ),
            ),
          ValueListenableBuilder<bool>(
            valueListenable: CodeVisibilityPreference.hideCodesUntilTap,
            builder: (context, hide, _) => SwitchListTile(
              secondary: const Icon(Icons.password_outlined),
              title: Text(l10n.hideCodesUntilTapped),
              subtitle: Text(
                hide
                    ? l10n.codesHiddenDescription
                    : l10n.codesVisibleDescription,
              ),
              value: hide,
              onChanged: _displayPreferenceBusy ? null : _setCodeVisibility,
            ),
          ),
          _SectionHeader(l10n.thisDevice),
          ValueListenableBuilder<bool>(
            valueListenable: BrandIconPreference.enabled,
            builder: (context, enabled, _) => SwitchListTile(
              secondary: const Icon(Icons.widgets_outlined),
              title: Text(l10n.useBuiltInIcons),
              subtitle: Text(l10n.useBuiltInIconsDescription),
              value: enabled,
              onChanged: _busy
                  ? null
                  : (value) async {
                      setState(() => _busy = true);
                      try {
                        await BrandIconPreference.setEnabled(value);
                      } finally {
                        if (mounted) setState(() => _busy = false);
                      }
                    },
            ),
          ),
          if (Theme.of(context).platform == TargetPlatform.android)
            ListTile(
              leading: const Icon(Icons.add_to_home_screen_outlined),
              title: Text(l10n.homeScreenWidget),
              subtitle: Text(l10n.homeScreenWidgetDescription),
              onTap: _busy
                  ? null
                  : () => Navigator.push(
                      context,
                      MaterialPageRoute<void>(
                        builder: (_) =>
                            HomeWidgetPage(controller: widget.controller),
                      ),
                    ),
            ),
          SwitchListTile(
            secondary: const Icon(Icons.screenshot_monitor_outlined),
            title: Text(l10n.blockScreenshots),
            subtitle: Text(
              _blockScreenshots
                  ? l10n.screenshotsBlocked
                  : l10n.screenshotsAllowed,
            ),
            value: _blockScreenshots,
            onChanged: _screenCaptureBusy ? null : _setScreenCapturePolicy,
          ),
          ListTile(
            leading: Icon(
              Icons.delete_forever_outlined,
              color: Theme.of(context).colorScheme.error,
            ),
            title: Text(
              l10n.wipeThisDevice,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
            subtitle: Text(l10n.wipeThisDeviceDescription),
            onTap: _busy ? null : _wipe,
          ),
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(l10n.lockingExplanation),
          ),
        ],
      ),
    );
  }

  Future<void> _chooseTimeout() async {
    final chosen = await showDialog<LockTimeout>(
      context: context,
      builder: (context) => SimpleDialog(
        title: Text(AppLocalizations.of(context).lockAfter),
        children: [
          for (final choice in LockTimeout.values)
            ListTile(
              leading: _SelectionMark(
                selected: choice == widget.lock.policy.timeout,
              ),
              title: Text(_timeoutLabel(context, choice)),
              onTap: () => Navigator.pop(context, choice),
            ),
        ],
      ),
    );
    if (chosen == null) return;
    await _setPolicy(widget.lock.policy.copyWith(timeout: chosen));
  }

  /// FR-35: arming or disarming the wipe.
  Future<void> _chooseWipeThreshold() async {
    final policy = widget.lock.policy;
    final choice = await showModalBottomSheet<_Choice>(
      context: context,
      isScrollControlled: true,
      builder: (_) => _WipeThresholdSheet(current: policy.wipeAfterFailures),
    );
    // Backing out is not the same as choosing "Off", which is why the sheet
    // returns a wrapper. Treating them alike would silently disarm a setting
    // the user turned on.
    if (choice == null || !mounted) return;

    // Turning it *on* is confirmed again; turning it off is not. The
    // confirmation exists for the irreversible direction only — making someone
    // confirm that they want to stop deleting their own data is friction with
    // no failure behind it.
    if (choice.value != null) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          icon: Icon(
            Icons.warning_amber_outlined,
            color: Theme.of(context).colorScheme.error,
          ),
          title: Text(AppLocalizations.of(context).deleteAfterAttemptsQuestion),
          content: Text(
            AppLocalizations.of(
              context,
            ).deleteAfterAttemptsWarning(choice.value!),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(AppLocalizations.of(context).cancel),
            ),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.error,
              ),
              onPressed: () => Navigator.pop(context, true),
              child: Text(AppLocalizations.of(context).turnItOn),
            ),
          ],
        ),
      );
      if (confirmed != true || !mounted) return;
    }

    await _setPolicy(
      policy.copyWith(
        wipeAfterFailures: choice.value,
        clearWipe: choice.value == null,
      ),
    );
  }
}

/// FR-35's threshold, behind a screen that says what it costs.
///
/// The band comes from the core rather than being restated here, so the numbers
/// the user is offered and the numbers the core will accept cannot drift into
/// disagreeing.
class _WipeThresholdSheet extends StatelessWidget {
  const _WipeThresholdSheet({required this.current});

  /// Null means off.
  final int? current;

  @override
  Widget build(BuildContext context) {
    final colours = Theme.of(context).colorScheme;
    final (minimum, maximum) = rust.wipeThresholdRange();

    // Every fifth value across the band, rather than each one. Choosing
    // between 11 and 12 attempts is a decision nobody has an opinion about,
    // and a list of sixteen radio buttons hides the one that matters.
    final choices = <int>[
      for (var count = minimum; count <= maximum; count += 5) count,
    ];

    return SafeArea(
      child: ListView(
        shrinkWrap: true,
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  AppLocalizations.of(context).wipeAfterFailedAttempts,
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 12),
                Text(
                  AppLocalizations.of(context).wipeThresholdExplanation,
                  style: TextStyle(color: colours.onSurfaceVariant),
                ),
              ],
            ),
          ),
          const Divider(),
          ListTile(
            leading: _SelectionMark(selected: current == null),
            title: Text(AppLocalizations.of(context).off),
            subtitle: Text(AppLocalizations.of(context).wrongAttemptsCounted),
            onTap: () => Navigator.pop(context, const _Choice(null)),
          ),
          for (final count in choices)
            ListTile(
              leading: _SelectionMark(selected: current == count),
              title: Text(
                AppLocalizations.of(context).afterWrongAttempts(count),
              ),
              onTap: () => Navigator.pop(context, _Choice(count)),
            ),
          const SizedBox(height: 8),
        ],
      ),
    );
  }
}

/// Wraps the chosen value so that "the user picked Off" and "the user backed
/// out without choosing" are distinguishable. Both would otherwise be null,
/// and confusing them would silently disarm a setting somebody turned on.
class _Choice {
  const _Choice(this.value);

  final int? value;
}

class _SelectionMark extends StatelessWidget {
  const _SelectionMark({required this.selected});

  final bool selected;

  @override
  Widget build(BuildContext context) {
    return Icon(
      Icons.check,
      color: selected
          ? Theme.of(context).colorScheme.primary
          : Colors.transparent,
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelLarge?.copyWith(
          color: Theme.of(context).colorScheme.primary,
        ),
      ),
    );
  }
}
