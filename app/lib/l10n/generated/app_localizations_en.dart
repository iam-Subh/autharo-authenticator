// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'Authenticator';

  @override
  String get openingAuthenticator => 'Opening authenticator…';

  @override
  String get lockedTitle => 'Locked';

  @override
  String get lockedBody => 'Your codes are encrypted until you unlock.';

  @override
  String get unlock => 'Unlock';

  @override
  String get useBiometrics => 'Use biometrics';

  @override
  String get useAccountPassword => 'Use account password';

  @override
  String get useRecoveryPhrase => 'Use recovery phrase';

  @override
  String get settings => 'Settings';

  @override
  String get appearanceAndPrivacy => 'Appearance and privacy';

  @override
  String get theme => 'Theme';

  @override
  String get accountListSpacing => 'Account list spacing';

  @override
  String get hideCodesUntilTapped => 'Hide codes until tapped';

  @override
  String get useDeviceColours => 'Use device colours';

  @override
  String get language => 'Language';

  @override
  String get useDeviceLanguage => 'Use device language';

  @override
  String get english => 'English';

  @override
  String get hindi => 'Hindi';

  @override
  String get applicationLock => 'Application lock';

  @override
  String get changePin => 'Change PIN';

  @override
  String get setPin => 'Set a PIN';

  @override
  String get pinRequiredDescription =>
      'Required along with this device\'s key to open your codes.';

  @override
  String get pinNotSetDescription =>
      'Without one, anyone who unlocks this device can read your codes.';

  @override
  String get lockAfter => 'Lock after';

  @override
  String get lockWhenLeaving => 'Lock when leaving the app';

  @override
  String get lockWhenLeavingDescription =>
      'Locks the moment the app is no longer on screen.';

  @override
  String get wipeAfterFailedAttempts => 'Wipe after failed attempts';

  @override
  String get wipeAttemptsOff =>
      'Off. Wrong attempts are counted but nothing is deleted.';

  @override
  String wipeAttemptsOn(int count) {
    return 'On — everything is deleted after $count wrong attempts in a row.';
  }

  @override
  String get lockNow => 'Lock now';

  @override
  String get sync => 'Sync';

  @override
  String get createAccount => 'Create an account';

  @override
  String get createAccountDescription =>
      'Lets your codes reach your other devices. They stay encrypted.';

  @override
  String get account => 'Account';

  @override
  String get recoveryPhrase => 'Recovery phrase';

  @override
  String get recoveryConfirmed => 'Confirmed on this device.';

  @override
  String get recoveryNotConfirmed =>
      'No completed confirmation is recorded on this device.';

  @override
  String get yourDevices => 'Your devices';

  @override
  String get yourDevicesDescription =>
      'See what can sync your codes, and remove anything you have lost.';

  @override
  String get dataManagement => 'Data management';

  @override
  String get trash => 'Trash';

  @override
  String get trashDescription =>
      'Restore entries for 30 days or delete them permanently.';

  @override
  String get duplicateAccounts => 'Duplicate accounts';

  @override
  String get duplicateAccountsDescription =>
      'Find entries that contain the same OTP secret.';

  @override
  String get backup => 'Backup';

  @override
  String get backupAndRestore => 'Backup and restore';

  @override
  String get backupAndRestoreDescription =>
      'Save your codes to a file, or read one back. Works without an account.';

  @override
  String get usesApplicationColour =>
      'Uses the application colour on this Android version.';

  @override
  String get usesMaterialYouColour => 'Uses your Android Material You colour.';

  @override
  String get codesHiddenDescription =>
      'Each code stays hidden until you tap its row.';

  @override
  String get codesVisibleDescription =>
      'Codes are visible in the account list.';

  @override
  String get thisDevice => 'This device';

  @override
  String get useBuiltInIcons => 'Show service icons automatically';

  @override
  String get useBuiltInIconsDescription =>
      'Downloads full-colour service favicons through Google\'s favicon service. Turn this off to keep issuer names on this device.';

  @override
  String get serviceIconAttribution =>
      'Service matching data: 2FA Directory by 2factorauth.';

  @override
  String get homeScreenWidget => 'Home-screen widget';

  @override
  String get homeScreenWidgetDescription =>
      'Add a safe shortcut for one account.';

  @override
  String get blockScreenshots => 'Block screenshots';

  @override
  String get screenshotsBlocked =>
      'Screenshots and screen recording are blocked.';

  @override
  String get screenshotsAllowed =>
      'Screenshots and screen recording are allowed.';

  @override
  String get wipeThisDevice => 'Wipe this device';

  @override
  String get wipeThisDeviceDescription =>
      'Deletes every code and destroys the key.';

  @override
  String get lockingExplanation =>
      'Locking is not a screen that hides your codes. It removes the key from memory, so the stored codes cannot be read until you unlock again.';

  @override
  String get useDeviceSetting => 'Use device setting';

  @override
  String get lightTheme => 'Light';

  @override
  String get darkTheme => 'Dark';

  @override
  String get amoledTheme => 'AMOLED black';

  @override
  String get comfortableDensity => 'Comfortable';

  @override
  String get compactDensity => 'Compact';

  @override
  String get automaticBackup => 'Automatic backup';

  @override
  String get automaticEncryptedBackups => 'Automatic encrypted backups';

  @override
  String get readingBackupSettings => 'Reading backup settings.';

  @override
  String get changeBackupDirectory => 'Change backup directory';

  @override
  String get backUpNow => 'Back up now';

  @override
  String get backUp => 'Back up';

  @override
  String get encryptedBackup => 'Encrypted backup';

  @override
  String get encryptedBackupDescription =>
      'Every code, in a file only your passphrase opens. Keep it somewhere you will still have it if this phone is lost.';

  @override
  String get unprotectedExport => 'Unprotected export';

  @override
  String get unprotectedExportDescription =>
      'A readable file with every secret in it. For moving to another app — not for keeping.';

  @override
  String get restore => 'Restore';

  @override
  String get testBackup => 'Test a backup';

  @override
  String get testBackupDescription =>
      'Checks that a backup opens and reports its contents. Nothing is added to this vault.';

  @override
  String get restoreFromBackup => 'Restore from a backup';

  @override
  String get restoreFromBackupDescription =>
      'Adds the accounts in a backup file to this device. Accounts you already have are left alone.';

  @override
  String get getNewRecoveryPhrase => 'Get a new recovery phrase';

  @override
  String get getNewRecoveryPhraseDescription =>
      'Your old phrase cannot be shown again — it is not stored anywhere. This gives you a new one and retires the old.';

  @override
  String get backupTestPassed => 'Backup test passed';

  @override
  String backupTestResult(int accounts, int folders, String encryption) {
    return 'The file opened without changing this vault.\n\nAccounts: $accounts\nFolders: $folders\nEncryption: $encryption';
  }

  @override
  String get encrypted => 'Encrypted';

  @override
  String get notEncrypted => 'Not encrypted';

  @override
  String get done => 'Done';

  @override
  String get editEntry => 'Edit entry';

  @override
  String get save => 'Save';

  @override
  String get service => 'Service';

  @override
  String get optional => 'Optional';

  @override
  String get note => 'Note';

  @override
  String get tags => 'Tags';

  @override
  String get icon => 'Icon';

  @override
  String get iconDescription =>
      'Useful when you have more than one account at the same service.';

  @override
  String get searchIcons => 'Search icons';

  @override
  String get searchIconsHint => 'work, bank, mail…';

  @override
  String get recent => 'Recent';

  @override
  String get chooseCustomImage => 'Choose a custom image';

  @override
  String get noIconMatches => 'No icon matches that search.';

  @override
  String get useAutomaticLetter => 'Use the automatic service icon instead';

  @override
  String get codeCopied => 'Code copied. The clipboard clears in 30 seconds.';

  @override
  String get accountAdded => 'Account added.';

  @override
  String get clipboardHasNoText => 'The clipboard has no text.';

  @override
  String get clipboardHasNoSetupLink =>
      'The clipboard does not contain a setup link.';

  @override
  String moveEntriesToTrash(int count) {
    return 'Move $count entries to Trash?';
  }

  @override
  String get moveEntriesToTrashDescription =>
      'The entries move to Trash on every device. You can restore them for 30 days.';

  @override
  String get cancel => 'Cancel';

  @override
  String get moveToTrash => 'Move to Trash';

  @override
  String entriesMovedToTrash(int count) {
    return '$count entries moved to Trash.';
  }

  @override
  String get add => 'Add';

  @override
  String get selectAccountForDetails =>
      'Select an account to view its details.';

  @override
  String get revealCode => 'Reveal code';

  @override
  String get copyCode => 'Copy code';

  @override
  String get rename => 'Rename';

  @override
  String get deleteFolder => 'Delete folder';

  @override
  String get folderAccountsKept => 'The accounts in it are kept';

  @override
  String get accountIsInTrash => 'That account is in Trash.';

  @override
  String alreadySavedAs(String label) {
    return 'Already saved as $label.';
  }

  @override
  String get emptyVaultDescription =>
      'Add one by scanning the QR code a service shows you, or by entering its setup key by hand.';

  @override
  String get scan => 'Scan';

  @override
  String get enterKey => 'Enter key';

  @override
  String get importFile => 'Import file';

  @override
  String sharedAccountImportFailed(String error) {
    return 'The shared account could not be imported: $error';
  }

  @override
  String get scanShareQr => 'Scan share QR code';

  @override
  String get pasteShareLink => 'Paste share link';

  @override
  String get nextCode => 'Next code';

  @override
  String get copyNextCode => 'Copy next code';

  @override
  String deleteEntryQuestion(String label) {
    return 'Delete $label?';
  }

  @override
  String get deleteEntryDescription =>
      'This moves the entry to Trash on every device. You can restore it for 30 days.';

  @override
  String get keep => 'Keep';

  @override
  String get delete => 'Delete';

  @override
  String get entryMovedToTrash => 'Entry moved to Trash.';

  @override
  String get scanQrCode => 'Scan a QR code';

  @override
  String get enterSetupKey => 'Enter a setup key';

  @override
  String get pasteSetupLink => 'Paste a setup link';

  @override
  String get pasteSetupLinkDescription =>
      'Read an otpauth link from the clipboard';

  @override
  String get importSharedAccount => 'Import a shared account';

  @override
  String get importSharedAccountDescription =>
      'Scan a share QR code or paste its link';

  @override
  String get importFromFile => 'Import from a file';

  @override
  String get supportedImportFiles =>
      'Aegis, 2FAS, Ente, Proton, Bitwarden, or Standard Notes';

  @override
  String get movingFromAnotherApp => 'Moving from another app?';

  @override
  String get supportedMigrationApps => 'Google, Aegis, 2FAS, Authy, Microsoft';

  @override
  String get viewDetails => 'View details';

  @override
  String get edit => 'Edit';

  @override
  String get moveToFolder => 'Move to folder';

  @override
  String get moveToAnotherApp => 'Move to another app';

  @override
  String get shareEncryptedLink => 'Share encrypted link';

  @override
  String get previewNextCode => 'Preview next code';

  @override
  String get create => 'Create';

  @override
  String get noFolder => 'No folder';

  @override
  String get newFolder => 'New folder';

  @override
  String get renameFolder => 'Rename folder';

  @override
  String get entryRestored => 'Entry restored.';

  @override
  String deletePermanentlyQuestion(String label) {
    return 'Delete $label permanently?';
  }

  @override
  String get deletePermanentlyDescription =>
      'This action cannot be undone. The entry will be removed from every device after synchronization.';

  @override
  String get deletePermanently => 'Delete permanently';

  @override
  String get tryAgain => 'Try again';

  @override
  String get trashEmpty => 'Trash is empty.';

  @override
  String get shareLinkCopied =>
      'Share link copied. The clipboard clears in 30 seconds.';

  @override
  String get shareAccount => 'Share account';

  @override
  String get shareEncryptionDescription =>
      'The app encrypts this account before upload. The server cannot read it. The decryption key stays after the # character in the link and is not sent to the server.';

  @override
  String get linkExpiresAfter => 'Link expires after';

  @override
  String get fiveMinutes => '5 minutes';

  @override
  String get oneHour => '1 hour';

  @override
  String get sixHours => '6 hours';

  @override
  String get twentyFourHours => '24 hours';

  @override
  String get deleteAfterFirstDownload => 'Delete after first download';

  @override
  String get oneTimeShareDescription =>
      'A second device cannot download the same share.';

  @override
  String get createEncryptedLink => 'Create encrypted link';

  @override
  String shareCreationFailed(String error) {
    return 'The share could not be created: $error';
  }

  @override
  String get shareSignInDescription =>
      'You must be signed in to create a link. The recipient does not need an account.';

  @override
  String get copyShareLink => 'Copy share link';

  @override
  String get shareLinkWarning =>
      'Anyone who has the complete link can import this account until the link expires or is downloaded once. Send it only to the intended recipient.';

  @override
  String get pendingPermanentDeletion => 'Pending permanent deletion';

  @override
  String get permanentlyDeletedInOneDay => 'Permanently deleted in 1 day';

  @override
  String permanentlyDeletedInDays(int days) {
    return 'Permanently deleted in $days days';
  }

  @override
  String expiresAt(String time) {
    return 'Expires: $time';
  }

  @override
  String get signOutOfSyncQuestion => 'Sign out of sync?';

  @override
  String get signOutOfSyncDescription =>
      'Your codes stay on this device. This device just stops sending and receiving changes until you sign in again.';

  @override
  String get signOut => 'Sign out';

  @override
  String get syncEncryptionDescription =>
      'Sync keeps your codes on every device you sign in to. The server stores them encrypted and cannot read them.';

  @override
  String get turnOnSync => 'Turn on sync for this device';

  @override
  String get turnOnSyncDescription =>
      'Uses the account already on this device.';

  @override
  String get signInExistingAccount => 'Sign in to an existing account';

  @override
  String get signInExistingAccountDescription =>
      'For a device that has not joined this vault yet.';

  @override
  String get unknown => 'unknown';

  @override
  String get server => 'Server';

  @override
  String get notSet => 'not set';

  @override
  String get syncNow => 'Sync now';

  @override
  String get signOutOfSync => 'Sign out of sync';

  @override
  String get codesStayOnDevice => 'Your codes stay on this device.';

  @override
  String get noCompletedSync => 'No completed sync yet';

  @override
  String get unknownWhileLocked => 'Unknown while locked';

  @override
  String get couldNotLoad => 'Could not load';

  @override
  String get loading => 'Loading';

  @override
  String get synchronizationStatus => 'Synchronization status';

  @override
  String get lastSync => 'Last sync';

  @override
  String get pendingChanges => 'Pending changes';

  @override
  String get activeDevices => 'Active devices';

  @override
  String get notConfigured => 'Not configured';

  @override
  String get retry => 'Retry';

  @override
  String get syncIsOff => 'Sync is off';

  @override
  String get synced => 'Synced';

  @override
  String changesWaiting(int count) {
    return '$count waiting to sync';
  }

  @override
  String get changesWaitingUnknown => 'Changes are waiting to sync';

  @override
  String get offline => 'Offline';

  @override
  String get syncSessionExpired => 'Sync session expired';

  @override
  String get signThisDeviceOutQuestion => 'Sign this device out?';

  @override
  String removeDeviceQuestion(String name) {
    return 'Remove $name?';
  }

  @override
  String get signThisDeviceOutDescription =>
      'You will be signed out here and your codes will stop syncing until you sign in again. The codes already on this device are kept.';

  @override
  String get removeDeviceDescription =>
      'It will stop syncing straight away and will need your password to sign in again.\n\nThe codes already on that device are not deleted. If the device is lost and unlocked, change the passwords it protects.';

  @override
  String get remove => 'Remove';

  @override
  String get signOutEverywhereQuestion => 'Sign out everywhere?';

  @override
  String get signOutEverywhereDescription =>
      'Every device, including this one, will need your password to sign in again.\n\nUse this if you think someone else has access and you are not sure which device. Your codes are not deleted anywhere.';

  @override
  String get signOutEverywhere => 'Sign out everywhere';

  @override
  String accountDeletedResult(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'records were',
      one: 'record was',
    );
    return 'Account deleted. $count encrypted $_temp0 destroyed. Your codes on this device are still here.';
  }

  @override
  String get refresh => 'Refresh';

  @override
  String get devicesIntroduction =>
      'These devices can sync your codes. Removing one stops it immediately.';

  @override
  String get signOutEverywhereDescriptionShort =>
      'Every device needs the password again. Nothing is deleted.';

  @override
  String get deleteSyncAccount => 'Delete sync account';

  @override
  String get deleteSyncAccountDescription =>
      'Removes everything from the server. The codes on this device stay.';

  @override
  String get neverSynced => 'Never synced';

  @override
  String lastSyncedAt(String time) {
    return 'Last synced $time';
  }

  @override
  String get activeNow => 'Active now';

  @override
  String minutesAgo(int count) {
    return '$count minutes ago';
  }

  @override
  String hoursAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count hours ago',
      one: '1 hour ago',
    );
    return '$_temp0';
  }

  @override
  String daysAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count days ago',
      one: '1 day ago',
    );
    return '$_temp0';
  }

  @override
  String get removed => 'Removed';

  @override
  String get removeThisDevice => 'Remove this device';

  @override
  String get deleteSyncAccountQuestion => 'Delete your sync account?';

  @override
  String get deleteSyncAccountWarning =>
      'Everything stored on the server is destroyed and every device is signed out. This cannot be undone.';

  @override
  String get deleteSyncAccountKeepsCodes =>
      'The codes on this device are kept and will keep working. Your other devices keep the codes they already have, but nothing will sync between them again.';

  @override
  String get accountPassword => 'Account password';

  @override
  String get deleteAccount => 'Delete account';

  @override
  String get allowScreenCaptureQuestion => 'Allow screen capture?';

  @override
  String get allowScreenCaptureWarning =>
      'Screenshots and screen recording can capture codes, QR codes, account names, notes, and custom images. Other apps and backup services can keep those images.';

  @override
  String get allow => 'Allow';

  @override
  String screenshotSettingFailed(String error) {
    return 'The screenshot setting could not be changed: $error';
  }

  @override
  String codeVisibilitySettingFailed(String error) {
    return 'The code visibility setting failed: $error';
  }

  @override
  String get applicationTheme => 'Application theme';

  @override
  String themeSettingFailed(String error) {
    return 'The theme setting failed: $error';
  }

  @override
  String listSpacingSettingFailed(String error) {
    return 'The list spacing setting failed: $error';
  }

  @override
  String get wipeThisDeviceQuestion => 'Wipe this device?';

  @override
  String get wipeThisDeviceWarning =>
      'Every code on this device is deleted and the key that decrypts them is destroyed. If you have not set up sync, nothing can bring them back.';

  @override
  String get wipe => 'Wipe';

  @override
  String get deleteAfterAttemptsQuestion =>
      'Delete everything after failed attempts?';

  @override
  String deleteAfterAttemptsWarning(int count) {
    return 'After $count wrong attempts in a row, every code on this device will be deleted and the key destroyed.\n\nNobody can undo it or recover them for you. Make sure you have a backup or another signed-in device.';
  }

  @override
  String get turnItOn => 'Turn it on';

  @override
  String get off => 'Off';

  @override
  String get wrongAttemptsCounted =>
      'Wrong attempts are counted, nothing is deleted.';

  @override
  String afterWrongAttempts(int count) {
    return 'After $count wrong attempts';
  }

  @override
  String get choosePassphrase => 'Choose a passphrase';

  @override
  String get backupPassphraseWarning =>
      'This passphrase is the only thing that opens the backup. It cannot be reset. Keep a copy outside this device.';

  @override
  String get automaticPassphraseStorage =>
      'This device stores the passphrase in secure storage so it can create backups without asking each time.';

  @override
  String get passphrase => 'Passphrase';

  @override
  String get typeAgain => 'Type it again';

  @override
  String get thisBackupIsEncrypted => 'This backup is encrypted';

  @override
  String get backupPassphrase => 'Backup passphrase';

  @override
  String get thisFileProtectsNothing => 'This file protects nothing';

  @override
  String get useEncryptedBackup => 'Use the encrypted backup';

  @override
  String get continueAnyway => 'Continue anyway';

  @override
  String get typeExportToContinue => 'Type EXPORT to continue';

  @override
  String get exportPlainText => 'Export in plain text';

  @override
  String get enterAccountPassword => 'Enter your account password';

  @override
  String get rotateRecoveryWarning =>
      'Your current recovery phrase will stop working. If you have it stored anywhere, replace it with the new phrase.';

  @override
  String get continueAction => 'Continue';

  @override
  String get wipeThresholdExplanation =>
      'If someone gets this phone and guesses your PIN, this setting deletes every code instead of letting them continue.\n\nThis cannot be undone. Keep a backup or a second device before you turn it on.';

  @override
  String get immediately => 'Immediately';

  @override
  String get after15Seconds => 'After 15 seconds';

  @override
  String get after1Minute => 'After 1 minute';

  @override
  String get after5Minutes => 'After 5 minutes';

  @override
  String get after15Minutes => 'After 15 minutes';

  @override
  String get never => 'Never';

  @override
  String minimumCharacters(int count) {
    return 'Use at least $count characters.';
  }

  @override
  String get passphrasesDifferent => 'The two passphrases are different.';

  @override
  String get turnOn => 'Turn on';

  @override
  String get plainExportWarning =>
      'Every code in your vault will be written in plain text. Anyone who opens the file, or any app or cloud service that reads it, can sign in as you.\n\nUse this only to move to another app. Delete the file when you finish.\n\nFor a backup that you keep, use an encrypted backup.';

  @override
  String get exportWord => 'EXPORT';

  @override
  String get copiedClipboardTwoMinutes =>
      'Copied. The clipboard clears in 2 minutes.';

  @override
  String get copyToClipboard => 'Copy to clipboard';

  @override
  String get recoveryWrittenDown => 'I have written these words down';

  @override
  String get confirmRecoveryInstructions =>
      'Type these words from your list. This checks that you wrote them down correctly.';

  @override
  String get confirm => 'Confirm';

  @override
  String get showWordsAgain => 'Show the words again';

  @override
  String get selectWidgetAccount => 'Select the widget account';

  @override
  String get widgetDescription =>
      'The widget shows one account name. Tap it to unlock the app and view the current code.';

  @override
  String get noWidgetAccount => 'No account is selected.';

  @override
  String get disableWidget => 'Disable widget';

  @override
  String get addAccountBeforeWidget =>
      'Add an account before you configure the widget.';

  @override
  String get widgetLauncherInstructions =>
      'After you select an account, use your Android launcher to add the Authenticator widget.';

  @override
  String get removePinQuestion => 'Remove the PIN?';

  @override
  String get removePinWarning =>
      'Your codes stay encrypted, but anyone who can unlock this device can open them without a separate PIN.';

  @override
  String get keepIt => 'Keep it';

  @override
  String get removePin => 'Remove the PIN';

  @override
  String get pinKeyDescription =>
      'The PIN is combined with a key held by this device. Both are needed to open your codes.';

  @override
  String get allowBiometricUnlock => 'Allow biometric unlock';

  @override
  String get biometricBindingDescription =>
      'Binds this device key to your fingerprint or face.';

  @override
  String get accountSyncDescription =>
      'An account lets your codes reach your other devices. They stay encrypted.';

  @override
  String get skipForNow => 'Skip for now';

  @override
  String get scanQrCodeTitle => 'Scan QR code';

  @override
  String get manualEntryAlternative =>
      'You can add the account by entering its setup key instead.';

  @override
  String get goBack => 'Go back';

  @override
  String get moveThisAccount => 'Move this account';

  @override
  String get tapToShow => 'Tap to show';

  @override
  String importedCount(int count) {
    return 'Imported $count';
  }

  @override
  String get addSkippedManually =>
      'Add these by hand from the app you are moving from.';

  @override
  String get bringAccountsAcross => 'Bring your accounts across';

  @override
  String get typeSetupKeyManually => 'Type a setup key by hand';

  @override
  String get setupKeyAvailable =>
      'Every service can show a setup key instead of a QR code.';

  @override
  String get importAction => 'Import';

  @override
  String get duplicateMovedToTrash => 'Duplicate moved to Trash.';

  @override
  String get noDuplicateSecrets => 'No duplicate secrets were found.';

  @override
  String get sameSecretDescription => 'These accounts use the same secret.';

  @override
  String get timeBased => 'Time-based';

  @override
  String get counterBased => 'Counter-based';

  @override
  String get advanced => 'Advanced';

  @override
  String secondsValue(int count) {
    return '$count seconds';
  }

  @override
  String get stopImportingQuestion => 'Stop importing?';

  @override
  String get keepScanning => 'Keep scanning';

  @override
  String get stop => 'Stop';

  @override
  String get importGoogleAuthenticator => 'Import from Google Authenticator';

  @override
  String importReadyCount(int count) {
    return 'Import $count';
  }

  @override
  String get quickAccessNoExposedCodes => 'Quick access without exposed codes';

  @override
  String widgetSettingReadFailed(String error) {
    return 'The widget setting could not be read: $error';
  }

  @override
  String get widgetEnabled => 'Widget enabled';

  @override
  String get widgetDisabled => 'Widget disabled';

  @override
  String get changeAccount => 'Change account';

  @override
  String get selectAccount => 'Select account';

  @override
  String get newPinOrPassphrase => 'New PIN or passphrase';

  @override
  String get enterItAgain => 'Enter it again';

  @override
  String get entriesDoNotMatch => 'The two entries do not match.';

  @override
  String get biometricInvalidationDescription =>
      'Binds this device key to your fingerprint or face. Enrolling a new fingerprint invalidates it.';

  @override
  String get pinDerivationDescription =>
      'Setting a PIN takes a moment. The key is deliberately slow to derive, which makes guessing slower.';

  @override
  String get secretCannotBeChanged => 'The secret cannot be changed';

  @override
  String get secretCannotBeChangedDescription =>
      'A different secret is a different account, not a rename. Delete this entry and scan the new code.';

  @override
  String get chooseBackupFile => 'Choose a backup file';

  @override
  String get chooseBackupToTest => 'Choose a backup to test';

  @override
  String get password => 'Password';

  @override
  String get emailAddress => 'Email address';

  @override
  String get email => 'Email';

  @override
  String get enterPasswordAgain => 'Enter the password again';

  @override
  String get setupKey => 'Setup key';

  @override
  String get startingCounter => 'Starting counter';

  @override
  String get algorithm => 'Algorithm';

  @override
  String get digits => 'Digits';

  @override
  String get period => 'Period';

  @override
  String get folderName => 'Folder name';

  @override
  String get syncServer => 'Sync server';

  @override
  String get pinOrPassphrase => 'PIN or passphrase';

  @override
  String wordPosition(int position) {
    return 'Word $position';
  }

  @override
  String get signIn => 'Sign in';

  @override
  String get signInDownloadDescription =>
      'This device downloads your codes and unlocks them with your password. The server never sees the key.';

  @override
  String get fromDeviceAccount => 'From the account on this device';

  @override
  String get emailRecoveryDescription =>
      'Used for recovery and for approving new devices.';

  @override
  String get createAccountAction => 'Create account';

  @override
  String get addAccount => 'Add account';

  @override
  String get chooseExportFile => 'Choose an export file';

  @override
  String get cancelSelection => 'Cancel selection';

  @override
  String get changeFavouriteStatus => 'Change favourite status';

  @override
  String get searchAccountsNotesTags => 'Search accounts, notes, or tags';

  @override
  String get sort => 'Sort';

  @override
  String get workExample => 'Work';

  @override
  String get issuerExample => 'GitHub';

  @override
  String get accountExample => 'you@example.com';

  @override
  String get issuerHelper => 'For example, GitHub. Optional.';

  @override
  String get accountHelper => 'Your username or email address at that service.';

  @override
  String get encryptedEntryOptional => 'Encrypted with this entry. Optional.';

  @override
  String get tagsHelper => 'Separate tags with commas. Up to 20 tags.';

  @override
  String get tagsExample => 'work, finance';

  @override
  String get chooseCustomIcon => 'Choose a custom icon';

  @override
  String get saveBackup => 'Save your backup';

  @override
  String get syncServerExample => 'https://…';

  @override
  String get chooseQrImage => 'Choose an image with a QR code';

  @override
  String get chooseImage => 'Choose an image';

  @override
  String get torch => 'Torch';

  @override
  String get welcomeTitle => 'Your codes, on your terms';

  @override
  String get welcomeDescription =>
      'Everything is encrypted on this device before it goes anywhere. You can take it all with you at any time.';

  @override
  String get bringMyAccountsAcross => 'Bring my accounts across';

  @override
  String get bringAccountsSources =>
      'From Google Authenticator, Aegis, 2FAS, Authy, Microsoft Authenticator, or anywhere else.';

  @override
  String get setUpSync => 'Set up sync';

  @override
  String get setUpSyncDescription =>
      'Keeps your codes on every device you own. The server stores only encrypted data.';

  @override
  String get useOnThisPhone => 'Just use it on this phone';

  @override
  String get useOnThisPhoneDescription =>
      'No account and no network transfer. You can turn on sync later without adding the accounts again.';

  @override
  String get changeLaterInSettings =>
      'You can change these choices later in Settings.';

  @override
  String get nextCodeTooltip => 'Next code';

  @override
  String get undo => 'Undo';

  @override
  String get folder => 'Folder';

  @override
  String get qrCode => 'QR code';

  @override
  String get share => 'Share';

  @override
  String get showIt => 'Show it';

  @override
  String get nameSort => 'Name';

  @override
  String get issuerSort => 'Issuer';

  @override
  String get recentlyAddedSort => 'Recently added';

  @override
  String get manualSort => 'My order';

  @override
  String get noSearchResults => 'No entry matches that search.';

  @override
  String get noAccountsYet => 'No accounts yet.';

  @override
  String availableAfterSeconds(int count) {
    return 'Available after $count seconds.';
  }

  @override
  String get nextCodeCopied =>
      'Next code copied. The clipboard clears in 30 seconds.';

  @override
  String clockOffsetWarning(int count) {
    return 'This device clock is off by about $count seconds. Codes can fail until you correct the clock.';
  }

  @override
  String selectedCount(int count) {
    return '$count selected';
  }

  @override
  String get vaultOpenFailed => 'The vault could not be opened';

  @override
  String get vaultDataSafeAfterOpenFailure =>
      'Your entries have not been deleted. Close and reopen the application to try again.';

  @override
  String get unnamedEntry => 'An unnamed entry';

  @override
  String get all => 'All';

  @override
  String get unfiled => 'Unfiled';

  @override
  String get holdToManageFolder => 'Hold to rename or delete';

  @override
  String codeExpiresInSeconds(int count) {
    return 'Code expires in $count seconds';
  }

  @override
  String get codeHiddenAccessibility => 'Code hidden. Activate to show.';

  @override
  String duplicatesSkipped(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count accounts were already in your list and were not added again.',
      one: '1 account was already in your list and was not added again.',
    );
    return '$_temp0';
  }

  @override
  String couldNotImportCount(int count) {
    return '$count could not be imported:';
  }

  @override
  String get unreadableExport =>
      'That file is not an export this app can read.';

  @override
  String encryptedSourceExport(String source) {
    return 'This $source export is encrypted';
  }

  @override
  String get enterBackupPassphrase =>
      'Enter the passphrase you set when you made it.';

  @override
  String enterSourceExportPassword(String source) {
    return 'Enter the password you set in $source when you created the export.';
  }

  @override
  String get syncCatchUpUnlock =>
      'The app is catching up with your other devices. Unlock again in a moment.';

  @override
  String get removeFromFavourites => 'Remove from favourites';

  @override
  String get addToFavourites => 'Add to favourites';

  @override
  String get automaticBackupOnMessage => 'Automatic encrypted backup is on.';

  @override
  String get automaticBackupCancelled =>
      'Automatic backup setup was cancelled.';

  @override
  String get backupDirectoryChanged =>
      'The automatic backup directory was changed.';

  @override
  String get automaticBackupSaved => 'Automatic encrypted backup saved.';

  @override
  String get automaticBackupAndroidOnly => 'Available on Android.';

  @override
  String get automaticBackupOffStatus =>
      'Off. Keeps the newest seven encrypted files.';

  @override
  String get selectedDirectory => 'Selected directory';

  @override
  String automaticBackupOnDirectory(String location) {
    return 'On. Directory: $location';
  }

  @override
  String automaticBackupLast(String time, String location) {
    return 'On. Last backup: $time.\nDirectory: $location';
  }

  @override
  String get backupCancelled => 'Backup cancelled.';

  @override
  String get backupSaved => 'Backup saved.';

  @override
  String get notApplicationBackup => 'That file is not a backup from this app.';

  @override
  String get emailRequired => 'An email address is required.';

  @override
  String get emailInvalid => 'Enter a valid email address.';

  @override
  String get passwordMinimumTen => 'Use at least 10 characters.';

  @override
  String get passwordsDoNotMatch => 'The two password entries do not match.';

  @override
  String get createAccountKeepsCodes =>
      'Your existing codes stay unchanged. Creating an account adds encrypted synchronization and account recovery.';

  @override
  String get accountNameRequired => 'An account name is required.';

  @override
  String get noteTooLong => 'The note can have at most 512 characters.';

  @override
  String get tooManyTags => 'An entry can have at most 20 tags.';

  @override
  String get tagTooLong => 'A tag can have at most 32 characters.';

  @override
  String get renameSyncDescription =>
      'Renaming an entry changes it on every device on this account. It does not change the codes.';

  @override
  String get imageCouldNotOpen => 'That image could not be opened.';

  @override
  String get counterInvalid =>
      'The starting counter must be a whole number that is zero or greater.';

  @override
  String get enterAccountForCode => 'Enter the account that owns this code.';

  @override
  String get setupKeyHelper =>
      'Enter the key shown next to the service QR code. Spaces and letter case do not matter.';

  @override
  String get enterSetupKeyError => 'Enter the setup key.';

  @override
  String get timeBasedDescription =>
      'The code changes on a timer. Almost every service uses this type.';

  @override
  String get counterBasedDescription =>
      'The code changes when you request the next code.';

  @override
  String get counterHelper =>
      'Usually 0. This value must match the value held by the service.';

  @override
  String get enterWholeCounter => 'Enter the counter as a whole number.';

  @override
  String get qrSecretWarning =>
      'This QR code is the account secret. A person who photographs it can sign in as you. Reset two-factor authentication to revoke it.';

  @override
  String get hideSetupKey => 'Hide the setup key';

  @override
  String get showSetupKey => 'Show the setup key instead';

  @override
  String get checkScreenPrivacy => 'Check who can see your screen';

  @override
  String get useAtLeastSixDigits => 'Use at least 6 digits.';

  @override
  String get useAtLeastSixCharacters => 'Use at least 6 characters.';

  @override
  String get avoidRepeatedPin => 'Do not use one repeated digit.';

  @override
  String get avoidSequentialPin => 'Do not use a sequence such as 123456.';

  @override
  String get deviceKeyProtectionFailed =>
      'The device key could not be protected.';

  @override
  String get wrongExportPart =>
      'That code belongs to a different export. Scan the remaining codes from the first export.';

  @override
  String get migrationCodeAlreadyScanned => 'That code was already scanned.';

  @override
  String partialExportScanned(int count) {
    return 'You scanned part of this export. Scan $count more before you leave.';
  }

  @override
  String get allCodesScanned => 'All codes scanned.';

  @override
  String scanNextMigrationCode(int count) {
    return 'Scan the next code. $count remain.';
  }

  @override
  String get notSharedAccountQr => 'That QR code is not a shared-account link.';

  @override
  String get notOtpSetupQr => 'That QR code is not a two-factor setup code.';

  @override
  String get selectedImageUnavailable =>
      'This device did not provide the selected image.';

  @override
  String get noSharedQrInImage =>
      'No shared-account QR code was found in that image.';

  @override
  String get noOtpQrInImage => 'No two-factor QR code was found in that image.';

  @override
  String get imageScanFailed => 'The selected image could not be scanned.';

  @override
  String get cameraPermissionRequired =>
      'This application does not have permission to use the camera.';

  @override
  String get cameraStartFailed => 'The camera could not be started.';

  @override
  String get enterSyncServer => 'Enter the address of your sync server.';

  @override
  String get syncServerRequiresHttps => 'The address must start with https://.';

  @override
  String get enterAccountEmail => 'Enter the email address of your account.';

  @override
  String get enterNewAccountPassword =>
      'Enter the password you set for this account.';

  @override
  String get enterPin => 'Enter your PIN.';

  @override
  String get biometricUnlockFailed =>
      'Biometric unlock failed. Enter your PIN instead.';

  @override
  String get show => 'Show';

  @override
  String get hide => 'Hide';

  @override
  String get failedAttemptLimitReached =>
      'The failed attempt limit has been reached.';

  @override
  String get useRecoveryPhraseTitle => 'Use recovery phrase';

  @override
  String get useAccountPasswordTitle => 'Use account password';

  @override
  String get recoveryPhraseEntryHelp =>
      'Enter the 24 words you saved when you created the account.';

  @override
  String get accountPasswordEntryHelp =>
      'Enter the password for the sync account on this device.';

  @override
  String get recoveryPhraseField => '24-word recovery phrase';

  @override
  String incorrectRecoveryWord(int position) {
    return 'That is not the word at position $position.';
  }

  @override
  String get writeRecoveryFirst =>
      'Write these words down first. They are the only way to recover your codes.';

  @override
  String get confirmRecoveryKey => 'Confirm your recovery key';

  @override
  String get yourRecoveryKey => 'Your recovery key';

  @override
  String get recoveryKeyWarning =>
      'These 24 words are shown once. They are the only way to recover your codes if you lose your password and devices. We cannot show them again.';

  @override
  String get paperSaferThanClipboard =>
      'Paper is safer than the clipboard. Other applications can read clipboard data.';

  @override
  String failedAttemptsRemaining(int attempts, int remaining) {
    String _temp0 = intl.Intl.pluralLogic(
      attempts,
      locale: localeName,
      other: 'attempts',
      one: 'attempt',
    );
    return '$attempts failed $_temp0. $remaining remain before this device is wiped, if wipe protection is on.';
  }

  @override
  String migrationFoundReport(int ready, int refused) {
    String _temp0 = intl.Intl.pluralLogic(
      ready,
      locale: localeName,
      other: 'accounts',
      one: 'account',
    );
    return '$ready $_temp0 found. $refused could not be read.';
  }

  @override
  String get directImports => 'Direct imports';

  @override
  String get googleImportSteps =>
      'Open Google Authenticator.\nOpen the menu. Select Transfer accounts, then Export accounts.\nSelect the accounts. Then select Next.\nScan each QR code shown. A large export has more than one QR code.';

  @override
  String get scanExportCode => 'Scan an export code';

  @override
  String get aegisImportSteps =>
      'Open Aegis.\nSelect Settings, Import & Export, then Export.\nSave the file in a location that you can open from this app.\nSelect the file below. Enter the export password when asked.';

  @override
  String get chooseFile => 'Choose a file';

  @override
  String get twoFasImportSteps =>
      'Open 2FAS.\nSelect Settings, Backup, then Export to file.\nSave the .2fas file in a location that you can open from this app.\nSelect the file below. Password-protected backups are supported.';

  @override
  String get enteImportSteps =>
      'Open Ente Auth and export your codes.\nUse a password-protected export when available.\nSelect the file below. Enter the export password when asked.\nPlain-text exports are also supported.';

  @override
  String get protonImportSteps =>
      'Open Proton Authenticator and export your codes.\nSet an export password.\nSelect the JSON file below. Enter the export password when asked.\nPlain JSON exports are also supported.';

  @override
  String get bitwardenImportSteps =>
      'Export the vault as unencrypted JSON.\nSelect the JSON file below. Only items with a TOTP value are imported.\nDelete the unencrypted export after you verify the import.';

  @override
  String get standardNotesImportSteps =>
      'Export the Authenticator note as JSON.\nSelect the JSON file below. Notes are kept with each entry.';

  @override
  String get appsWithoutExport => 'Apps that do not provide an export';

  @override
  String get appsWithoutExportDescription =>
      'Microsoft Authenticator and Authy do not provide a supported export. Set up each account again at its service.';

  @override
  String get microsoftImportSteps =>
      'Microsoft Authenticator does not provide an export.\nFor each account, sign in to the service and open its security settings.\nRemove the old authenticator. Set it up again and scan the new QR code with this app.\nMove important accounts first. Keep the old app until all accounts are moved.';

  @override
  String get authyImportSteps =>
      'Authy does not provide an export.\nIf an old Authy desktop application still works, Aegis can import from it. Then export from Aegis.\nOtherwise, set up each account again at its service.';

  @override
  String get otherAuthenticators => 'Other authenticators';

  @override
  String get otherAuthenticatorHelp =>
      'Most authenticator apps export a QR code or a file. This app supports both. If the format is not recognized, import it into Aegis and export it from Aegis.';

  @override
  String get imageFileEmpty => 'The image file is empty.';

  @override
  String get imageTooLarge => 'Choose an image smaller than 5 MB.';

  @override
  String get imageCannotFitEntry =>
      'This image cannot fit in the encrypted entry. Choose a simpler image.';

  @override
  String get automaticBackupPassphraseMissing =>
      'Automatic backup has no passphrase. Set it up again.';
}
