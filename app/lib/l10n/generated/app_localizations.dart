import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_hi.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'generated/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('hi'),
  ];

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'Authenticator'**
  String get appTitle;

  /// No description provided for @openingAuthenticator.
  ///
  /// In en, this message translates to:
  /// **'Opening authenticator…'**
  String get openingAuthenticator;

  /// No description provided for @lockedTitle.
  ///
  /// In en, this message translates to:
  /// **'Locked'**
  String get lockedTitle;

  /// No description provided for @lockedBody.
  ///
  /// In en, this message translates to:
  /// **'Your codes are encrypted until you unlock.'**
  String get lockedBody;

  /// No description provided for @unlock.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get unlock;

  /// No description provided for @useBiometrics.
  ///
  /// In en, this message translates to:
  /// **'Use biometrics'**
  String get useBiometrics;

  /// No description provided for @useAccountPassword.
  ///
  /// In en, this message translates to:
  /// **'Use account password'**
  String get useAccountPassword;

  /// No description provided for @useRecoveryPhrase.
  ///
  /// In en, this message translates to:
  /// **'Use recovery phrase'**
  String get useRecoveryPhrase;

  /// No description provided for @settings.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get settings;

  /// No description provided for @appearanceAndPrivacy.
  ///
  /// In en, this message translates to:
  /// **'Appearance and privacy'**
  String get appearanceAndPrivacy;

  /// No description provided for @theme.
  ///
  /// In en, this message translates to:
  /// **'Theme'**
  String get theme;

  /// No description provided for @accountListSpacing.
  ///
  /// In en, this message translates to:
  /// **'Account list spacing'**
  String get accountListSpacing;

  /// No description provided for @hideCodesUntilTapped.
  ///
  /// In en, this message translates to:
  /// **'Hide codes until tapped'**
  String get hideCodesUntilTapped;

  /// No description provided for @useDeviceColours.
  ///
  /// In en, this message translates to:
  /// **'Use device colours'**
  String get useDeviceColours;

  /// No description provided for @language.
  ///
  /// In en, this message translates to:
  /// **'Language'**
  String get language;

  /// No description provided for @useDeviceLanguage.
  ///
  /// In en, this message translates to:
  /// **'Use device language'**
  String get useDeviceLanguage;

  /// No description provided for @english.
  ///
  /// In en, this message translates to:
  /// **'English'**
  String get english;

  /// No description provided for @hindi.
  ///
  /// In en, this message translates to:
  /// **'Hindi'**
  String get hindi;

  /// No description provided for @applicationLock.
  ///
  /// In en, this message translates to:
  /// **'Application lock'**
  String get applicationLock;

  /// No description provided for @changePin.
  ///
  /// In en, this message translates to:
  /// **'Change PIN'**
  String get changePin;

  /// No description provided for @setPin.
  ///
  /// In en, this message translates to:
  /// **'Set a PIN'**
  String get setPin;

  /// No description provided for @pinRequiredDescription.
  ///
  /// In en, this message translates to:
  /// **'Required along with this device\'s key to open your codes.'**
  String get pinRequiredDescription;

  /// No description provided for @pinNotSetDescription.
  ///
  /// In en, this message translates to:
  /// **'Without one, anyone who unlocks this device can read your codes.'**
  String get pinNotSetDescription;

  /// No description provided for @lockAfter.
  ///
  /// In en, this message translates to:
  /// **'Lock after'**
  String get lockAfter;

  /// No description provided for @lockWhenLeaving.
  ///
  /// In en, this message translates to:
  /// **'Lock when leaving the app'**
  String get lockWhenLeaving;

  /// No description provided for @lockWhenLeavingDescription.
  ///
  /// In en, this message translates to:
  /// **'Locks the moment the app is no longer on screen.'**
  String get lockWhenLeavingDescription;

  /// No description provided for @wipeAfterFailedAttempts.
  ///
  /// In en, this message translates to:
  /// **'Wipe after failed attempts'**
  String get wipeAfterFailedAttempts;

  /// No description provided for @wipeAttemptsOff.
  ///
  /// In en, this message translates to:
  /// **'Off. Wrong attempts are counted but nothing is deleted.'**
  String get wipeAttemptsOff;

  /// No description provided for @wipeAttemptsOn.
  ///
  /// In en, this message translates to:
  /// **'On — everything is deleted after {count} wrong attempts in a row.'**
  String wipeAttemptsOn(int count);

  /// No description provided for @lockNow.
  ///
  /// In en, this message translates to:
  /// **'Lock now'**
  String get lockNow;

  /// No description provided for @sync.
  ///
  /// In en, this message translates to:
  /// **'Sync'**
  String get sync;

  /// No description provided for @createAccount.
  ///
  /// In en, this message translates to:
  /// **'Create an account'**
  String get createAccount;

  /// No description provided for @createAccountDescription.
  ///
  /// In en, this message translates to:
  /// **'Lets your codes reach your other devices. They stay encrypted.'**
  String get createAccountDescription;

  /// No description provided for @account.
  ///
  /// In en, this message translates to:
  /// **'Account'**
  String get account;

  /// No description provided for @recoveryPhrase.
  ///
  /// In en, this message translates to:
  /// **'Recovery phrase'**
  String get recoveryPhrase;

  /// No description provided for @recoveryConfirmed.
  ///
  /// In en, this message translates to:
  /// **'Confirmed on this device.'**
  String get recoveryConfirmed;

  /// No description provided for @recoveryNotConfirmed.
  ///
  /// In en, this message translates to:
  /// **'No completed confirmation is recorded on this device.'**
  String get recoveryNotConfirmed;

  /// No description provided for @yourDevices.
  ///
  /// In en, this message translates to:
  /// **'Your devices'**
  String get yourDevices;

  /// No description provided for @yourDevicesDescription.
  ///
  /// In en, this message translates to:
  /// **'See what can sync your codes, and remove anything you have lost.'**
  String get yourDevicesDescription;

  /// No description provided for @dataManagement.
  ///
  /// In en, this message translates to:
  /// **'Data management'**
  String get dataManagement;

  /// No description provided for @trash.
  ///
  /// In en, this message translates to:
  /// **'Trash'**
  String get trash;

  /// No description provided for @trashDescription.
  ///
  /// In en, this message translates to:
  /// **'Restore entries for 30 days or delete them permanently.'**
  String get trashDescription;

  /// No description provided for @duplicateAccounts.
  ///
  /// In en, this message translates to:
  /// **'Duplicate accounts'**
  String get duplicateAccounts;

  /// No description provided for @duplicateAccountsDescription.
  ///
  /// In en, this message translates to:
  /// **'Find entries that contain the same OTP secret.'**
  String get duplicateAccountsDescription;

  /// No description provided for @backup.
  ///
  /// In en, this message translates to:
  /// **'Backup'**
  String get backup;

  /// No description provided for @backupAndRestore.
  ///
  /// In en, this message translates to:
  /// **'Backup and restore'**
  String get backupAndRestore;

  /// No description provided for @backupAndRestoreDescription.
  ///
  /// In en, this message translates to:
  /// **'Save your codes to a file, or read one back. Works without an account.'**
  String get backupAndRestoreDescription;

  /// No description provided for @usesApplicationColour.
  ///
  /// In en, this message translates to:
  /// **'Uses the application colour on this Android version.'**
  String get usesApplicationColour;

  /// No description provided for @usesMaterialYouColour.
  ///
  /// In en, this message translates to:
  /// **'Uses your Android Material You colour.'**
  String get usesMaterialYouColour;

  /// No description provided for @codesHiddenDescription.
  ///
  /// In en, this message translates to:
  /// **'Each code stays hidden until you tap its row.'**
  String get codesHiddenDescription;

  /// No description provided for @codesVisibleDescription.
  ///
  /// In en, this message translates to:
  /// **'Codes are visible in the account list.'**
  String get codesVisibleDescription;

  /// No description provided for @thisDevice.
  ///
  /// In en, this message translates to:
  /// **'This device'**
  String get thisDevice;

  /// No description provided for @useBuiltInIcons.
  ///
  /// In en, this message translates to:
  /// **'Show service icons automatically'**
  String get useBuiltInIcons;

  /// No description provided for @useBuiltInIconsDescription.
  ///
  /// In en, this message translates to:
  /// **'Downloads full-colour service favicons through Google\'s favicon service. Turn this off to keep issuer names on this device.'**
  String get useBuiltInIconsDescription;

  /// No description provided for @serviceIconAttribution.
  ///
  /// In en, this message translates to:
  /// **'Service matching data: 2FA Directory by 2factorauth.'**
  String get serviceIconAttribution;

  /// No description provided for @homeScreenWidget.
  ///
  /// In en, this message translates to:
  /// **'Home-screen widget'**
  String get homeScreenWidget;

  /// No description provided for @homeScreenWidgetDescription.
  ///
  /// In en, this message translates to:
  /// **'Add a safe shortcut for one account.'**
  String get homeScreenWidgetDescription;

  /// No description provided for @blockScreenshots.
  ///
  /// In en, this message translates to:
  /// **'Block screenshots'**
  String get blockScreenshots;

  /// No description provided for @screenshotsBlocked.
  ///
  /// In en, this message translates to:
  /// **'Screenshots and screen recording are blocked.'**
  String get screenshotsBlocked;

  /// No description provided for @screenshotsAllowed.
  ///
  /// In en, this message translates to:
  /// **'Screenshots and screen recording are allowed.'**
  String get screenshotsAllowed;

  /// No description provided for @wipeThisDevice.
  ///
  /// In en, this message translates to:
  /// **'Wipe this device'**
  String get wipeThisDevice;

  /// No description provided for @wipeThisDeviceDescription.
  ///
  /// In en, this message translates to:
  /// **'Deletes every code and destroys the key.'**
  String get wipeThisDeviceDescription;

  /// No description provided for @lockingExplanation.
  ///
  /// In en, this message translates to:
  /// **'Locking is not a screen that hides your codes. It removes the key from memory, so the stored codes cannot be read until you unlock again.'**
  String get lockingExplanation;

  /// No description provided for @useDeviceSetting.
  ///
  /// In en, this message translates to:
  /// **'Use device setting'**
  String get useDeviceSetting;

  /// No description provided for @lightTheme.
  ///
  /// In en, this message translates to:
  /// **'Light'**
  String get lightTheme;

  /// No description provided for @darkTheme.
  ///
  /// In en, this message translates to:
  /// **'Dark'**
  String get darkTheme;

  /// No description provided for @amoledTheme.
  ///
  /// In en, this message translates to:
  /// **'AMOLED black'**
  String get amoledTheme;

  /// No description provided for @comfortableDensity.
  ///
  /// In en, this message translates to:
  /// **'Comfortable'**
  String get comfortableDensity;

  /// No description provided for @compactDensity.
  ///
  /// In en, this message translates to:
  /// **'Compact'**
  String get compactDensity;

  /// No description provided for @automaticBackup.
  ///
  /// In en, this message translates to:
  /// **'Automatic backup'**
  String get automaticBackup;

  /// No description provided for @automaticEncryptedBackups.
  ///
  /// In en, this message translates to:
  /// **'Automatic encrypted backups'**
  String get automaticEncryptedBackups;

  /// No description provided for @readingBackupSettings.
  ///
  /// In en, this message translates to:
  /// **'Reading backup settings.'**
  String get readingBackupSettings;

  /// No description provided for @changeBackupDirectory.
  ///
  /// In en, this message translates to:
  /// **'Change backup directory'**
  String get changeBackupDirectory;

  /// No description provided for @backUpNow.
  ///
  /// In en, this message translates to:
  /// **'Back up now'**
  String get backUpNow;

  /// No description provided for @backUp.
  ///
  /// In en, this message translates to:
  /// **'Back up'**
  String get backUp;

  /// No description provided for @encryptedBackup.
  ///
  /// In en, this message translates to:
  /// **'Encrypted backup'**
  String get encryptedBackup;

  /// No description provided for @encryptedBackupDescription.
  ///
  /// In en, this message translates to:
  /// **'Every code, in a file only your passphrase opens. Keep it somewhere you will still have it if this phone is lost.'**
  String get encryptedBackupDescription;

  /// No description provided for @unprotectedExport.
  ///
  /// In en, this message translates to:
  /// **'Unprotected export'**
  String get unprotectedExport;

  /// No description provided for @unprotectedExportDescription.
  ///
  /// In en, this message translates to:
  /// **'A readable file with every secret in it. For moving to another app — not for keeping.'**
  String get unprotectedExportDescription;

  /// No description provided for @restore.
  ///
  /// In en, this message translates to:
  /// **'Restore'**
  String get restore;

  /// No description provided for @testBackup.
  ///
  /// In en, this message translates to:
  /// **'Test a backup'**
  String get testBackup;

  /// No description provided for @testBackupDescription.
  ///
  /// In en, this message translates to:
  /// **'Checks that a backup opens and reports its contents. Nothing is added to this vault.'**
  String get testBackupDescription;

  /// No description provided for @restoreFromBackup.
  ///
  /// In en, this message translates to:
  /// **'Restore from a backup'**
  String get restoreFromBackup;

  /// No description provided for @restoreFromBackupDescription.
  ///
  /// In en, this message translates to:
  /// **'Adds the accounts in a backup file to this device. Accounts you already have are left alone.'**
  String get restoreFromBackupDescription;

  /// No description provided for @getNewRecoveryPhrase.
  ///
  /// In en, this message translates to:
  /// **'Get a new recovery phrase'**
  String get getNewRecoveryPhrase;

  /// No description provided for @getNewRecoveryPhraseDescription.
  ///
  /// In en, this message translates to:
  /// **'Your old phrase cannot be shown again — it is not stored anywhere. This gives you a new one and retires the old.'**
  String get getNewRecoveryPhraseDescription;

  /// No description provided for @backupTestPassed.
  ///
  /// In en, this message translates to:
  /// **'Backup test passed'**
  String get backupTestPassed;

  /// No description provided for @backupTestResult.
  ///
  /// In en, this message translates to:
  /// **'The file opened without changing this vault.\n\nAccounts: {accounts}\nFolders: {folders}\nEncryption: {encryption}'**
  String backupTestResult(int accounts, int folders, String encryption);

  /// No description provided for @encrypted.
  ///
  /// In en, this message translates to:
  /// **'Encrypted'**
  String get encrypted;

  /// No description provided for @notEncrypted.
  ///
  /// In en, this message translates to:
  /// **'Not encrypted'**
  String get notEncrypted;

  /// No description provided for @done.
  ///
  /// In en, this message translates to:
  /// **'Done'**
  String get done;

  /// No description provided for @editEntry.
  ///
  /// In en, this message translates to:
  /// **'Edit entry'**
  String get editEntry;

  /// No description provided for @save.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// No description provided for @service.
  ///
  /// In en, this message translates to:
  /// **'Service'**
  String get service;

  /// No description provided for @optional.
  ///
  /// In en, this message translates to:
  /// **'Optional'**
  String get optional;

  /// No description provided for @note.
  ///
  /// In en, this message translates to:
  /// **'Note'**
  String get note;

  /// No description provided for @tags.
  ///
  /// In en, this message translates to:
  /// **'Tags'**
  String get tags;

  /// No description provided for @icon.
  ///
  /// In en, this message translates to:
  /// **'Icon'**
  String get icon;

  /// No description provided for @iconDescription.
  ///
  /// In en, this message translates to:
  /// **'Useful when you have more than one account at the same service.'**
  String get iconDescription;

  /// No description provided for @searchIcons.
  ///
  /// In en, this message translates to:
  /// **'Search icons'**
  String get searchIcons;

  /// No description provided for @searchIconsHint.
  ///
  /// In en, this message translates to:
  /// **'work, bank, mail…'**
  String get searchIconsHint;

  /// No description provided for @recent.
  ///
  /// In en, this message translates to:
  /// **'Recent'**
  String get recent;

  /// No description provided for @chooseCustomImage.
  ///
  /// In en, this message translates to:
  /// **'Choose a custom image'**
  String get chooseCustomImage;

  /// No description provided for @noIconMatches.
  ///
  /// In en, this message translates to:
  /// **'No icon matches that search.'**
  String get noIconMatches;

  /// No description provided for @useAutomaticLetter.
  ///
  /// In en, this message translates to:
  /// **'Use the automatic service icon instead'**
  String get useAutomaticLetter;

  /// No description provided for @codeCopied.
  ///
  /// In en, this message translates to:
  /// **'Code copied. The clipboard clears in 30 seconds.'**
  String get codeCopied;

  /// No description provided for @accountAdded.
  ///
  /// In en, this message translates to:
  /// **'Account added.'**
  String get accountAdded;

  /// No description provided for @clipboardHasNoText.
  ///
  /// In en, this message translates to:
  /// **'The clipboard has no text.'**
  String get clipboardHasNoText;

  /// No description provided for @clipboardHasNoSetupLink.
  ///
  /// In en, this message translates to:
  /// **'The clipboard does not contain a setup link.'**
  String get clipboardHasNoSetupLink;

  /// No description provided for @moveEntriesToTrash.
  ///
  /// In en, this message translates to:
  /// **'Move {count} entries to Trash?'**
  String moveEntriesToTrash(int count);

  /// No description provided for @moveEntriesToTrashDescription.
  ///
  /// In en, this message translates to:
  /// **'The entries move to Trash on every device. You can restore them for 30 days.'**
  String get moveEntriesToTrashDescription;

  /// No description provided for @cancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// No description provided for @moveToTrash.
  ///
  /// In en, this message translates to:
  /// **'Move to Trash'**
  String get moveToTrash;

  /// No description provided for @entriesMovedToTrash.
  ///
  /// In en, this message translates to:
  /// **'{count} entries moved to Trash.'**
  String entriesMovedToTrash(int count);

  /// No description provided for @add.
  ///
  /// In en, this message translates to:
  /// **'Add'**
  String get add;

  /// No description provided for @selectAccountForDetails.
  ///
  /// In en, this message translates to:
  /// **'Select an account to view its details.'**
  String get selectAccountForDetails;

  /// No description provided for @revealCode.
  ///
  /// In en, this message translates to:
  /// **'Reveal code'**
  String get revealCode;

  /// No description provided for @copyCode.
  ///
  /// In en, this message translates to:
  /// **'Copy code'**
  String get copyCode;

  /// No description provided for @rename.
  ///
  /// In en, this message translates to:
  /// **'Rename'**
  String get rename;

  /// No description provided for @deleteFolder.
  ///
  /// In en, this message translates to:
  /// **'Delete folder'**
  String get deleteFolder;

  /// No description provided for @folderAccountsKept.
  ///
  /// In en, this message translates to:
  /// **'The accounts in it are kept'**
  String get folderAccountsKept;

  /// No description provided for @accountIsInTrash.
  ///
  /// In en, this message translates to:
  /// **'That account is in Trash.'**
  String get accountIsInTrash;

  /// No description provided for @alreadySavedAs.
  ///
  /// In en, this message translates to:
  /// **'Already saved as {label}.'**
  String alreadySavedAs(String label);

  /// No description provided for @emptyVaultDescription.
  ///
  /// In en, this message translates to:
  /// **'Add one by scanning the QR code a service shows you, or by entering its setup key by hand.'**
  String get emptyVaultDescription;

  /// No description provided for @scan.
  ///
  /// In en, this message translates to:
  /// **'Scan'**
  String get scan;

  /// No description provided for @enterKey.
  ///
  /// In en, this message translates to:
  /// **'Enter key'**
  String get enterKey;

  /// No description provided for @importFile.
  ///
  /// In en, this message translates to:
  /// **'Import file'**
  String get importFile;

  /// No description provided for @sharedAccountImportFailed.
  ///
  /// In en, this message translates to:
  /// **'The shared account could not be imported: {error}'**
  String sharedAccountImportFailed(String error);

  /// No description provided for @scanShareQr.
  ///
  /// In en, this message translates to:
  /// **'Scan share QR code'**
  String get scanShareQr;

  /// No description provided for @pasteShareLink.
  ///
  /// In en, this message translates to:
  /// **'Paste share link'**
  String get pasteShareLink;

  /// No description provided for @nextCode.
  ///
  /// In en, this message translates to:
  /// **'Next code'**
  String get nextCode;

  /// No description provided for @copyNextCode.
  ///
  /// In en, this message translates to:
  /// **'Copy next code'**
  String get copyNextCode;

  /// No description provided for @deleteEntryQuestion.
  ///
  /// In en, this message translates to:
  /// **'Delete {label}?'**
  String deleteEntryQuestion(String label);

  /// No description provided for @deleteEntryDescription.
  ///
  /// In en, this message translates to:
  /// **'This moves the entry to Trash on every device. You can restore it for 30 days.'**
  String get deleteEntryDescription;

  /// No description provided for @keep.
  ///
  /// In en, this message translates to:
  /// **'Keep'**
  String get keep;

  /// No description provided for @delete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get delete;

  /// No description provided for @entryMovedToTrash.
  ///
  /// In en, this message translates to:
  /// **'Entry moved to Trash.'**
  String get entryMovedToTrash;

  /// No description provided for @scanQrCode.
  ///
  /// In en, this message translates to:
  /// **'Scan a QR code'**
  String get scanQrCode;

  /// No description provided for @enterSetupKey.
  ///
  /// In en, this message translates to:
  /// **'Enter a setup key'**
  String get enterSetupKey;

  /// No description provided for @pasteSetupLink.
  ///
  /// In en, this message translates to:
  /// **'Paste a setup link'**
  String get pasteSetupLink;

  /// No description provided for @pasteSetupLinkDescription.
  ///
  /// In en, this message translates to:
  /// **'Read an otpauth link from the clipboard'**
  String get pasteSetupLinkDescription;

  /// No description provided for @importSharedAccount.
  ///
  /// In en, this message translates to:
  /// **'Import a shared account'**
  String get importSharedAccount;

  /// No description provided for @importSharedAccountDescription.
  ///
  /// In en, this message translates to:
  /// **'Scan a share QR code or paste its link'**
  String get importSharedAccountDescription;

  /// No description provided for @importFromFile.
  ///
  /// In en, this message translates to:
  /// **'Import from a file'**
  String get importFromFile;

  /// No description provided for @supportedImportFiles.
  ///
  /// In en, this message translates to:
  /// **'Aegis, 2FAS, Ente, Proton, Bitwarden, or Standard Notes'**
  String get supportedImportFiles;

  /// No description provided for @movingFromAnotherApp.
  ///
  /// In en, this message translates to:
  /// **'Moving from another app?'**
  String get movingFromAnotherApp;

  /// No description provided for @supportedMigrationApps.
  ///
  /// In en, this message translates to:
  /// **'Google, Aegis, 2FAS, Authy, Microsoft'**
  String get supportedMigrationApps;

  /// No description provided for @viewDetails.
  ///
  /// In en, this message translates to:
  /// **'View details'**
  String get viewDetails;

  /// No description provided for @edit.
  ///
  /// In en, this message translates to:
  /// **'Edit'**
  String get edit;

  /// No description provided for @moveToFolder.
  ///
  /// In en, this message translates to:
  /// **'Move to folder'**
  String get moveToFolder;

  /// No description provided for @moveToAnotherApp.
  ///
  /// In en, this message translates to:
  /// **'Move to another app'**
  String get moveToAnotherApp;

  /// No description provided for @shareEncryptedLink.
  ///
  /// In en, this message translates to:
  /// **'Share encrypted link'**
  String get shareEncryptedLink;

  /// No description provided for @previewNextCode.
  ///
  /// In en, this message translates to:
  /// **'Preview next code'**
  String get previewNextCode;

  /// No description provided for @create.
  ///
  /// In en, this message translates to:
  /// **'Create'**
  String get create;

  /// No description provided for @noFolder.
  ///
  /// In en, this message translates to:
  /// **'No folder'**
  String get noFolder;

  /// No description provided for @newFolder.
  ///
  /// In en, this message translates to:
  /// **'New folder'**
  String get newFolder;

  /// No description provided for @renameFolder.
  ///
  /// In en, this message translates to:
  /// **'Rename folder'**
  String get renameFolder;

  /// No description provided for @entryRestored.
  ///
  /// In en, this message translates to:
  /// **'Entry restored.'**
  String get entryRestored;

  /// No description provided for @deletePermanentlyQuestion.
  ///
  /// In en, this message translates to:
  /// **'Delete {label} permanently?'**
  String deletePermanentlyQuestion(String label);

  /// No description provided for @deletePermanentlyDescription.
  ///
  /// In en, this message translates to:
  /// **'This action cannot be undone. The entry will be removed from every device after synchronization.'**
  String get deletePermanentlyDescription;

  /// No description provided for @deletePermanently.
  ///
  /// In en, this message translates to:
  /// **'Delete permanently'**
  String get deletePermanently;

  /// No description provided for @tryAgain.
  ///
  /// In en, this message translates to:
  /// **'Try again'**
  String get tryAgain;

  /// No description provided for @trashEmpty.
  ///
  /// In en, this message translates to:
  /// **'Trash is empty.'**
  String get trashEmpty;

  /// No description provided for @shareLinkCopied.
  ///
  /// In en, this message translates to:
  /// **'Share link copied. The clipboard clears in 30 seconds.'**
  String get shareLinkCopied;

  /// No description provided for @shareAccount.
  ///
  /// In en, this message translates to:
  /// **'Share account'**
  String get shareAccount;

  /// No description provided for @shareEncryptionDescription.
  ///
  /// In en, this message translates to:
  /// **'The app encrypts this account before upload. The server cannot read it. The decryption key stays after the # character in the link and is not sent to the server.'**
  String get shareEncryptionDescription;

  /// No description provided for @linkExpiresAfter.
  ///
  /// In en, this message translates to:
  /// **'Link expires after'**
  String get linkExpiresAfter;

  /// No description provided for @fiveMinutes.
  ///
  /// In en, this message translates to:
  /// **'5 minutes'**
  String get fiveMinutes;

  /// No description provided for @oneHour.
  ///
  /// In en, this message translates to:
  /// **'1 hour'**
  String get oneHour;

  /// No description provided for @sixHours.
  ///
  /// In en, this message translates to:
  /// **'6 hours'**
  String get sixHours;

  /// No description provided for @twentyFourHours.
  ///
  /// In en, this message translates to:
  /// **'24 hours'**
  String get twentyFourHours;

  /// No description provided for @deleteAfterFirstDownload.
  ///
  /// In en, this message translates to:
  /// **'Delete after first download'**
  String get deleteAfterFirstDownload;

  /// No description provided for @oneTimeShareDescription.
  ///
  /// In en, this message translates to:
  /// **'A second device cannot download the same share.'**
  String get oneTimeShareDescription;

  /// No description provided for @createEncryptedLink.
  ///
  /// In en, this message translates to:
  /// **'Create encrypted link'**
  String get createEncryptedLink;

  /// No description provided for @shareCreationFailed.
  ///
  /// In en, this message translates to:
  /// **'The share could not be created: {error}'**
  String shareCreationFailed(String error);

  /// No description provided for @shareSignInDescription.
  ///
  /// In en, this message translates to:
  /// **'You must be signed in to create a link. The recipient does not need an account.'**
  String get shareSignInDescription;

  /// No description provided for @copyShareLink.
  ///
  /// In en, this message translates to:
  /// **'Copy share link'**
  String get copyShareLink;

  /// No description provided for @shareLinkWarning.
  ///
  /// In en, this message translates to:
  /// **'Anyone who has the complete link can import this account until the link expires or is downloaded once. Send it only to the intended recipient.'**
  String get shareLinkWarning;

  /// No description provided for @pendingPermanentDeletion.
  ///
  /// In en, this message translates to:
  /// **'Pending permanent deletion'**
  String get pendingPermanentDeletion;

  /// No description provided for @permanentlyDeletedInOneDay.
  ///
  /// In en, this message translates to:
  /// **'Permanently deleted in 1 day'**
  String get permanentlyDeletedInOneDay;

  /// No description provided for @permanentlyDeletedInDays.
  ///
  /// In en, this message translates to:
  /// **'Permanently deleted in {days} days'**
  String permanentlyDeletedInDays(int days);

  /// No description provided for @expiresAt.
  ///
  /// In en, this message translates to:
  /// **'Expires: {time}'**
  String expiresAt(String time);

  /// No description provided for @signOutOfSyncQuestion.
  ///
  /// In en, this message translates to:
  /// **'Sign out of sync?'**
  String get signOutOfSyncQuestion;

  /// No description provided for @signOutOfSyncDescription.
  ///
  /// In en, this message translates to:
  /// **'Your codes stay on this device. This device just stops sending and receiving changes until you sign in again.'**
  String get signOutOfSyncDescription;

  /// No description provided for @signOut.
  ///
  /// In en, this message translates to:
  /// **'Sign out'**
  String get signOut;

  /// No description provided for @syncEncryptionDescription.
  ///
  /// In en, this message translates to:
  /// **'Sync keeps your codes on every device you sign in to. The server stores them encrypted and cannot read them.'**
  String get syncEncryptionDescription;

  /// No description provided for @turnOnSync.
  ///
  /// In en, this message translates to:
  /// **'Turn on sync for this device'**
  String get turnOnSync;

  /// No description provided for @turnOnSyncDescription.
  ///
  /// In en, this message translates to:
  /// **'Uses the account already on this device.'**
  String get turnOnSyncDescription;

  /// No description provided for @signInExistingAccount.
  ///
  /// In en, this message translates to:
  /// **'Sign in to an existing account'**
  String get signInExistingAccount;

  /// No description provided for @signInExistingAccountDescription.
  ///
  /// In en, this message translates to:
  /// **'For a device that has not joined this vault yet.'**
  String get signInExistingAccountDescription;

  /// No description provided for @unknown.
  ///
  /// In en, this message translates to:
  /// **'unknown'**
  String get unknown;

  /// No description provided for @server.
  ///
  /// In en, this message translates to:
  /// **'Server'**
  String get server;

  /// No description provided for @notSet.
  ///
  /// In en, this message translates to:
  /// **'not set'**
  String get notSet;

  /// No description provided for @syncNow.
  ///
  /// In en, this message translates to:
  /// **'Sync now'**
  String get syncNow;

  /// No description provided for @signOutOfSync.
  ///
  /// In en, this message translates to:
  /// **'Sign out of sync'**
  String get signOutOfSync;

  /// No description provided for @codesStayOnDevice.
  ///
  /// In en, this message translates to:
  /// **'Your codes stay on this device.'**
  String get codesStayOnDevice;

  /// No description provided for @noCompletedSync.
  ///
  /// In en, this message translates to:
  /// **'No completed sync yet'**
  String get noCompletedSync;

  /// No description provided for @unknownWhileLocked.
  ///
  /// In en, this message translates to:
  /// **'Unknown while locked'**
  String get unknownWhileLocked;

  /// No description provided for @couldNotLoad.
  ///
  /// In en, this message translates to:
  /// **'Could not load'**
  String get couldNotLoad;

  /// No description provided for @loading.
  ///
  /// In en, this message translates to:
  /// **'Loading'**
  String get loading;

  /// No description provided for @synchronizationStatus.
  ///
  /// In en, this message translates to:
  /// **'Synchronization status'**
  String get synchronizationStatus;

  /// No description provided for @lastSync.
  ///
  /// In en, this message translates to:
  /// **'Last sync'**
  String get lastSync;

  /// No description provided for @pendingChanges.
  ///
  /// In en, this message translates to:
  /// **'Pending changes'**
  String get pendingChanges;

  /// No description provided for @activeDevices.
  ///
  /// In en, this message translates to:
  /// **'Active devices'**
  String get activeDevices;

  /// No description provided for @notConfigured.
  ///
  /// In en, this message translates to:
  /// **'Not configured'**
  String get notConfigured;

  /// No description provided for @retry.
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get retry;

  /// No description provided for @syncIsOff.
  ///
  /// In en, this message translates to:
  /// **'Sync is off'**
  String get syncIsOff;

  /// No description provided for @synced.
  ///
  /// In en, this message translates to:
  /// **'Synced'**
  String get synced;

  /// No description provided for @changesWaiting.
  ///
  /// In en, this message translates to:
  /// **'{count} waiting to sync'**
  String changesWaiting(int count);

  /// No description provided for @changesWaitingUnknown.
  ///
  /// In en, this message translates to:
  /// **'Changes are waiting to sync'**
  String get changesWaitingUnknown;

  /// No description provided for @offline.
  ///
  /// In en, this message translates to:
  /// **'Offline'**
  String get offline;

  /// No description provided for @syncSessionExpired.
  ///
  /// In en, this message translates to:
  /// **'Sync session expired'**
  String get syncSessionExpired;

  /// No description provided for @signThisDeviceOutQuestion.
  ///
  /// In en, this message translates to:
  /// **'Sign this device out?'**
  String get signThisDeviceOutQuestion;

  /// No description provided for @removeDeviceQuestion.
  ///
  /// In en, this message translates to:
  /// **'Remove {name}?'**
  String removeDeviceQuestion(String name);

  /// No description provided for @signThisDeviceOutDescription.
  ///
  /// In en, this message translates to:
  /// **'You will be signed out here and your codes will stop syncing until you sign in again. The codes already on this device are kept.'**
  String get signThisDeviceOutDescription;

  /// No description provided for @removeDeviceDescription.
  ///
  /// In en, this message translates to:
  /// **'It will stop syncing straight away and will need your password to sign in again.\n\nThe codes already on that device are not deleted. If the device is lost and unlocked, change the passwords it protects.'**
  String get removeDeviceDescription;

  /// No description provided for @remove.
  ///
  /// In en, this message translates to:
  /// **'Remove'**
  String get remove;

  /// No description provided for @signOutEverywhereQuestion.
  ///
  /// In en, this message translates to:
  /// **'Sign out everywhere?'**
  String get signOutEverywhereQuestion;

  /// No description provided for @signOutEverywhereDescription.
  ///
  /// In en, this message translates to:
  /// **'Every device, including this one, will need your password to sign in again.\n\nUse this if you think someone else has access and you are not sure which device. Your codes are not deleted anywhere.'**
  String get signOutEverywhereDescription;

  /// No description provided for @signOutEverywhere.
  ///
  /// In en, this message translates to:
  /// **'Sign out everywhere'**
  String get signOutEverywhere;

  /// No description provided for @accountDeletedResult.
  ///
  /// In en, this message translates to:
  /// **'Account deleted. {count} encrypted {count, plural, =1{record was} other{records were}} destroyed. Your codes on this device are still here.'**
  String accountDeletedResult(int count);

  /// No description provided for @refresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get refresh;

  /// No description provided for @devicesIntroduction.
  ///
  /// In en, this message translates to:
  /// **'These devices can sync your codes. Removing one stops it immediately.'**
  String get devicesIntroduction;

  /// No description provided for @signOutEverywhereDescriptionShort.
  ///
  /// In en, this message translates to:
  /// **'Every device needs the password again. Nothing is deleted.'**
  String get signOutEverywhereDescriptionShort;

  /// No description provided for @deleteSyncAccount.
  ///
  /// In en, this message translates to:
  /// **'Delete sync account'**
  String get deleteSyncAccount;

  /// No description provided for @deleteSyncAccountDescription.
  ///
  /// In en, this message translates to:
  /// **'Removes everything from the server. The codes on this device stay.'**
  String get deleteSyncAccountDescription;

  /// No description provided for @neverSynced.
  ///
  /// In en, this message translates to:
  /// **'Never synced'**
  String get neverSynced;

  /// No description provided for @lastSyncedAt.
  ///
  /// In en, this message translates to:
  /// **'Last synced {time}'**
  String lastSyncedAt(String time);

  /// No description provided for @activeNow.
  ///
  /// In en, this message translates to:
  /// **'Active now'**
  String get activeNow;

  /// No description provided for @minutesAgo.
  ///
  /// In en, this message translates to:
  /// **'{count} minutes ago'**
  String minutesAgo(int count);

  /// No description provided for @hoursAgo.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 hour ago} other{{count} hours ago}}'**
  String hoursAgo(int count);

  /// No description provided for @daysAgo.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 day ago} other{{count} days ago}}'**
  String daysAgo(int count);

  /// No description provided for @removed.
  ///
  /// In en, this message translates to:
  /// **'Removed'**
  String get removed;

  /// No description provided for @removeThisDevice.
  ///
  /// In en, this message translates to:
  /// **'Remove this device'**
  String get removeThisDevice;

  /// No description provided for @deleteSyncAccountQuestion.
  ///
  /// In en, this message translates to:
  /// **'Delete your sync account?'**
  String get deleteSyncAccountQuestion;

  /// No description provided for @deleteSyncAccountWarning.
  ///
  /// In en, this message translates to:
  /// **'Everything stored on the server is destroyed and every device is signed out. This cannot be undone.'**
  String get deleteSyncAccountWarning;

  /// No description provided for @deleteSyncAccountKeepsCodes.
  ///
  /// In en, this message translates to:
  /// **'The codes on this device are kept and will keep working. Your other devices keep the codes they already have, but nothing will sync between them again.'**
  String get deleteSyncAccountKeepsCodes;

  /// No description provided for @accountPassword.
  ///
  /// In en, this message translates to:
  /// **'Account password'**
  String get accountPassword;

  /// No description provided for @deleteAccount.
  ///
  /// In en, this message translates to:
  /// **'Delete account'**
  String get deleteAccount;

  /// No description provided for @allowScreenCaptureQuestion.
  ///
  /// In en, this message translates to:
  /// **'Allow screen capture?'**
  String get allowScreenCaptureQuestion;

  /// No description provided for @allowScreenCaptureWarning.
  ///
  /// In en, this message translates to:
  /// **'Screenshots and screen recording can capture codes, QR codes, account names, notes, and custom images. Other apps and backup services can keep those images.'**
  String get allowScreenCaptureWarning;

  /// No description provided for @allow.
  ///
  /// In en, this message translates to:
  /// **'Allow'**
  String get allow;

  /// No description provided for @screenshotSettingFailed.
  ///
  /// In en, this message translates to:
  /// **'The screenshot setting could not be changed: {error}'**
  String screenshotSettingFailed(String error);

  /// No description provided for @codeVisibilitySettingFailed.
  ///
  /// In en, this message translates to:
  /// **'The code visibility setting failed: {error}'**
  String codeVisibilitySettingFailed(String error);

  /// No description provided for @applicationTheme.
  ///
  /// In en, this message translates to:
  /// **'Application theme'**
  String get applicationTheme;

  /// No description provided for @themeSettingFailed.
  ///
  /// In en, this message translates to:
  /// **'The theme setting failed: {error}'**
  String themeSettingFailed(String error);

  /// No description provided for @listSpacingSettingFailed.
  ///
  /// In en, this message translates to:
  /// **'The list spacing setting failed: {error}'**
  String listSpacingSettingFailed(String error);

  /// No description provided for @wipeThisDeviceQuestion.
  ///
  /// In en, this message translates to:
  /// **'Wipe this device?'**
  String get wipeThisDeviceQuestion;

  /// No description provided for @wipeThisDeviceWarning.
  ///
  /// In en, this message translates to:
  /// **'Every code on this device is deleted and the key that decrypts them is destroyed. If you have not set up sync, nothing can bring them back.'**
  String get wipeThisDeviceWarning;

  /// No description provided for @wipe.
  ///
  /// In en, this message translates to:
  /// **'Wipe'**
  String get wipe;

  /// No description provided for @deleteAfterAttemptsQuestion.
  ///
  /// In en, this message translates to:
  /// **'Delete everything after failed attempts?'**
  String get deleteAfterAttemptsQuestion;

  /// No description provided for @deleteAfterAttemptsWarning.
  ///
  /// In en, this message translates to:
  /// **'After {count} wrong attempts in a row, every code on this device will be deleted and the key destroyed.\n\nNobody can undo it or recover them for you. Make sure you have a backup or another signed-in device.'**
  String deleteAfterAttemptsWarning(int count);

  /// No description provided for @turnItOn.
  ///
  /// In en, this message translates to:
  /// **'Turn it on'**
  String get turnItOn;

  /// No description provided for @off.
  ///
  /// In en, this message translates to:
  /// **'Off'**
  String get off;

  /// No description provided for @wrongAttemptsCounted.
  ///
  /// In en, this message translates to:
  /// **'Wrong attempts are counted, nothing is deleted.'**
  String get wrongAttemptsCounted;

  /// No description provided for @afterWrongAttempts.
  ///
  /// In en, this message translates to:
  /// **'After {count} wrong attempts'**
  String afterWrongAttempts(int count);

  /// No description provided for @choosePassphrase.
  ///
  /// In en, this message translates to:
  /// **'Choose a passphrase'**
  String get choosePassphrase;

  /// No description provided for @backupPassphraseWarning.
  ///
  /// In en, this message translates to:
  /// **'This passphrase is the only thing that opens the backup. It cannot be reset. Keep a copy outside this device.'**
  String get backupPassphraseWarning;

  /// No description provided for @automaticPassphraseStorage.
  ///
  /// In en, this message translates to:
  /// **'This device stores the passphrase in secure storage so it can create backups without asking each time.'**
  String get automaticPassphraseStorage;

  /// No description provided for @passphrase.
  ///
  /// In en, this message translates to:
  /// **'Passphrase'**
  String get passphrase;

  /// No description provided for @typeAgain.
  ///
  /// In en, this message translates to:
  /// **'Type it again'**
  String get typeAgain;

  /// No description provided for @thisBackupIsEncrypted.
  ///
  /// In en, this message translates to:
  /// **'This backup is encrypted'**
  String get thisBackupIsEncrypted;

  /// No description provided for @backupPassphrase.
  ///
  /// In en, this message translates to:
  /// **'Backup passphrase'**
  String get backupPassphrase;

  /// No description provided for @thisFileProtectsNothing.
  ///
  /// In en, this message translates to:
  /// **'This file protects nothing'**
  String get thisFileProtectsNothing;

  /// No description provided for @useEncryptedBackup.
  ///
  /// In en, this message translates to:
  /// **'Use the encrypted backup'**
  String get useEncryptedBackup;

  /// No description provided for @continueAnyway.
  ///
  /// In en, this message translates to:
  /// **'Continue anyway'**
  String get continueAnyway;

  /// No description provided for @typeExportToContinue.
  ///
  /// In en, this message translates to:
  /// **'Type EXPORT to continue'**
  String get typeExportToContinue;

  /// No description provided for @exportPlainText.
  ///
  /// In en, this message translates to:
  /// **'Export in plain text'**
  String get exportPlainText;

  /// No description provided for @enterAccountPassword.
  ///
  /// In en, this message translates to:
  /// **'Enter your account password'**
  String get enterAccountPassword;

  /// No description provided for @rotateRecoveryWarning.
  ///
  /// In en, this message translates to:
  /// **'Your current recovery phrase will stop working. If you have it stored anywhere, replace it with the new phrase.'**
  String get rotateRecoveryWarning;

  /// No description provided for @continueAction.
  ///
  /// In en, this message translates to:
  /// **'Continue'**
  String get continueAction;

  /// No description provided for @wipeThresholdExplanation.
  ///
  /// In en, this message translates to:
  /// **'If someone gets this phone and guesses your PIN, this setting deletes every code instead of letting them continue.\n\nThis cannot be undone. Keep a backup or a second device before you turn it on.'**
  String get wipeThresholdExplanation;

  /// No description provided for @immediately.
  ///
  /// In en, this message translates to:
  /// **'Immediately'**
  String get immediately;

  /// No description provided for @after15Seconds.
  ///
  /// In en, this message translates to:
  /// **'After 15 seconds'**
  String get after15Seconds;

  /// No description provided for @after1Minute.
  ///
  /// In en, this message translates to:
  /// **'After 1 minute'**
  String get after1Minute;

  /// No description provided for @after5Minutes.
  ///
  /// In en, this message translates to:
  /// **'After 5 minutes'**
  String get after5Minutes;

  /// No description provided for @after15Minutes.
  ///
  /// In en, this message translates to:
  /// **'After 15 minutes'**
  String get after15Minutes;

  /// No description provided for @never.
  ///
  /// In en, this message translates to:
  /// **'Never'**
  String get never;

  /// No description provided for @minimumCharacters.
  ///
  /// In en, this message translates to:
  /// **'Use at least {count} characters.'**
  String minimumCharacters(int count);

  /// No description provided for @passphrasesDifferent.
  ///
  /// In en, this message translates to:
  /// **'The two passphrases are different.'**
  String get passphrasesDifferent;

  /// No description provided for @turnOn.
  ///
  /// In en, this message translates to:
  /// **'Turn on'**
  String get turnOn;

  /// No description provided for @plainExportWarning.
  ///
  /// In en, this message translates to:
  /// **'Every code in your vault will be written in plain text. Anyone who opens the file, or any app or cloud service that reads it, can sign in as you.\n\nUse this only to move to another app. Delete the file when you finish.\n\nFor a backup that you keep, use an encrypted backup.'**
  String get plainExportWarning;

  /// No description provided for @exportWord.
  ///
  /// In en, this message translates to:
  /// **'EXPORT'**
  String get exportWord;

  /// No description provided for @copiedClipboardTwoMinutes.
  ///
  /// In en, this message translates to:
  /// **'Copied. The clipboard clears in 2 minutes.'**
  String get copiedClipboardTwoMinutes;

  /// No description provided for @copyToClipboard.
  ///
  /// In en, this message translates to:
  /// **'Copy to clipboard'**
  String get copyToClipboard;

  /// No description provided for @recoveryWrittenDown.
  ///
  /// In en, this message translates to:
  /// **'I have written these words down'**
  String get recoveryWrittenDown;

  /// No description provided for @confirmRecoveryInstructions.
  ///
  /// In en, this message translates to:
  /// **'Type these words from your list. This checks that you wrote them down correctly.'**
  String get confirmRecoveryInstructions;

  /// No description provided for @confirm.
  ///
  /// In en, this message translates to:
  /// **'Confirm'**
  String get confirm;

  /// No description provided for @showWordsAgain.
  ///
  /// In en, this message translates to:
  /// **'Show the words again'**
  String get showWordsAgain;

  /// No description provided for @selectWidgetAccount.
  ///
  /// In en, this message translates to:
  /// **'Select the widget account'**
  String get selectWidgetAccount;

  /// No description provided for @widgetDescription.
  ///
  /// In en, this message translates to:
  /// **'The widget shows one account name. Tap it to unlock the app and view the current code.'**
  String get widgetDescription;

  /// No description provided for @noWidgetAccount.
  ///
  /// In en, this message translates to:
  /// **'No account is selected.'**
  String get noWidgetAccount;

  /// No description provided for @disableWidget.
  ///
  /// In en, this message translates to:
  /// **'Disable widget'**
  String get disableWidget;

  /// No description provided for @addAccountBeforeWidget.
  ///
  /// In en, this message translates to:
  /// **'Add an account before you configure the widget.'**
  String get addAccountBeforeWidget;

  /// No description provided for @widgetLauncherInstructions.
  ///
  /// In en, this message translates to:
  /// **'After you select an account, use your Android launcher to add the Authenticator widget.'**
  String get widgetLauncherInstructions;

  /// No description provided for @removePinQuestion.
  ///
  /// In en, this message translates to:
  /// **'Remove the PIN?'**
  String get removePinQuestion;

  /// No description provided for @removePinWarning.
  ///
  /// In en, this message translates to:
  /// **'Your codes stay encrypted, but anyone who can unlock this device can open them without a separate PIN.'**
  String get removePinWarning;

  /// No description provided for @keepIt.
  ///
  /// In en, this message translates to:
  /// **'Keep it'**
  String get keepIt;

  /// No description provided for @removePin.
  ///
  /// In en, this message translates to:
  /// **'Remove the PIN'**
  String get removePin;

  /// No description provided for @pinKeyDescription.
  ///
  /// In en, this message translates to:
  /// **'The PIN is combined with a key held by this device. Both are needed to open your codes.'**
  String get pinKeyDescription;

  /// No description provided for @allowBiometricUnlock.
  ///
  /// In en, this message translates to:
  /// **'Allow biometric unlock'**
  String get allowBiometricUnlock;

  /// No description provided for @biometricBindingDescription.
  ///
  /// In en, this message translates to:
  /// **'Binds this device key to your fingerprint or face.'**
  String get biometricBindingDescription;

  /// No description provided for @accountSyncDescription.
  ///
  /// In en, this message translates to:
  /// **'An account lets your codes reach your other devices. They stay encrypted.'**
  String get accountSyncDescription;

  /// No description provided for @skipForNow.
  ///
  /// In en, this message translates to:
  /// **'Skip for now'**
  String get skipForNow;

  /// No description provided for @scanQrCodeTitle.
  ///
  /// In en, this message translates to:
  /// **'Scan QR code'**
  String get scanQrCodeTitle;

  /// No description provided for @manualEntryAlternative.
  ///
  /// In en, this message translates to:
  /// **'You can add the account by entering its setup key instead.'**
  String get manualEntryAlternative;

  /// No description provided for @goBack.
  ///
  /// In en, this message translates to:
  /// **'Go back'**
  String get goBack;

  /// No description provided for @moveThisAccount.
  ///
  /// In en, this message translates to:
  /// **'Move this account'**
  String get moveThisAccount;

  /// No description provided for @tapToShow.
  ///
  /// In en, this message translates to:
  /// **'Tap to show'**
  String get tapToShow;

  /// No description provided for @importedCount.
  ///
  /// In en, this message translates to:
  /// **'Imported {count}'**
  String importedCount(int count);

  /// No description provided for @addSkippedManually.
  ///
  /// In en, this message translates to:
  /// **'Add these by hand from the app you are moving from.'**
  String get addSkippedManually;

  /// No description provided for @bringAccountsAcross.
  ///
  /// In en, this message translates to:
  /// **'Bring your accounts across'**
  String get bringAccountsAcross;

  /// No description provided for @typeSetupKeyManually.
  ///
  /// In en, this message translates to:
  /// **'Type a setup key by hand'**
  String get typeSetupKeyManually;

  /// No description provided for @setupKeyAvailable.
  ///
  /// In en, this message translates to:
  /// **'Every service can show a setup key instead of a QR code.'**
  String get setupKeyAvailable;

  /// No description provided for @importAction.
  ///
  /// In en, this message translates to:
  /// **'Import'**
  String get importAction;

  /// No description provided for @duplicateMovedToTrash.
  ///
  /// In en, this message translates to:
  /// **'Duplicate moved to Trash.'**
  String get duplicateMovedToTrash;

  /// No description provided for @noDuplicateSecrets.
  ///
  /// In en, this message translates to:
  /// **'No duplicate secrets were found.'**
  String get noDuplicateSecrets;

  /// No description provided for @sameSecretDescription.
  ///
  /// In en, this message translates to:
  /// **'These accounts use the same secret.'**
  String get sameSecretDescription;

  /// No description provided for @timeBased.
  ///
  /// In en, this message translates to:
  /// **'Time-based'**
  String get timeBased;

  /// No description provided for @counterBased.
  ///
  /// In en, this message translates to:
  /// **'Counter-based'**
  String get counterBased;

  /// No description provided for @advanced.
  ///
  /// In en, this message translates to:
  /// **'Advanced'**
  String get advanced;

  /// No description provided for @secondsValue.
  ///
  /// In en, this message translates to:
  /// **'{count} seconds'**
  String secondsValue(int count);

  /// No description provided for @stopImportingQuestion.
  ///
  /// In en, this message translates to:
  /// **'Stop importing?'**
  String get stopImportingQuestion;

  /// No description provided for @keepScanning.
  ///
  /// In en, this message translates to:
  /// **'Keep scanning'**
  String get keepScanning;

  /// No description provided for @stop.
  ///
  /// In en, this message translates to:
  /// **'Stop'**
  String get stop;

  /// No description provided for @importGoogleAuthenticator.
  ///
  /// In en, this message translates to:
  /// **'Import from Google Authenticator'**
  String get importGoogleAuthenticator;

  /// No description provided for @importReadyCount.
  ///
  /// In en, this message translates to:
  /// **'Import {count}'**
  String importReadyCount(int count);

  /// No description provided for @quickAccessNoExposedCodes.
  ///
  /// In en, this message translates to:
  /// **'Quick access without exposed codes'**
  String get quickAccessNoExposedCodes;

  /// No description provided for @widgetSettingReadFailed.
  ///
  /// In en, this message translates to:
  /// **'The widget setting could not be read: {error}'**
  String widgetSettingReadFailed(String error);

  /// No description provided for @widgetEnabled.
  ///
  /// In en, this message translates to:
  /// **'Widget enabled'**
  String get widgetEnabled;

  /// No description provided for @widgetDisabled.
  ///
  /// In en, this message translates to:
  /// **'Widget disabled'**
  String get widgetDisabled;

  /// No description provided for @changeAccount.
  ///
  /// In en, this message translates to:
  /// **'Change account'**
  String get changeAccount;

  /// No description provided for @selectAccount.
  ///
  /// In en, this message translates to:
  /// **'Select account'**
  String get selectAccount;

  /// No description provided for @newPinOrPassphrase.
  ///
  /// In en, this message translates to:
  /// **'New PIN or passphrase'**
  String get newPinOrPassphrase;

  /// No description provided for @enterItAgain.
  ///
  /// In en, this message translates to:
  /// **'Enter it again'**
  String get enterItAgain;

  /// No description provided for @entriesDoNotMatch.
  ///
  /// In en, this message translates to:
  /// **'The two entries do not match.'**
  String get entriesDoNotMatch;

  /// No description provided for @biometricInvalidationDescription.
  ///
  /// In en, this message translates to:
  /// **'Binds this device key to your fingerprint or face. Enrolling a new fingerprint invalidates it.'**
  String get biometricInvalidationDescription;

  /// No description provided for @pinDerivationDescription.
  ///
  /// In en, this message translates to:
  /// **'Setting a PIN takes a moment. The key is deliberately slow to derive, which makes guessing slower.'**
  String get pinDerivationDescription;

  /// No description provided for @secretCannotBeChanged.
  ///
  /// In en, this message translates to:
  /// **'The secret cannot be changed'**
  String get secretCannotBeChanged;

  /// No description provided for @secretCannotBeChangedDescription.
  ///
  /// In en, this message translates to:
  /// **'A different secret is a different account, not a rename. Delete this entry and scan the new code.'**
  String get secretCannotBeChangedDescription;

  /// No description provided for @chooseBackupFile.
  ///
  /// In en, this message translates to:
  /// **'Choose a backup file'**
  String get chooseBackupFile;

  /// No description provided for @chooseBackupToTest.
  ///
  /// In en, this message translates to:
  /// **'Choose a backup to test'**
  String get chooseBackupToTest;

  /// No description provided for @password.
  ///
  /// In en, this message translates to:
  /// **'Password'**
  String get password;

  /// No description provided for @emailAddress.
  ///
  /// In en, this message translates to:
  /// **'Email address'**
  String get emailAddress;

  /// No description provided for @email.
  ///
  /// In en, this message translates to:
  /// **'Email'**
  String get email;

  /// No description provided for @enterPasswordAgain.
  ///
  /// In en, this message translates to:
  /// **'Enter the password again'**
  String get enterPasswordAgain;

  /// No description provided for @setupKey.
  ///
  /// In en, this message translates to:
  /// **'Setup key'**
  String get setupKey;

  /// No description provided for @startingCounter.
  ///
  /// In en, this message translates to:
  /// **'Starting counter'**
  String get startingCounter;

  /// No description provided for @algorithm.
  ///
  /// In en, this message translates to:
  /// **'Algorithm'**
  String get algorithm;

  /// No description provided for @digits.
  ///
  /// In en, this message translates to:
  /// **'Digits'**
  String get digits;

  /// No description provided for @period.
  ///
  /// In en, this message translates to:
  /// **'Period'**
  String get period;

  /// No description provided for @folderName.
  ///
  /// In en, this message translates to:
  /// **'Folder name'**
  String get folderName;

  /// No description provided for @syncServer.
  ///
  /// In en, this message translates to:
  /// **'Sync server'**
  String get syncServer;

  /// No description provided for @pinOrPassphrase.
  ///
  /// In en, this message translates to:
  /// **'PIN or passphrase'**
  String get pinOrPassphrase;

  /// No description provided for @wordPosition.
  ///
  /// In en, this message translates to:
  /// **'Word {position}'**
  String wordPosition(int position);

  /// No description provided for @signIn.
  ///
  /// In en, this message translates to:
  /// **'Sign in'**
  String get signIn;

  /// No description provided for @signInDownloadDescription.
  ///
  /// In en, this message translates to:
  /// **'This device downloads your codes and unlocks them with your password. The server never sees the key.'**
  String get signInDownloadDescription;

  /// No description provided for @fromDeviceAccount.
  ///
  /// In en, this message translates to:
  /// **'From the account on this device'**
  String get fromDeviceAccount;

  /// No description provided for @emailRecoveryDescription.
  ///
  /// In en, this message translates to:
  /// **'Used for recovery and for approving new devices.'**
  String get emailRecoveryDescription;

  /// No description provided for @createAccountAction.
  ///
  /// In en, this message translates to:
  /// **'Create account'**
  String get createAccountAction;

  /// No description provided for @addAccount.
  ///
  /// In en, this message translates to:
  /// **'Add account'**
  String get addAccount;

  /// No description provided for @chooseExportFile.
  ///
  /// In en, this message translates to:
  /// **'Choose an export file'**
  String get chooseExportFile;

  /// No description provided for @cancelSelection.
  ///
  /// In en, this message translates to:
  /// **'Cancel selection'**
  String get cancelSelection;

  /// No description provided for @changeFavouriteStatus.
  ///
  /// In en, this message translates to:
  /// **'Change favourite status'**
  String get changeFavouriteStatus;

  /// No description provided for @searchAccountsNotesTags.
  ///
  /// In en, this message translates to:
  /// **'Search accounts, notes, or tags'**
  String get searchAccountsNotesTags;

  /// No description provided for @sort.
  ///
  /// In en, this message translates to:
  /// **'Sort'**
  String get sort;

  /// No description provided for @workExample.
  ///
  /// In en, this message translates to:
  /// **'Work'**
  String get workExample;

  /// No description provided for @issuerExample.
  ///
  /// In en, this message translates to:
  /// **'GitHub'**
  String get issuerExample;

  /// No description provided for @accountExample.
  ///
  /// In en, this message translates to:
  /// **'you@example.com'**
  String get accountExample;

  /// No description provided for @issuerHelper.
  ///
  /// In en, this message translates to:
  /// **'For example, GitHub. Optional.'**
  String get issuerHelper;

  /// No description provided for @accountHelper.
  ///
  /// In en, this message translates to:
  /// **'Your username or email address at that service.'**
  String get accountHelper;

  /// No description provided for @encryptedEntryOptional.
  ///
  /// In en, this message translates to:
  /// **'Encrypted with this entry. Optional.'**
  String get encryptedEntryOptional;

  /// No description provided for @tagsHelper.
  ///
  /// In en, this message translates to:
  /// **'Separate tags with commas. Up to 20 tags.'**
  String get tagsHelper;

  /// No description provided for @tagsExample.
  ///
  /// In en, this message translates to:
  /// **'work, finance'**
  String get tagsExample;

  /// No description provided for @chooseCustomIcon.
  ///
  /// In en, this message translates to:
  /// **'Choose a custom icon'**
  String get chooseCustomIcon;

  /// No description provided for @saveBackup.
  ///
  /// In en, this message translates to:
  /// **'Save your backup'**
  String get saveBackup;

  /// No description provided for @syncServerExample.
  ///
  /// In en, this message translates to:
  /// **'https://…'**
  String get syncServerExample;

  /// No description provided for @chooseQrImage.
  ///
  /// In en, this message translates to:
  /// **'Choose an image with a QR code'**
  String get chooseQrImage;

  /// No description provided for @chooseImage.
  ///
  /// In en, this message translates to:
  /// **'Choose an image'**
  String get chooseImage;

  /// No description provided for @torch.
  ///
  /// In en, this message translates to:
  /// **'Torch'**
  String get torch;

  /// No description provided for @welcomeTitle.
  ///
  /// In en, this message translates to:
  /// **'Your codes, on your terms'**
  String get welcomeTitle;

  /// No description provided for @welcomeDescription.
  ///
  /// In en, this message translates to:
  /// **'Everything is encrypted on this device before it goes anywhere. You can take it all with you at any time.'**
  String get welcomeDescription;

  /// No description provided for @bringMyAccountsAcross.
  ///
  /// In en, this message translates to:
  /// **'Bring my accounts across'**
  String get bringMyAccountsAcross;

  /// No description provided for @bringAccountsSources.
  ///
  /// In en, this message translates to:
  /// **'From Google Authenticator, Aegis, 2FAS, Authy, Microsoft Authenticator, or anywhere else.'**
  String get bringAccountsSources;

  /// No description provided for @setUpSync.
  ///
  /// In en, this message translates to:
  /// **'Set up sync'**
  String get setUpSync;

  /// No description provided for @setUpSyncDescription.
  ///
  /// In en, this message translates to:
  /// **'Keeps your codes on every device you own. The server stores only encrypted data.'**
  String get setUpSyncDescription;

  /// No description provided for @useOnThisPhone.
  ///
  /// In en, this message translates to:
  /// **'Just use it on this phone'**
  String get useOnThisPhone;

  /// No description provided for @useOnThisPhoneDescription.
  ///
  /// In en, this message translates to:
  /// **'No account and no network transfer. You can turn on sync later without adding the accounts again.'**
  String get useOnThisPhoneDescription;

  /// No description provided for @changeLaterInSettings.
  ///
  /// In en, this message translates to:
  /// **'You can change these choices later in Settings.'**
  String get changeLaterInSettings;

  /// No description provided for @nextCodeTooltip.
  ///
  /// In en, this message translates to:
  /// **'Next code'**
  String get nextCodeTooltip;

  /// No description provided for @undo.
  ///
  /// In en, this message translates to:
  /// **'Undo'**
  String get undo;

  /// No description provided for @folder.
  ///
  /// In en, this message translates to:
  /// **'Folder'**
  String get folder;

  /// No description provided for @qrCode.
  ///
  /// In en, this message translates to:
  /// **'QR code'**
  String get qrCode;

  /// No description provided for @share.
  ///
  /// In en, this message translates to:
  /// **'Share'**
  String get share;

  /// No description provided for @showIt.
  ///
  /// In en, this message translates to:
  /// **'Show it'**
  String get showIt;

  /// No description provided for @nameSort.
  ///
  /// In en, this message translates to:
  /// **'Name'**
  String get nameSort;

  /// No description provided for @issuerSort.
  ///
  /// In en, this message translates to:
  /// **'Issuer'**
  String get issuerSort;

  /// No description provided for @recentlyAddedSort.
  ///
  /// In en, this message translates to:
  /// **'Recently added'**
  String get recentlyAddedSort;

  /// No description provided for @manualSort.
  ///
  /// In en, this message translates to:
  /// **'My order'**
  String get manualSort;

  /// No description provided for @noSearchResults.
  ///
  /// In en, this message translates to:
  /// **'No entry matches that search.'**
  String get noSearchResults;

  /// No description provided for @noAccountsYet.
  ///
  /// In en, this message translates to:
  /// **'No accounts yet.'**
  String get noAccountsYet;

  /// No description provided for @availableAfterSeconds.
  ///
  /// In en, this message translates to:
  /// **'Available after {count} seconds.'**
  String availableAfterSeconds(int count);

  /// No description provided for @nextCodeCopied.
  ///
  /// In en, this message translates to:
  /// **'Next code copied. The clipboard clears in 30 seconds.'**
  String get nextCodeCopied;

  /// No description provided for @clockOffsetWarning.
  ///
  /// In en, this message translates to:
  /// **'This device clock is off by about {count} seconds. Codes can fail until you correct the clock.'**
  String clockOffsetWarning(int count);

  /// No description provided for @selectedCount.
  ///
  /// In en, this message translates to:
  /// **'{count} selected'**
  String selectedCount(int count);

  /// No description provided for @vaultOpenFailed.
  ///
  /// In en, this message translates to:
  /// **'The vault could not be opened'**
  String get vaultOpenFailed;

  /// No description provided for @vaultDataSafeAfterOpenFailure.
  ///
  /// In en, this message translates to:
  /// **'Your entries have not been deleted. Close and reopen the application to try again.'**
  String get vaultDataSafeAfterOpenFailure;

  /// No description provided for @unnamedEntry.
  ///
  /// In en, this message translates to:
  /// **'An unnamed entry'**
  String get unnamedEntry;

  /// No description provided for @all.
  ///
  /// In en, this message translates to:
  /// **'All'**
  String get all;

  /// No description provided for @unfiled.
  ///
  /// In en, this message translates to:
  /// **'Unfiled'**
  String get unfiled;

  /// No description provided for @holdToManageFolder.
  ///
  /// In en, this message translates to:
  /// **'Hold to rename or delete'**
  String get holdToManageFolder;

  /// No description provided for @codeExpiresInSeconds.
  ///
  /// In en, this message translates to:
  /// **'Code expires in {count} seconds'**
  String codeExpiresInSeconds(int count);

  /// No description provided for @codeHiddenAccessibility.
  ///
  /// In en, this message translates to:
  /// **'Code hidden. Activate to show.'**
  String get codeHiddenAccessibility;

  /// No description provided for @duplicatesSkipped.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 account was already in your list and was not added again.} other{{count} accounts were already in your list and were not added again.}}'**
  String duplicatesSkipped(int count);

  /// No description provided for @couldNotImportCount.
  ///
  /// In en, this message translates to:
  /// **'{count} could not be imported:'**
  String couldNotImportCount(int count);

  /// No description provided for @unreadableExport.
  ///
  /// In en, this message translates to:
  /// **'That file is not an export this app can read.'**
  String get unreadableExport;

  /// No description provided for @encryptedSourceExport.
  ///
  /// In en, this message translates to:
  /// **'This {source} export is encrypted'**
  String encryptedSourceExport(String source);

  /// No description provided for @enterBackupPassphrase.
  ///
  /// In en, this message translates to:
  /// **'Enter the passphrase you set when you made it.'**
  String get enterBackupPassphrase;

  /// No description provided for @enterSourceExportPassword.
  ///
  /// In en, this message translates to:
  /// **'Enter the password you set in {source} when you created the export.'**
  String enterSourceExportPassword(String source);

  /// No description provided for @syncCatchUpUnlock.
  ///
  /// In en, this message translates to:
  /// **'The app is catching up with your other devices. Unlock again in a moment.'**
  String get syncCatchUpUnlock;

  /// No description provided for @removeFromFavourites.
  ///
  /// In en, this message translates to:
  /// **'Remove from favourites'**
  String get removeFromFavourites;

  /// No description provided for @addToFavourites.
  ///
  /// In en, this message translates to:
  /// **'Add to favourites'**
  String get addToFavourites;

  /// No description provided for @automaticBackupOnMessage.
  ///
  /// In en, this message translates to:
  /// **'Automatic encrypted backup is on.'**
  String get automaticBackupOnMessage;

  /// No description provided for @automaticBackupCancelled.
  ///
  /// In en, this message translates to:
  /// **'Automatic backup setup was cancelled.'**
  String get automaticBackupCancelled;

  /// No description provided for @backupDirectoryChanged.
  ///
  /// In en, this message translates to:
  /// **'The automatic backup directory was changed.'**
  String get backupDirectoryChanged;

  /// No description provided for @automaticBackupSaved.
  ///
  /// In en, this message translates to:
  /// **'Automatic encrypted backup saved.'**
  String get automaticBackupSaved;

  /// No description provided for @automaticBackupAndroidOnly.
  ///
  /// In en, this message translates to:
  /// **'Available on Android.'**
  String get automaticBackupAndroidOnly;

  /// No description provided for @automaticBackupOffStatus.
  ///
  /// In en, this message translates to:
  /// **'Off. Keeps the newest seven encrypted files.'**
  String get automaticBackupOffStatus;

  /// No description provided for @selectedDirectory.
  ///
  /// In en, this message translates to:
  /// **'Selected directory'**
  String get selectedDirectory;

  /// No description provided for @automaticBackupOnDirectory.
  ///
  /// In en, this message translates to:
  /// **'On. Directory: {location}'**
  String automaticBackupOnDirectory(String location);

  /// No description provided for @automaticBackupLast.
  ///
  /// In en, this message translates to:
  /// **'On. Last backup: {time}.\nDirectory: {location}'**
  String automaticBackupLast(String time, String location);

  /// No description provided for @backupCancelled.
  ///
  /// In en, this message translates to:
  /// **'Backup cancelled.'**
  String get backupCancelled;

  /// No description provided for @backupSaved.
  ///
  /// In en, this message translates to:
  /// **'Backup saved.'**
  String get backupSaved;

  /// No description provided for @notApplicationBackup.
  ///
  /// In en, this message translates to:
  /// **'That file is not a backup from this app.'**
  String get notApplicationBackup;

  /// No description provided for @emailRequired.
  ///
  /// In en, this message translates to:
  /// **'An email address is required.'**
  String get emailRequired;

  /// No description provided for @emailInvalid.
  ///
  /// In en, this message translates to:
  /// **'Enter a valid email address.'**
  String get emailInvalid;

  /// No description provided for @passwordMinimumTen.
  ///
  /// In en, this message translates to:
  /// **'Use at least 10 characters.'**
  String get passwordMinimumTen;

  /// No description provided for @passwordsDoNotMatch.
  ///
  /// In en, this message translates to:
  /// **'The two password entries do not match.'**
  String get passwordsDoNotMatch;

  /// No description provided for @createAccountKeepsCodes.
  ///
  /// In en, this message translates to:
  /// **'Your existing codes stay unchanged. Creating an account adds encrypted synchronization and account recovery.'**
  String get createAccountKeepsCodes;

  /// No description provided for @accountNameRequired.
  ///
  /// In en, this message translates to:
  /// **'An account name is required.'**
  String get accountNameRequired;

  /// No description provided for @noteTooLong.
  ///
  /// In en, this message translates to:
  /// **'The note can have at most 512 characters.'**
  String get noteTooLong;

  /// No description provided for @tooManyTags.
  ///
  /// In en, this message translates to:
  /// **'An entry can have at most 20 tags.'**
  String get tooManyTags;

  /// No description provided for @tagTooLong.
  ///
  /// In en, this message translates to:
  /// **'A tag can have at most 32 characters.'**
  String get tagTooLong;

  /// No description provided for @renameSyncDescription.
  ///
  /// In en, this message translates to:
  /// **'Renaming an entry changes it on every device on this account. It does not change the codes.'**
  String get renameSyncDescription;

  /// No description provided for @imageCouldNotOpen.
  ///
  /// In en, this message translates to:
  /// **'That image could not be opened.'**
  String get imageCouldNotOpen;

  /// No description provided for @counterInvalid.
  ///
  /// In en, this message translates to:
  /// **'The starting counter must be a whole number that is zero or greater.'**
  String get counterInvalid;

  /// No description provided for @enterAccountForCode.
  ///
  /// In en, this message translates to:
  /// **'Enter the account that owns this code.'**
  String get enterAccountForCode;

  /// No description provided for @setupKeyHelper.
  ///
  /// In en, this message translates to:
  /// **'Enter the key shown next to the service QR code. Spaces and letter case do not matter.'**
  String get setupKeyHelper;

  /// No description provided for @enterSetupKeyError.
  ///
  /// In en, this message translates to:
  /// **'Enter the setup key.'**
  String get enterSetupKeyError;

  /// No description provided for @timeBasedDescription.
  ///
  /// In en, this message translates to:
  /// **'The code changes on a timer. Almost every service uses this type.'**
  String get timeBasedDescription;

  /// No description provided for @counterBasedDescription.
  ///
  /// In en, this message translates to:
  /// **'The code changes when you request the next code.'**
  String get counterBasedDescription;

  /// No description provided for @counterHelper.
  ///
  /// In en, this message translates to:
  /// **'Usually 0. This value must match the value held by the service.'**
  String get counterHelper;

  /// No description provided for @enterWholeCounter.
  ///
  /// In en, this message translates to:
  /// **'Enter the counter as a whole number.'**
  String get enterWholeCounter;

  /// No description provided for @qrSecretWarning.
  ///
  /// In en, this message translates to:
  /// **'This QR code is the account secret. A person who photographs it can sign in as you. Reset two-factor authentication to revoke it.'**
  String get qrSecretWarning;

  /// No description provided for @hideSetupKey.
  ///
  /// In en, this message translates to:
  /// **'Hide the setup key'**
  String get hideSetupKey;

  /// No description provided for @showSetupKey.
  ///
  /// In en, this message translates to:
  /// **'Show the setup key instead'**
  String get showSetupKey;

  /// No description provided for @checkScreenPrivacy.
  ///
  /// In en, this message translates to:
  /// **'Check who can see your screen'**
  String get checkScreenPrivacy;

  /// No description provided for @useAtLeastSixDigits.
  ///
  /// In en, this message translates to:
  /// **'Use at least 6 digits.'**
  String get useAtLeastSixDigits;

  /// No description provided for @useAtLeastSixCharacters.
  ///
  /// In en, this message translates to:
  /// **'Use at least 6 characters.'**
  String get useAtLeastSixCharacters;

  /// No description provided for @avoidRepeatedPin.
  ///
  /// In en, this message translates to:
  /// **'Do not use one repeated digit.'**
  String get avoidRepeatedPin;

  /// No description provided for @avoidSequentialPin.
  ///
  /// In en, this message translates to:
  /// **'Do not use a sequence such as 123456.'**
  String get avoidSequentialPin;

  /// No description provided for @deviceKeyProtectionFailed.
  ///
  /// In en, this message translates to:
  /// **'The device key could not be protected.'**
  String get deviceKeyProtectionFailed;

  /// No description provided for @wrongExportPart.
  ///
  /// In en, this message translates to:
  /// **'That code belongs to a different export. Scan the remaining codes from the first export.'**
  String get wrongExportPart;

  /// No description provided for @migrationCodeAlreadyScanned.
  ///
  /// In en, this message translates to:
  /// **'That code was already scanned.'**
  String get migrationCodeAlreadyScanned;

  /// No description provided for @partialExportScanned.
  ///
  /// In en, this message translates to:
  /// **'You scanned part of this export. Scan {count} more before you leave.'**
  String partialExportScanned(int count);

  /// No description provided for @allCodesScanned.
  ///
  /// In en, this message translates to:
  /// **'All codes scanned.'**
  String get allCodesScanned;

  /// No description provided for @scanNextMigrationCode.
  ///
  /// In en, this message translates to:
  /// **'Scan the next code. {count} remain.'**
  String scanNextMigrationCode(int count);

  /// No description provided for @notSharedAccountQr.
  ///
  /// In en, this message translates to:
  /// **'That QR code is not a shared-account link.'**
  String get notSharedAccountQr;

  /// No description provided for @notOtpSetupQr.
  ///
  /// In en, this message translates to:
  /// **'That QR code is not a two-factor setup code.'**
  String get notOtpSetupQr;

  /// No description provided for @selectedImageUnavailable.
  ///
  /// In en, this message translates to:
  /// **'This device did not provide the selected image.'**
  String get selectedImageUnavailable;

  /// No description provided for @noSharedQrInImage.
  ///
  /// In en, this message translates to:
  /// **'No shared-account QR code was found in that image.'**
  String get noSharedQrInImage;

  /// No description provided for @noOtpQrInImage.
  ///
  /// In en, this message translates to:
  /// **'No two-factor QR code was found in that image.'**
  String get noOtpQrInImage;

  /// No description provided for @imageScanFailed.
  ///
  /// In en, this message translates to:
  /// **'The selected image could not be scanned.'**
  String get imageScanFailed;

  /// No description provided for @cameraPermissionRequired.
  ///
  /// In en, this message translates to:
  /// **'This application does not have permission to use the camera.'**
  String get cameraPermissionRequired;

  /// No description provided for @cameraStartFailed.
  ///
  /// In en, this message translates to:
  /// **'The camera could not be started.'**
  String get cameraStartFailed;

  /// No description provided for @enterSyncServer.
  ///
  /// In en, this message translates to:
  /// **'Enter the address of your sync server.'**
  String get enterSyncServer;

  /// No description provided for @syncServerRequiresHttps.
  ///
  /// In en, this message translates to:
  /// **'The address must start with https://.'**
  String get syncServerRequiresHttps;

  /// No description provided for @enterAccountEmail.
  ///
  /// In en, this message translates to:
  /// **'Enter the email address of your account.'**
  String get enterAccountEmail;

  /// No description provided for @enterNewAccountPassword.
  ///
  /// In en, this message translates to:
  /// **'Enter the password you set for this account.'**
  String get enterNewAccountPassword;

  /// No description provided for @enterPin.
  ///
  /// In en, this message translates to:
  /// **'Enter your PIN.'**
  String get enterPin;

  /// No description provided for @biometricUnlockFailed.
  ///
  /// In en, this message translates to:
  /// **'Biometric unlock failed. Enter your PIN instead.'**
  String get biometricUnlockFailed;

  /// No description provided for @show.
  ///
  /// In en, this message translates to:
  /// **'Show'**
  String get show;

  /// No description provided for @hide.
  ///
  /// In en, this message translates to:
  /// **'Hide'**
  String get hide;

  /// No description provided for @failedAttemptLimitReached.
  ///
  /// In en, this message translates to:
  /// **'The failed attempt limit has been reached.'**
  String get failedAttemptLimitReached;

  /// No description provided for @useRecoveryPhraseTitle.
  ///
  /// In en, this message translates to:
  /// **'Use recovery phrase'**
  String get useRecoveryPhraseTitle;

  /// No description provided for @useAccountPasswordTitle.
  ///
  /// In en, this message translates to:
  /// **'Use account password'**
  String get useAccountPasswordTitle;

  /// No description provided for @recoveryPhraseEntryHelp.
  ///
  /// In en, this message translates to:
  /// **'Enter the 24 words you saved when you created the account.'**
  String get recoveryPhraseEntryHelp;

  /// No description provided for @accountPasswordEntryHelp.
  ///
  /// In en, this message translates to:
  /// **'Enter the password for the sync account on this device.'**
  String get accountPasswordEntryHelp;

  /// No description provided for @recoveryPhraseField.
  ///
  /// In en, this message translates to:
  /// **'24-word recovery phrase'**
  String get recoveryPhraseField;

  /// No description provided for @incorrectRecoveryWord.
  ///
  /// In en, this message translates to:
  /// **'That is not the word at position {position}.'**
  String incorrectRecoveryWord(int position);

  /// No description provided for @writeRecoveryFirst.
  ///
  /// In en, this message translates to:
  /// **'Write these words down first. They are the only way to recover your codes.'**
  String get writeRecoveryFirst;

  /// No description provided for @confirmRecoveryKey.
  ///
  /// In en, this message translates to:
  /// **'Confirm your recovery key'**
  String get confirmRecoveryKey;

  /// No description provided for @yourRecoveryKey.
  ///
  /// In en, this message translates to:
  /// **'Your recovery key'**
  String get yourRecoveryKey;

  /// No description provided for @recoveryKeyWarning.
  ///
  /// In en, this message translates to:
  /// **'These 24 words are shown once. They are the only way to recover your codes if you lose your password and devices. We cannot show them again.'**
  String get recoveryKeyWarning;

  /// No description provided for @paperSaferThanClipboard.
  ///
  /// In en, this message translates to:
  /// **'Paper is safer than the clipboard. Other applications can read clipboard data.'**
  String get paperSaferThanClipboard;

  /// No description provided for @failedAttemptsRemaining.
  ///
  /// In en, this message translates to:
  /// **'{attempts} failed {attempts, plural, =1{attempt} other{attempts}}. {remaining} remain before this device is wiped, if wipe protection is on.'**
  String failedAttemptsRemaining(int attempts, int remaining);

  /// No description provided for @migrationFoundReport.
  ///
  /// In en, this message translates to:
  /// **'{ready} {ready, plural, =1{account} other{accounts}} found. {refused} could not be read.'**
  String migrationFoundReport(int ready, int refused);

  /// No description provided for @directImports.
  ///
  /// In en, this message translates to:
  /// **'Direct imports'**
  String get directImports;

  /// No description provided for @googleImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Open Google Authenticator.\nOpen the menu. Select Transfer accounts, then Export accounts.\nSelect the accounts. Then select Next.\nScan each QR code shown. A large export has more than one QR code.'**
  String get googleImportSteps;

  /// No description provided for @scanExportCode.
  ///
  /// In en, this message translates to:
  /// **'Scan an export code'**
  String get scanExportCode;

  /// No description provided for @aegisImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Open Aegis.\nSelect Settings, Import & Export, then Export.\nSave the file in a location that you can open from this app.\nSelect the file below. Enter the export password when asked.'**
  String get aegisImportSteps;

  /// No description provided for @chooseFile.
  ///
  /// In en, this message translates to:
  /// **'Choose a file'**
  String get chooseFile;

  /// No description provided for @twoFasImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Open 2FAS.\nSelect Settings, Backup, then Export to file.\nSave the .2fas file in a location that you can open from this app.\nSelect the file below. Password-protected backups are supported.'**
  String get twoFasImportSteps;

  /// No description provided for @enteImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Open Ente Auth and export your codes.\nUse a password-protected export when available.\nSelect the file below. Enter the export password when asked.\nPlain-text exports are also supported.'**
  String get enteImportSteps;

  /// No description provided for @protonImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Open Proton Authenticator and export your codes.\nSet an export password.\nSelect the JSON file below. Enter the export password when asked.\nPlain JSON exports are also supported.'**
  String get protonImportSteps;

  /// No description provided for @bitwardenImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Export the vault as unencrypted JSON.\nSelect the JSON file below. Only items with a TOTP value are imported.\nDelete the unencrypted export after you verify the import.'**
  String get bitwardenImportSteps;

  /// No description provided for @standardNotesImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Export the Authenticator note as JSON.\nSelect the JSON file below. Notes are kept with each entry.'**
  String get standardNotesImportSteps;

  /// No description provided for @appsWithoutExport.
  ///
  /// In en, this message translates to:
  /// **'Apps that do not provide an export'**
  String get appsWithoutExport;

  /// No description provided for @appsWithoutExportDescription.
  ///
  /// In en, this message translates to:
  /// **'Microsoft Authenticator and Authy do not provide a supported export. Set up each account again at its service.'**
  String get appsWithoutExportDescription;

  /// No description provided for @microsoftImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Microsoft Authenticator does not provide an export.\nFor each account, sign in to the service and open its security settings.\nRemove the old authenticator. Set it up again and scan the new QR code with this app.\nMove important accounts first. Keep the old app until all accounts are moved.'**
  String get microsoftImportSteps;

  /// No description provided for @authyImportSteps.
  ///
  /// In en, this message translates to:
  /// **'Authy does not provide an export.\nIf an old Authy desktop application still works, Aegis can import from it. Then export from Aegis.\nOtherwise, set up each account again at its service.'**
  String get authyImportSteps;

  /// No description provided for @otherAuthenticators.
  ///
  /// In en, this message translates to:
  /// **'Other authenticators'**
  String get otherAuthenticators;

  /// No description provided for @otherAuthenticatorHelp.
  ///
  /// In en, this message translates to:
  /// **'Most authenticator apps export a QR code or a file. This app supports both. If the format is not recognized, import it into Aegis and export it from Aegis.'**
  String get otherAuthenticatorHelp;

  /// No description provided for @imageFileEmpty.
  ///
  /// In en, this message translates to:
  /// **'The image file is empty.'**
  String get imageFileEmpty;

  /// No description provided for @imageTooLarge.
  ///
  /// In en, this message translates to:
  /// **'Choose an image smaller than 5 MB.'**
  String get imageTooLarge;

  /// No description provided for @imageCannotFitEntry.
  ///
  /// In en, this message translates to:
  /// **'This image cannot fit in the encrypted entry. Choose a simpler image.'**
  String get imageCannotFitEntry;

  /// No description provided for @automaticBackupPassphraseMissing.
  ///
  /// In en, this message translates to:
  /// **'Automatic backup has no passphrase. Set it up again.'**
  String get automaticBackupPassphraseMissing;

  /// No description provided for @approveNewDevice.
  ///
  /// In en, this message translates to:
  /// **'Approve a new device'**
  String get approveNewDevice;

  /// No description provided for @approveNewDeviceDescription.
  ///
  /// In en, this message translates to:
  /// **'Create a single-use code that expires in 10 minutes. A new code replaces the old code.'**
  String get approveNewDeviceDescription;

  /// No description provided for @deviceApprovalCode.
  ///
  /// In en, this message translates to:
  /// **'Device approval code'**
  String get deviceApprovalCode;

  /// No description provided for @deviceApprovalCodeHelp.
  ///
  /// In en, this message translates to:
  /// **'Enter this code on the new device. The code works once.'**
  String get deviceApprovalCodeHelp;

  /// No description provided for @approvalCodeExpires.
  ///
  /// In en, this message translates to:
  /// **'Expires at {time}'**
  String approvalCodeExpires(String time);

  /// No description provided for @copy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get copy;

  /// No description provided for @copied.
  ///
  /// In en, this message translates to:
  /// **'Copied'**
  String get copied;

  /// No description provided for @continueLabel.
  ///
  /// In en, this message translates to:
  /// **'Continue'**
  String get continueLabel;

  /// No description provided for @passwordRequiredForSecurityAction.
  ///
  /// In en, this message translates to:
  /// **'Enter the account password to permit this security action.'**
  String get passwordRequiredForSecurityAction;

  /// No description provided for @passwordRequiredForProtectedAction.
  ///
  /// In en, this message translates to:
  /// **'Enter the account password. Authorization remains active for five minutes.'**
  String get passwordRequiredForProtectedAction;

  /// No description provided for @deviceApprovalCodeOptional.
  ///
  /// In en, this message translates to:
  /// **'Device approval code (optional)'**
  String get deviceApprovalCodeOptional;

  /// No description provided for @deviceApprovalSignInHelp.
  ///
  /// In en, this message translates to:
  /// **'An existing device creates this code. The first device does not need one.'**
  String get deviceApprovalSignInHelp;

  /// No description provided for @securityActivity.
  ///
  /// In en, this message translates to:
  /// **'Security activity'**
  String get securityActivity;

  /// No description provided for @securityActivityDescription.
  ///
  /// In en, this message translates to:
  /// **'Review device and session changes on this account.'**
  String get securityActivityDescription;

  /// No description provided for @noSecurityActivity.
  ///
  /// In en, this message translates to:
  /// **'No security activity is available.'**
  String get noSecurityActivity;

  /// No description provided for @securityDeviceAdded.
  ///
  /// In en, this message translates to:
  /// **'Device added'**
  String get securityDeviceAdded;

  /// No description provided for @securityDeviceRemoved.
  ///
  /// In en, this message translates to:
  /// **'Device removed'**
  String get securityDeviceRemoved;

  /// No description provided for @securityApprovalCreated.
  ///
  /// In en, this message translates to:
  /// **'Device approval created'**
  String get securityApprovalCreated;

  /// No description provided for @securityDeviceSignedOut.
  ///
  /// In en, this message translates to:
  /// **'Device signed out'**
  String get securityDeviceSignedOut;

  /// No description provided for @securityAllDevicesSignedOut.
  ///
  /// In en, this message translates to:
  /// **'All devices signed out'**
  String get securityAllDevicesSignedOut;

  /// No description provided for @securityTokenReuseDetected.
  ///
  /// In en, this message translates to:
  /// **'Session token reuse detected'**
  String get securityTokenReuseDetected;

  /// No description provided for @rootDetectedTitle.
  ///
  /// In en, this message translates to:
  /// **'Root access detected'**
  String get rootDetectedTitle;

  /// No description provided for @rootWarningDescription.
  ///
  /// In en, this message translates to:
  /// **'A rooted device can let other software read authenticator data. Continue only if you control this device.'**
  String get rootWarningDescription;

  /// No description provided for @rootBlockedDescription.
  ///
  /// In en, this message translates to:
  /// **'The current policy blocks vault access on a rooted device.'**
  String get rootBlockedDescription;

  /// No description provided for @rootDetectionLimit.
  ///
  /// In en, this message translates to:
  /// **'Root detection uses device indicators. It can report a modified system incorrectly, and advanced root tools can bypass it.'**
  String get rootDetectionLimit;

  /// No description provided for @rootCheckNotEvaluated.
  ///
  /// In en, this message translates to:
  /// **'The device modification check was not evaluated. This does not mean the device is safe.'**
  String get rootCheckNotEvaluated;

  /// No description provided for @changeRootPolicyToWarn.
  ///
  /// In en, this message translates to:
  /// **'Change policy to Warn'**
  String get changeRootPolicyToWarn;

  /// No description provided for @ignoreRootWarning.
  ///
  /// In en, this message translates to:
  /// **'Ignore this warning'**
  String get ignoreRootWarning;

  /// No description provided for @rootPolicy.
  ///
  /// In en, this message translates to:
  /// **'Rooted-device policy'**
  String get rootPolicy;

  /// No description provided for @rootPolicyIgnoreDescription.
  ///
  /// In en, this message translates to:
  /// **'Do not warn or block.'**
  String get rootPolicyIgnoreDescription;

  /// No description provided for @rootPolicyWarnDescription.
  ///
  /// In en, this message translates to:
  /// **'Show a warning before the vault opens.'**
  String get rootPolicyWarnDescription;

  /// No description provided for @rootPolicyBlockDescription.
  ///
  /// In en, this message translates to:
  /// **'Block the vault until the policy changes.'**
  String get rootPolicyBlockDescription;

  /// No description provided for @ignore.
  ///
  /// In en, this message translates to:
  /// **'Ignore'**
  String get ignore;

  /// No description provided for @warn.
  ///
  /// In en, this message translates to:
  /// **'Warn'**
  String get warn;

  /// No description provided for @block.
  ///
  /// In en, this message translates to:
  /// **'Block'**
  String get block;

  /// No description provided for @recoveryPhraseRequired.
  ///
  /// In en, this message translates to:
  /// **'Recovery phrase'**
  String get recoveryPhraseRequired;

  /// No description provided for @recoveryPhraseOptional.
  ///
  /// In en, this message translates to:
  /// **'Recovery phrase (optional)'**
  String get recoveryPhraseOptional;

  /// No description provided for @recoveryPhraseSyncRegistrationHelp.
  ///
  /// In en, this message translates to:
  /// **'Enter the 24 words to enable account recovery when no approved device is available.'**
  String get recoveryPhraseSyncRegistrationHelp;

  /// No description provided for @recoveryPhraseSignInHelp.
  ///
  /// In en, this message translates to:
  /// **'Use this only when no existing device can create an approval code.'**
  String get recoveryPhraseSignInHelp;

  /// No description provided for @enterRecoveryPhraseForSync.
  ///
  /// In en, this message translates to:
  /// **'Enter the 24-word recovery phrase for this account.'**
  String get enterRecoveryPhraseForSync;

  /// No description provided for @enableRecoverySignIn.
  ///
  /// In en, this message translates to:
  /// **'Enable recovery sign-in'**
  String get enableRecoverySignIn;

  /// No description provided for @enableRecoverySignInDescription.
  ///
  /// In en, this message translates to:
  /// **'Permit the recovery phrase when no approved device is available.'**
  String get enableRecoverySignInDescription;

  /// No description provided for @enableRecoverySignInHelp.
  ///
  /// In en, this message translates to:
  /// **'This updates accounts created by an older app. The app verifies the phrase locally. The phrase does not reach the server.'**
  String get enableRecoverySignInHelp;

  /// No description provided for @recoveryAccessEnabled.
  ///
  /// In en, this message translates to:
  /// **'Recovery sign-in is enabled.'**
  String get recoveryAccessEnabled;

  /// No description provided for @enable.
  ///
  /// In en, this message translates to:
  /// **'Enable'**
  String get enable;

  /// No description provided for @securityRecoveryEnabled.
  ///
  /// In en, this message translates to:
  /// **'Recovery sign-in enabled'**
  String get securityRecoveryEnabled;

  /// No description provided for @rootIndicatorTestKeys.
  ///
  /// In en, this message translates to:
  /// **'The system image uses test signing keys.'**
  String get rootIndicatorTestKeys;

  /// No description provided for @rootIndicatorRootFiles.
  ///
  /// In en, this message translates to:
  /// **'A root-management file is present.'**
  String get rootIndicatorRootFiles;

  /// No description provided for @rootIndicatorUnknown.
  ///
  /// In en, this message translates to:
  /// **'The device reported a root indicator.'**
  String get rootIndicatorUnknown;

  /// No description provided for @securityAccountRegistered.
  ///
  /// In en, this message translates to:
  /// **'Sync account created'**
  String get securityAccountRegistered;

  /// No description provided for @changeAccountPassword.
  ///
  /// In en, this message translates to:
  /// **'Change account password'**
  String get changeAccountPassword;

  /// No description provided for @changeAccountPasswordDescription.
  ///
  /// In en, this message translates to:
  /// **'Replace the sync password and sign out other devices.'**
  String get changeAccountPasswordDescription;

  /// No description provided for @currentPassword.
  ///
  /// In en, this message translates to:
  /// **'Current password'**
  String get currentPassword;

  /// No description provided for @newPassword.
  ///
  /// In en, this message translates to:
  /// **'New password'**
  String get newPassword;

  /// No description provided for @enterNewPasswordAgain.
  ///
  /// In en, this message translates to:
  /// **'Enter the new password again'**
  String get enterNewPasswordAgain;

  /// No description provided for @passwordChangeRevokesDevices.
  ///
  /// In en, this message translates to:
  /// **'This action signs out all other devices. Add each trusted device again with an approval code or the recovery phrase.'**
  String get passwordChangeRevokesDevices;

  /// No description provided for @passwordChanged.
  ///
  /// In en, this message translates to:
  /// **'The account password was changed.'**
  String get passwordChanged;

  /// No description provided for @passwordChangeFailed.
  ///
  /// In en, this message translates to:
  /// **'The password could not be changed: {error}'**
  String passwordChangeFailed(String error);

  /// No description provided for @renameDevice.
  ///
  /// In en, this message translates to:
  /// **'Rename device'**
  String get renameDevice;

  /// No description provided for @deviceName.
  ///
  /// In en, this message translates to:
  /// **'Device name'**
  String get deviceName;

  /// No description provided for @deviceRenamed.
  ///
  /// In en, this message translates to:
  /// **'The device was renamed.'**
  String get deviceRenamed;

  /// No description provided for @forgotPassword.
  ///
  /// In en, this message translates to:
  /// **'Forgot password?'**
  String get forgotPassword;

  /// No description provided for @resetAccountPassword.
  ///
  /// In en, this message translates to:
  /// **'Reset account password'**
  String get resetAccountPassword;

  /// No description provided for @resetPasswordDescription.
  ///
  /// In en, this message translates to:
  /// **'Use the 24-word recovery phrase to set a new password. This action signs out all other devices.'**
  String get resetPasswordDescription;

  /// No description provided for @passwordResetComplete.
  ///
  /// In en, this message translates to:
  /// **'The account password was reset.'**
  String get passwordResetComplete;

  /// No description provided for @verifyEmailOwnership.
  ///
  /// In en, this message translates to:
  /// **'Verify email ownership'**
  String get verifyEmailOwnership;

  /// No description provided for @verifyWithEmail.
  ///
  /// In en, this message translates to:
  /// **'Verify with email'**
  String get verifyWithEmail;

  /// No description provided for @continueWithGoogle.
  ///
  /// In en, this message translates to:
  /// **'Continue with Google'**
  String get continueWithGoogle;

  /// No description provided for @identityPassword.
  ///
  /// In en, this message translates to:
  /// **'Email sign-in password'**
  String get identityPassword;

  /// No description provided for @identityPasswordHelp.
  ///
  /// In en, this message translates to:
  /// **'Use a password that is different from the vault password. Firebase receives this password. Firebase never receives the vault password.'**
  String get identityPasswordHelp;

  /// No description provided for @identityPasswordMustDiffer.
  ///
  /// In en, this message translates to:
  /// **'Use a different password for email sign-in and vault encryption.'**
  String get identityPasswordMustDiffer;

  /// No description provided for @identityPasswordTooShort.
  ///
  /// In en, this message translates to:
  /// **'Enter at least 6 characters for the email sign-in password.'**
  String get identityPasswordTooShort;

  /// No description provided for @emailVerificationSent.
  ///
  /// In en, this message translates to:
  /// **'A verification email was sent. Open the link, then select I verified my email.'**
  String get emailVerificationSent;

  /// No description provided for @iVerifiedMyEmail.
  ///
  /// In en, this message translates to:
  /// **'I verified my email'**
  String get iVerifiedMyEmail;

  /// No description provided for @emailOwnershipVerified.
  ///
  /// In en, this message translates to:
  /// **'Email ownership verified for {email}.'**
  String emailOwnershipVerified(String email);

  /// No description provided for @verifyEmailBeforeSync.
  ///
  /// In en, this message translates to:
  /// **'Verify the account email before you turn on sync.'**
  String get verifyEmailBeforeSync;

  /// No description provided for @firebaseNotConfigured.
  ///
  /// In en, this message translates to:
  /// **'Firebase Authentication is not configured in this Android build.'**
  String get firebaseNotConfigured;

  /// No description provided for @verificationStillPending.
  ///
  /// In en, this message translates to:
  /// **'The email address is not verified yet.'**
  String get verificationStillPending;

  /// No description provided for @identityEmailMismatch.
  ///
  /// In en, this message translates to:
  /// **'The verified email does not match this vault account.'**
  String get identityEmailMismatch;

  /// No description provided for @errorInvalidCredentials.
  ///
  /// In en, this message translates to:
  /// **'The email address or password is not correct.'**
  String get errorInvalidCredentials;

  /// No description provided for @errorAccountConflict.
  ///
  /// In en, this message translates to:
  /// **'An account already exists for this email address.'**
  String get errorAccountConflict;

  /// No description provided for @errorServerUnavailable.
  ///
  /// In en, this message translates to:
  /// **'The sync server cannot be reached. Check the connection and server address.'**
  String get errorServerUnavailable;

  /// No description provided for @errorInvalidServerResponse.
  ///
  /// In en, this message translates to:
  /// **'The sync server sent an invalid response.'**
  String get errorInvalidServerResponse;

  /// No description provided for @errorSignedOut.
  ///
  /// In en, this message translates to:
  /// **'This device was signed out. Sign in again to continue synchronization.'**
  String get errorSignedOut;

  /// No description provided for @errorDeviceApprovalRequired.
  ///
  /// In en, this message translates to:
  /// **'Approve this device from an existing device, or use the recovery phrase.'**
  String get errorDeviceApprovalRequired;

  /// No description provided for @errorInsufficientScope.
  ///
  /// In en, this message translates to:
  /// **'This session does not permit that action. Sign in again.'**
  String get errorInsufficientScope;

  /// No description provided for @errorElevationRequired.
  ///
  /// In en, this message translates to:
  /// **'Enter the account password to authorize this action.'**
  String get errorElevationRequired;

  /// No description provided for @errorInvalidScope.
  ///
  /// In en, this message translates to:
  /// **'This permission is not available.'**
  String get errorInvalidScope;

  /// No description provided for @errorCapabilityExpired.
  ///
  /// In en, this message translates to:
  /// **'The temporary authorization expired. Enter the password again.'**
  String get errorCapabilityExpired;

  /// No description provided for @errorNotFound.
  ///
  /// In en, this message translates to:
  /// **'The requested item was not found.'**
  String get errorNotFound;

  /// No description provided for @errorEmailVerificationRequired.
  ///
  /// In en, this message translates to:
  /// **'Verify the email address before account registration.'**
  String get errorEmailVerificationRequired;

  /// No description provided for @errorInvalidIdentity.
  ///
  /// In en, this message translates to:
  /// **'The email identity proof is invalid or expired. Verify the email again.'**
  String get errorInvalidIdentity;

  /// No description provided for @errorRateLimited.
  ///
  /// In en, this message translates to:
  /// **'Too many requests were made. Wait and try again.'**
  String get errorRateLimited;

  /// No description provided for @errorQuotaExceeded.
  ///
  /// In en, this message translates to:
  /// **'This account reached a server limit.'**
  String get errorQuotaExceeded;

  /// No description provided for @errorRequestTooLarge.
  ///
  /// In en, this message translates to:
  /// **'The request is too large.'**
  String get errorRequestTooLarge;

  /// No description provided for @errorFeatureUnavailable.
  ///
  /// In en, this message translates to:
  /// **'This feature is not configured on the server.'**
  String get errorFeatureUnavailable;

  /// No description provided for @errorServerInternal.
  ///
  /// In en, this message translates to:
  /// **'The server could not complete the request.'**
  String get errorServerInternal;

  /// No description provided for @errorIdentityCredentials.
  ///
  /// In en, this message translates to:
  /// **'The email sign-in password is not correct.'**
  String get errorIdentityCredentials;

  /// No description provided for @errorIdentityEmail.
  ///
  /// In en, this message translates to:
  /// **'Enter a valid email address.'**
  String get errorIdentityEmail;

  /// No description provided for @errorIdentityWeakPassword.
  ///
  /// In en, this message translates to:
  /// **'Use a stronger email sign-in password.'**
  String get errorIdentityWeakPassword;

  /// No description provided for @errorIdentityNetwork.
  ///
  /// In en, this message translates to:
  /// **'Firebase Authentication cannot be reached. Check the connection.'**
  String get errorIdentityNetwork;

  /// No description provided for @errorIdentityDisabled.
  ///
  /// In en, this message translates to:
  /// **'This email identity is disabled.'**
  String get errorIdentityDisabled;

  /// No description provided for @errorIdentityCanceled.
  ///
  /// In en, this message translates to:
  /// **'Google sign-in was canceled.'**
  String get errorIdentityCanceled;

  /// No description provided for @linkVerifiedIdentity.
  ///
  /// In en, this message translates to:
  /// **'Link verified identity'**
  String get linkVerifiedIdentity;

  /// No description provided for @linkVerifiedIdentityRequired.
  ///
  /// In en, this message translates to:
  /// **'Verify email ownership for this existing account.'**
  String get linkVerifiedIdentityRequired;

  /// No description provided for @linkVerifiedIdentityDescription.
  ///
  /// In en, this message translates to:
  /// **'Verify ownership of {email}. Enter the current vault password to authorize the link.'**
  String linkVerifiedIdentityDescription(String email);

  /// No description provided for @verifiedIdentity.
  ///
  /// In en, this message translates to:
  /// **'Verified identity'**
  String get verifiedIdentity;

  /// No description provided for @securityIdentityLinked.
  ///
  /// In en, this message translates to:
  /// **'Verified identity linked'**
  String get securityIdentityLinked;

  /// No description provided for @addPasskey.
  ///
  /// In en, this message translates to:
  /// **'Add passkey'**
  String get addPasskey;

  /// No description provided for @addPasskeyDescription.
  ///
  /// In en, this message translates to:
  /// **'Use Android Credential Manager to create a passkey for this account.'**
  String get addPasskeyDescription;

  /// No description provided for @passkeyPrfUnavailable.
  ///
  /// In en, this message translates to:
  /// **'This credential provider did not return the key material required to protect the vault. Keep password and recovery access enabled.'**
  String get passkeyPrfUnavailable;

  /// No description provided for @passkeyAdded.
  ///
  /// In en, this message translates to:
  /// **'The passkey was added.'**
  String get passkeyAdded;

  /// No description provided for @passkeyAddFailed.
  ///
  /// In en, this message translates to:
  /// **'The passkey could not be added: {error}'**
  String passkeyAddFailed(String error);

  /// No description provided for @errorUnknown.
  ///
  /// In en, this message translates to:
  /// **'The operation could not be completed.'**
  String get errorUnknown;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'hi'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'hi':
      return AppLocalizationsHi();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
