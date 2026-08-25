// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Hindi (`hi`).
class AppLocalizationsHi extends AppLocalizations {
  AppLocalizationsHi([String locale = 'hi']) : super(locale);

  @override
  String get appTitle => 'प्रमाणक';

  @override
  String get openingAuthenticator => 'प्रमाणक खोला जा रहा है…';

  @override
  String get lockedTitle => 'लॉक है';

  @override
  String get lockedBody => 'अनलॉक करने तक आपके कोड एन्क्रिप्टेड रहते हैं।';

  @override
  String get unlock => 'अनलॉक करें';

  @override
  String get useBiometrics => 'बायोमेट्रिक का उपयोग करें';

  @override
  String get useAccountPassword => 'खाता पासवर्ड का उपयोग करें';

  @override
  String get useRecoveryPhrase => 'रिकवरी वाक्यांश का उपयोग करें';

  @override
  String get settings => 'सेटिंग्स';

  @override
  String get appearanceAndPrivacy => 'दिखावट और गोपनीयता';

  @override
  String get theme => 'थीम';

  @override
  String get accountListSpacing => 'खाता सूची का अंतर';

  @override
  String get hideCodesUntilTapped => 'टैप करने तक कोड छिपाएं';

  @override
  String get useDeviceColours => 'डिवाइस के रंगों का उपयोग करें';

  @override
  String get language => 'भाषा';

  @override
  String get useDeviceLanguage => 'डिवाइस की भाषा का उपयोग करें';

  @override
  String get english => 'अंग्रेज़ी';

  @override
  String get hindi => 'हिन्दी';

  @override
  String get applicationLock => 'ऐप लॉक';

  @override
  String get changePin => 'पिन बदलें';

  @override
  String get setPin => 'पिन सेट करें';

  @override
  String get pinRequiredDescription =>
      'कोड खोलने के लिए इस डिवाइस की कुंजी के साथ यह पिन भी आवश्यक है।';

  @override
  String get pinNotSetDescription =>
      'पिन के बिना, इस डिवाइस को अनलॉक करने वाला व्यक्ति आपके कोड पढ़ सकता है।';

  @override
  String get lockAfter => 'इसके बाद लॉक करें';

  @override
  String get lockWhenLeaving => 'ऐप छोड़ने पर लॉक करें';

  @override
  String get lockWhenLeavingDescription =>
      'ऐप स्क्रीन से हटते ही लॉक हो जाता है।';

  @override
  String get wipeAfterFailedAttempts => 'विफल प्रयासों के बाद मिटाएं';

  @override
  String get wipeAttemptsOff =>
      'बंद। गलत प्रयास गिने जाते हैं, लेकिन कुछ मिटाया नहीं जाता।';

  @override
  String wipeAttemptsOn(int count) {
    return 'चालू — लगातार $count गलत प्रयासों के बाद सब कुछ मिटा दिया जाएगा।';
  }

  @override
  String get lockNow => 'अभी लॉक करें';

  @override
  String get sync => 'सिंक';

  @override
  String get createAccount => 'खाता बनाएं';

  @override
  String get createAccountDescription =>
      'आपके कोड एन्क्रिप्टेड रूप में अन्य डिवाइस पर पहुंचते हैं।';

  @override
  String get account => 'खाता';

  @override
  String get recoveryPhrase => 'रिकवरी वाक्यांश';

  @override
  String get recoveryConfirmed => 'इस डिवाइस पर पुष्टि हो गई है।';

  @override
  String get recoveryNotConfirmed => 'इस डिवाइस पर पूर्ण पुष्टि दर्ज नहीं है।';

  @override
  String get yourDevices => 'आपके डिवाइस';

  @override
  String get yourDevicesDescription =>
      'सिंक करने वाले डिवाइस देखें और खोए हुए डिवाइस हटाएं।';

  @override
  String get dataManagement => 'डेटा प्रबंधन';

  @override
  String get trash => 'ट्रैश';

  @override
  String get trashDescription =>
      'प्रविष्टियां 30 दिन तक वापस लाएं या स्थायी रूप से मिटाएं।';

  @override
  String get duplicateAccounts => 'डुप्लिकेट खाते';

  @override
  String get duplicateAccountsDescription =>
      'समान ओटीपी गुप्त कुंजी वाली प्रविष्टियां खोजें।';

  @override
  String get backup => 'बैकअप';

  @override
  String get backupAndRestore => 'बैकअप और रिस्टोर';

  @override
  String get backupAndRestoreDescription =>
      'कोड को फ़ाइल में सहेजें या फ़ाइल से वापस लाएं। खाते की आवश्यकता नहीं है।';

  @override
  String get usesApplicationColour =>
      'Android के इस संस्करण पर ऐप का रंग उपयोग होता है।';

  @override
  String get usesMaterialYouColour =>
      'आपका Android Material You रंग उपयोग होता है।';

  @override
  String get codesHiddenDescription =>
      'पंक्ति टैप करने तक प्रत्येक कोड छिपा रहता है।';

  @override
  String get codesVisibleDescription => 'खाता सूची में कोड दिखाई देते हैं।';

  @override
  String get thisDevice => 'यह डिवाइस';

  @override
  String get useBuiltInIcons => 'सेवा आइकन अपने आप दिखाएं';

  @override
  String get useBuiltInIconsDescription =>
      'Google की favicon सेवा से पूरे रंग वाला सेवा आइकन डाउनलोड करता है। जारीकर्ता का नाम इसी डिवाइस पर रखने के लिए इसे बंद करें।';

  @override
  String get serviceIconAttribution =>
      'सेवा मिलान डेटा: 2factorauth की 2FA Directory।';

  @override
  String get homeScreenWidget => 'होम-स्क्रीन विजेट';

  @override
  String get homeScreenWidgetDescription =>
      'एक खाते के लिए सुरक्षित शॉर्टकट जोड़ें।';

  @override
  String get blockScreenshots => 'स्क्रीनशॉट रोकें';

  @override
  String get screenshotsBlocked =>
      'स्क्रीनशॉट और स्क्रीन रिकॉर्डिंग रोकी गई हैं।';

  @override
  String get screenshotsAllowed =>
      'स्क्रीनशॉट और स्क्रीन रिकॉर्डिंग की अनुमति है।';

  @override
  String get wipeThisDevice => 'यह डिवाइस मिटाएं';

  @override
  String get wipeThisDeviceDescription =>
      'सभी कोड मिटाता है और कुंजी नष्ट करता है।';

  @override
  String get lockingExplanation =>
      'लॉक केवल कोड को स्क्रीन पर नहीं छिपाता। यह कुंजी को मेमोरी से हटाता है। अनलॉक होने तक संग्रहीत कोड पढ़े नहीं जा सकते।';

  @override
  String get useDeviceSetting => 'डिवाइस सेटिंग उपयोग करें';

  @override
  String get lightTheme => 'लाइट';

  @override
  String get darkTheme => 'डार्क';

  @override
  String get amoledTheme => 'AMOLED ब्लैक';

  @override
  String get comfortableDensity => 'आरामदायक';

  @override
  String get compactDensity => 'कॉम्पैक्ट';

  @override
  String get automaticBackup => 'स्वचालित बैकअप';

  @override
  String get automaticEncryptedBackups => 'स्वचालित एन्क्रिप्टेड बैकअप';

  @override
  String get readingBackupSettings => 'बैकअप सेटिंग पढ़ी जा रही है।';

  @override
  String get changeBackupDirectory => 'बैकअप फ़ोल्डर बदलें';

  @override
  String get backUpNow => 'अभी बैकअप लें';

  @override
  String get backUp => 'बैकअप लें';

  @override
  String get encryptedBackup => 'एन्क्रिप्टेड बैकअप';

  @override
  String get encryptedBackupDescription =>
      'सभी कोड एक ऐसी फ़ाइल में रखें जो केवल आपके पासफ़्रेज़ से खुलती है। इसे फोन खोने पर भी उपलब्ध स्थान पर रखें।';

  @override
  String get unprotectedExport => 'असुरक्षित निर्यात';

  @override
  String get unprotectedExportDescription =>
      'हर गुप्त कुंजी वाली पढ़ने योग्य फ़ाइल। इसका उपयोग दूसरे ऐप में जाने के लिए करें, संग्रह के लिए नहीं।';

  @override
  String get restore => 'रिस्टोर';

  @override
  String get testBackup => 'बैकअप जांचें';

  @override
  String get testBackupDescription =>
      'जांचता है कि बैकअप खुलता है और उसकी सामग्री बताता है। इस वॉल्ट में कुछ नहीं जोड़ा जाता।';

  @override
  String get restoreFromBackup => 'बैकअप से रिस्टोर करें';

  @override
  String get restoreFromBackupDescription =>
      'बैकअप फ़ाइल के खाते इस डिवाइस में जोड़ता है। मौजूदा खाते नहीं बदलते।';

  @override
  String get getNewRecoveryPhrase => 'नया रिकवरी वाक्यांश लें';

  @override
  String get getNewRecoveryPhraseDescription =>
      'पुराना वाक्यांश फिर नहीं दिखाया जा सकता। यह नया वाक्यांश बनाता है और पुराने को बंद करता है।';

  @override
  String get backupTestPassed => 'बैकअप जांच सफल हुई';

  @override
  String backupTestResult(int accounts, int folders, String encryption) {
    return 'फ़ाइल ने इस वॉल्ट को बदले बिना खोला।\n\nखाते: $accounts\nफ़ोल्डर: $folders\nएन्क्रिप्शन: $encryption';
  }

  @override
  String get encrypted => 'एन्क्रिप्टेड';

  @override
  String get notEncrypted => 'एन्क्रिप्टेड नहीं';

  @override
  String get done => 'हो गया';

  @override
  String get editEntry => 'प्रविष्टि संपादित करें';

  @override
  String get save => 'सहेजें';

  @override
  String get service => 'सेवा';

  @override
  String get optional => 'वैकल्पिक';

  @override
  String get note => 'नोट';

  @override
  String get tags => 'टैग';

  @override
  String get icon => 'आइकन';

  @override
  String get iconDescription => 'एक सेवा पर एक से अधिक खाते होने पर उपयोगी।';

  @override
  String get searchIcons => 'आइकन खोजें';

  @override
  String get searchIconsHint => 'काम, बैंक, मेल…';

  @override
  String get recent => 'हाल के';

  @override
  String get chooseCustomImage => 'कस्टम चित्र चुनें';

  @override
  String get noIconMatches => 'कोई आइकन इस खोज से मेल नहीं खाता।';

  @override
  String get useAutomaticLetter => 'स्वचालित सेवा आइकन उपयोग करें';

  @override
  String get codeCopied => 'कोड कॉपी हुआ। क्लिपबोर्ड 30 सेकंड में साफ होगा।';

  @override
  String get accountAdded => 'खाता जोड़ा गया।';

  @override
  String get clipboardHasNoText => 'क्लिपबोर्ड में टेक्स्ट नहीं है।';

  @override
  String get clipboardHasNoSetupLink => 'क्लिपबोर्ड में सेटअप लिंक नहीं है।';

  @override
  String moveEntriesToTrash(int count) {
    return '$count प्रविष्टियां ट्रैश में भेजें?';
  }

  @override
  String get moveEntriesToTrashDescription =>
      'प्रविष्टियां सभी डिवाइस पर ट्रैश में जाएंगी। आप इन्हें 30 दिन तक वापस ला सकते हैं।';

  @override
  String get cancel => 'रद्द करें';

  @override
  String get moveToTrash => 'ट्रैश में भेजें';

  @override
  String entriesMovedToTrash(int count) {
    return '$count प्रविष्टियां ट्रैश में भेजी गईं।';
  }

  @override
  String get add => 'जोड़ें';

  @override
  String get selectAccountForDetails => 'विवरण देखने के लिए खाता चुनें।';

  @override
  String get revealCode => 'कोड दिखाएं';

  @override
  String get copyCode => 'कोड कॉपी करें';

  @override
  String get rename => 'नाम बदलें';

  @override
  String get deleteFolder => 'फ़ोल्डर मिटाएं';

  @override
  String get folderAccountsKept => 'इसके खाते सुरक्षित रहेंगे';

  @override
  String get accountIsInTrash => 'यह खाता ट्रैश में है।';

  @override
  String alreadySavedAs(String label) {
    return 'पहले से $label नाम से सहेजा गया है।';
  }

  @override
  String get emptyVaultDescription =>
      'सेवा का QR कोड स्कैन करें या सेटअप कुंजी हाथ से दर्ज करें।';

  @override
  String get scan => 'स्कैन करें';

  @override
  String get enterKey => 'कुंजी दर्ज करें';

  @override
  String get importFile => 'फ़ाइल आयात करें';

  @override
  String sharedAccountImportFailed(String error) {
    return 'साझा खाता आयात नहीं हुआ: $error';
  }

  @override
  String get scanShareQr => 'साझा QR कोड स्कैन करें';

  @override
  String get pasteShareLink => 'साझा लिंक पेस्ट करें';

  @override
  String get nextCode => 'अगला कोड';

  @override
  String get copyNextCode => 'अगला कोड कॉपी करें';

  @override
  String deleteEntryQuestion(String label) {
    return '$label मिटाएं?';
  }

  @override
  String get deleteEntryDescription =>
      'यह प्रविष्टि सभी डिवाइस पर ट्रैश में जाएगी। आप इसे 30 दिन तक वापस ला सकते हैं।';

  @override
  String get keep => 'रखें';

  @override
  String get delete => 'मिटाएं';

  @override
  String get entryMovedToTrash => 'प्रविष्टि ट्रैश में भेजी गई।';

  @override
  String get scanQrCode => 'QR कोड स्कैन करें';

  @override
  String get enterSetupKey => 'सेटअप कुंजी दर्ज करें';

  @override
  String get pasteSetupLink => 'सेटअप लिंक पेस्ट करें';

  @override
  String get pasteSetupLinkDescription => 'क्लिपबोर्ड से otpauth लिंक पढ़ें';

  @override
  String get importSharedAccount => 'साझा खाता आयात करें';

  @override
  String get importSharedAccountDescription =>
      'साझा QR कोड स्कैन करें या लिंक पेस्ट करें';

  @override
  String get importFromFile => 'फ़ाइल से आयात करें';

  @override
  String get supportedImportFiles =>
      'Aegis, 2FAS, Ente, Proton, Bitwarden या Standard Notes';

  @override
  String get movingFromAnotherApp => 'किसी दूसरे ऐप से आ रहे हैं?';

  @override
  String get supportedMigrationApps => 'Google, Aegis, 2FAS, Authy, Microsoft';

  @override
  String get viewDetails => 'विवरण देखें';

  @override
  String get edit => 'संपादित करें';

  @override
  String get moveToFolder => 'फ़ोल्डर में भेजें';

  @override
  String get moveToAnotherApp => 'दूसरे ऐप में भेजें';

  @override
  String get shareEncryptedLink => 'एन्क्रिप्टेड लिंक साझा करें';

  @override
  String get previewNextCode => 'अगला कोड देखें';

  @override
  String get create => 'बनाएं';

  @override
  String get noFolder => 'कोई फ़ोल्डर नहीं';

  @override
  String get newFolder => 'नया फ़ोल्डर';

  @override
  String get renameFolder => 'फ़ोल्डर का नाम बदलें';

  @override
  String get entryRestored => 'प्रविष्टि वापस लाई गई।';

  @override
  String deletePermanentlyQuestion(String label) {
    return '$label स्थायी रूप से मिटाएं?';
  }

  @override
  String get deletePermanentlyDescription =>
      'यह क्रिया वापस नहीं हो सकती। सिंक के बाद प्रविष्टि सभी डिवाइस से हट जाएगी।';

  @override
  String get deletePermanently => 'स्थायी रूप से मिटाएं';

  @override
  String get tryAgain => 'फिर प्रयास करें';

  @override
  String get trashEmpty => 'ट्रैश खाली है।';

  @override
  String get shareLinkCopied =>
      'साझा लिंक कॉपी हुआ। क्लिपबोर्ड 30 सेकंड में साफ होगा।';

  @override
  String get shareAccount => 'खाता साझा करें';

  @override
  String get shareEncryptionDescription =>
      'ऐप अपलोड से पहले इस खाते को एन्क्रिप्ट करता है। सर्वर इसे पढ़ नहीं सकता। डिक्रिप्शन कुंजी लिंक में # चिह्न के बाद रहती है और सर्वर को नहीं भेजी जाती।';

  @override
  String get linkExpiresAfter => 'लिंक की समय-सीमा';

  @override
  String get fiveMinutes => '5 मिनट';

  @override
  String get oneHour => '1 घंटा';

  @override
  String get sixHours => '6 घंटे';

  @override
  String get twentyFourHours => '24 घंटे';

  @override
  String get deleteAfterFirstDownload => 'पहले डाउनलोड के बाद मिटाएं';

  @override
  String get oneTimeShareDescription =>
      'दूसरा डिवाइस उसी शेयर को डाउनलोड नहीं कर सकता।';

  @override
  String get createEncryptedLink => 'एन्क्रिप्टेड लिंक बनाएं';

  @override
  String shareCreationFailed(String error) {
    return 'शेयर नहीं बना: $error';
  }

  @override
  String get shareSignInDescription =>
      'लिंक बनाने के लिए साइन इन करना आवश्यक है। प्राप्तकर्ता को खाते की आवश्यकता नहीं है।';

  @override
  String get copyShareLink => 'साझा लिंक कॉपी करें';

  @override
  String get shareLinkWarning =>
      'पूरा लिंक रखने वाला व्यक्ति समय-सीमा तक या एक डाउनलोड होने तक यह खाता आयात कर सकता है। इसे केवल सही प्राप्तकर्ता को भेजें।';

  @override
  String get pendingPermanentDeletion => 'स्थायी रूप से मिटाना बाकी है';

  @override
  String get permanentlyDeletedInOneDay => '1 दिन में स्थायी रूप से मिटेगा';

  @override
  String permanentlyDeletedInDays(int days) {
    return '$days दिन में स्थायी रूप से मिटेगा';
  }

  @override
  String expiresAt(String time) {
    return 'समाप्ति: $time';
  }

  @override
  String get signOutOfSyncQuestion => 'सिंक से साइन आउट करें?';

  @override
  String get signOutOfSyncDescription =>
      'आपके कोड इस डिवाइस पर रहेंगे। फिर साइन इन करने तक यह डिवाइस बदलाव भेजना और प्राप्त करना बंद करेगा।';

  @override
  String get signOut => 'साइन आउट';

  @override
  String get syncEncryptionDescription =>
      'सिंक आपके कोड को सभी साइन-इन डिवाइस पर रखता है। सर्वर इन्हें एन्क्रिप्टेड रखता है और पढ़ नहीं सकता।';

  @override
  String get turnOnSync => 'इस डिवाइस पर सिंक चालू करें';

  @override
  String get turnOnSyncDescription =>
      'इस डिवाइस पर मौजूद खाते का उपयोग करता है।';

  @override
  String get signInExistingAccount => 'मौजूदा खाते में साइन इन करें';

  @override
  String get signInExistingAccountDescription =>
      'ऐसे डिवाइस के लिए जो अभी इस वॉल्ट में शामिल नहीं है।';

  @override
  String get unknown => 'अज्ञात';

  @override
  String get server => 'सर्वर';

  @override
  String get notSet => 'सेट नहीं है';

  @override
  String get syncNow => 'अभी सिंक करें';

  @override
  String get signOutOfSync => 'सिंक से साइन आउट करें';

  @override
  String get codesStayOnDevice => 'आपके कोड इस डिवाइस पर रहेंगे।';

  @override
  String get noCompletedSync => 'अभी कोई सिंक पूरा नहीं हुआ';

  @override
  String get unknownWhileLocked => 'लॉक होने पर अज्ञात';

  @override
  String get couldNotLoad => 'लोड नहीं हुआ';

  @override
  String get loading => 'लोड हो रहा है';

  @override
  String get synchronizationStatus => 'सिंक स्थिति';

  @override
  String get lastSync => 'पिछला सिंक';

  @override
  String get pendingChanges => 'बाकी बदलाव';

  @override
  String get activeDevices => 'सक्रिय डिवाइस';

  @override
  String get notConfigured => 'कॉन्फ़िगर नहीं है';

  @override
  String get retry => 'फिर प्रयास करें';

  @override
  String get syncIsOff => 'सिंक बंद है';

  @override
  String get synced => 'सिंक पूरा हुआ';

  @override
  String changesWaiting(int count) {
    return '$count बदलाव सिंक के लिए बाकी हैं';
  }

  @override
  String get changesWaitingUnknown => 'बदलाव सिंक के लिए बाकी हैं';

  @override
  String get offline => 'ऑफ़लाइन';

  @override
  String get syncSessionExpired => 'सिंक सत्र समाप्त हो गया';

  @override
  String get signThisDeviceOutQuestion => 'इस डिवाइस से साइन आउट करें?';

  @override
  String removeDeviceQuestion(String name) {
    return '$name हटाएं?';
  }

  @override
  String get signThisDeviceOutDescription =>
      'आप यहां साइन आउट हो जाएंगे। फिर साइन इन करने तक सिंक बंद रहेगा। इस डिवाइस के मौजूदा कोड सुरक्षित रहेंगे।';

  @override
  String get removeDeviceDescription =>
      'सिंक तुरंत बंद होगा और फिर साइन इन करने के लिए पासवर्ड आवश्यक होगा।\n\nउस डिवाइस के मौजूदा कोड नहीं मिटेंगे। डिवाइस खो गया है और अनलॉक है, तो उससे सुरक्षित पासवर्ड बदलें।';

  @override
  String get remove => 'हटाएं';

  @override
  String get signOutEverywhereQuestion => 'सभी जगह से साइन आउट करें?';

  @override
  String get signOutEverywhereDescription =>
      'इस डिवाइस सहित सभी डिवाइस पर फिर साइन इन करने के लिए पासवर्ड आवश्यक होगा।\n\nयदि किसी अन्य व्यक्ति की पहुंच का संदेह है और डिवाइस पता नहीं है, तो इसका उपयोग करें। कोई कोड नहीं मिटेगा।';

  @override
  String get signOutEverywhere => 'सभी जगह से साइन आउट करें';

  @override
  String accountDeletedResult(int count) {
    return 'खाता मिटा दिया गया। $count एन्क्रिप्टेड रिकॉर्ड नष्ट हुए। इस डिवाइस के कोड अभी भी मौजूद हैं।';
  }

  @override
  String get refresh => 'रीफ़्रेश';

  @override
  String get devicesIntroduction =>
      'ये डिवाइस आपके कोड सिंक कर सकते हैं। किसी डिवाइस को हटाने पर उसका सिंक तुरंत बंद होता है।';

  @override
  String get signOutEverywhereDescriptionShort =>
      'सभी डिवाइस पर फिर पासवर्ड आवश्यक होगा। कुछ नहीं मिटेगा।';

  @override
  String get deleteSyncAccount => 'सिंक खाता मिटाएं';

  @override
  String get deleteSyncAccountDescription =>
      'सर्वर से सब कुछ हटाता है। इस डिवाइस के कोड सुरक्षित रहते हैं।';

  @override
  String get neverSynced => 'कभी सिंक नहीं हुआ';

  @override
  String lastSyncedAt(String time) {
    return 'पिछला सिंक: $time';
  }

  @override
  String get activeNow => 'अभी सक्रिय';

  @override
  String minutesAgo(int count) {
    return '$count मिनट पहले';
  }

  @override
  String hoursAgo(int count) {
    return '$count घंटे पहले';
  }

  @override
  String daysAgo(int count) {
    return '$count दिन पहले';
  }

  @override
  String get removed => 'हटाया गया';

  @override
  String get removeThisDevice => 'यह डिवाइस हटाएं';

  @override
  String get deleteSyncAccountQuestion => 'अपना सिंक खाता मिटाएं?';

  @override
  String get deleteSyncAccountWarning =>
      'सर्वर पर संग्रहीत सब कुछ नष्ट होगा और सभी डिवाइस साइन आउट होंगे। इसे वापस नहीं किया जा सकता।';

  @override
  String get deleteSyncAccountKeepsCodes =>
      'इस डिवाइस के कोड सुरक्षित रहेंगे और काम करेंगे। दूसरे डिवाइस अपने मौजूदा कोड रखेंगे, लेकिन आगे सिंक नहीं होगा।';

  @override
  String get accountPassword => 'खाता पासवर्ड';

  @override
  String get deleteAccount => 'खाता मिटाएं';

  @override
  String get allowScreenCaptureQuestion => 'स्क्रीन कैप्चर की अनुमति दें?';

  @override
  String get allowScreenCaptureWarning =>
      'स्क्रीनशॉट और स्क्रीन रिकॉर्डिंग में कोड, QR कोड, खाते के नाम, नोट और कस्टम चित्र आ सकते हैं। दूसरे ऐप और बैकअप सेवाएं इन चित्रों को रख सकती हैं।';

  @override
  String get allow => 'अनुमति दें';

  @override
  String screenshotSettingFailed(String error) {
    return 'स्क्रीनशॉट सेटिंग नहीं बदली: $error';
  }

  @override
  String codeVisibilitySettingFailed(String error) {
    return 'कोड दृश्यता सेटिंग विफल हुई: $error';
  }

  @override
  String get applicationTheme => 'ऐप थीम';

  @override
  String themeSettingFailed(String error) {
    return 'थीम सेटिंग विफल हुई: $error';
  }

  @override
  String listSpacingSettingFailed(String error) {
    return 'सूची अंतर सेटिंग विफल हुई: $error';
  }

  @override
  String get wipeThisDeviceQuestion => 'यह डिवाइस मिटाएं?';

  @override
  String get wipeThisDeviceWarning =>
      'इस डिवाइस के सभी कोड मिटेंगे और उन्हें डिक्रिप्ट करने वाली कुंजी नष्ट होगी। सिंक सेट नहीं है, तो इन्हें वापस नहीं लाया जा सकता।';

  @override
  String get wipe => 'मिटाएं';

  @override
  String get deleteAfterAttemptsQuestion =>
      'विफल प्रयासों के बाद सब कुछ मिटाएं?';

  @override
  String deleteAfterAttemptsWarning(int count) {
    return 'लगातार $count गलत प्रयासों के बाद इस डिवाइस के सभी कोड और कुंजी मिट जाएंगे।\n\nइसे वापस नहीं किया जा सकता। पहले बैकअप या दूसरा साइन-इन डिवाइस रखें।';
  }

  @override
  String get turnItOn => 'चालू करें';

  @override
  String get off => 'बंद';

  @override
  String get wrongAttemptsCounted =>
      'गलत प्रयास गिने जाते हैं। कुछ नहीं मिटता।';

  @override
  String afterWrongAttempts(int count) {
    return '$count गलत प्रयासों के बाद';
  }

  @override
  String get choosePassphrase => 'पासफ़्रेज़ चुनें';

  @override
  String get backupPassphraseWarning =>
      'केवल यह पासफ़्रेज़ बैकअप खोलता है। इसे रीसेट नहीं किया जा सकता। इसकी प्रति इस डिवाइस से बाहर रखें।';

  @override
  String get automaticPassphraseStorage =>
      'हर बार पूछे बिना बैकअप बनाने के लिए यह डिवाइस पासफ़्रेज़ को सुरक्षित स्टोरेज में रखता है।';

  @override
  String get passphrase => 'पासफ़्रेज़';

  @override
  String get typeAgain => 'फिर दर्ज करें';

  @override
  String get thisBackupIsEncrypted => 'यह बैकअप एन्क्रिप्टेड है';

  @override
  String get backupPassphrase => 'बैकअप पासफ़्रेज़';

  @override
  String get thisFileProtectsNothing => 'यह फ़ाइल सुरक्षित नहीं है';

  @override
  String get useEncryptedBackup => 'एन्क्रिप्टेड बैकअप उपयोग करें';

  @override
  String get continueAnyway => 'फिर भी जारी रखें';

  @override
  String get typeExportToContinue => 'जारी रखने के लिए EXPORT लिखें';

  @override
  String get exportPlainText => 'सादे टेक्स्ट में निर्यात करें';

  @override
  String get enterAccountPassword => 'खाता पासवर्ड दर्ज करें';

  @override
  String get rotateRecoveryWarning =>
      'आपका वर्तमान रिकवरी वाक्यांश काम करना बंद करेगा। जहां भी पुराना वाक्यांश रखा है, उसे नए वाक्यांश से बदलें।';

  @override
  String get continueAction => 'जारी रखें';

  @override
  String get wipeThresholdExplanation =>
      'यदि किसी को यह फोन मिलता है और वह आपका पिन अनुमान लगाता है, तो यह सेटिंग आगे प्रयास करने देने के बजाय सभी कोड मिटाती है।\n\nइसे वापस नहीं किया जा सकता। इसे चालू करने से पहले बैकअप या दूसरा डिवाइस रखें।';

  @override
  String get immediately => 'तुरंत';

  @override
  String get after15Seconds => '15 सेकंड बाद';

  @override
  String get after1Minute => '1 मिनट बाद';

  @override
  String get after5Minutes => '5 मिनट बाद';

  @override
  String get after15Minutes => '15 मिनट बाद';

  @override
  String get never => 'कभी नहीं';

  @override
  String minimumCharacters(int count) {
    return 'कम से कम $count अक्षर उपयोग करें।';
  }

  @override
  String get passphrasesDifferent => 'दोनों पासफ़्रेज़ अलग हैं।';

  @override
  String get turnOn => 'चालू करें';

  @override
  String get plainExportWarning =>
      'आपके वॉल्ट के सभी कोड सादे टेक्स्ट में लिखे जाएंगे। फ़ाइल खोलने वाला व्यक्ति या इसे पढ़ने वाला ऐप अथवा क्लाउड सेवा आपके रूप में साइन इन कर सकती है।\n\nइसका उपयोग केवल दूसरे ऐप में जाने के लिए करें। काम पूरा होने पर फ़ाइल मिटाएं।\n\nरखने वाले बैकअप के लिए एन्क्रिप्टेड बैकअप उपयोग करें।';

  @override
  String get exportWord => 'EXPORT';

  @override
  String get copiedClipboardTwoMinutes =>
      'कॉपी हुआ। क्लिपबोर्ड 2 मिनट में साफ होगा।';

  @override
  String get copyToClipboard => 'क्लिपबोर्ड पर कॉपी करें';

  @override
  String get recoveryWrittenDown => 'मैंने ये शब्द लिख लिए हैं';

  @override
  String get confirmRecoveryInstructions =>
      'अपनी सूची से ये शब्द दर्ज करें। इससे जांच होती है कि आपने उन्हें सही लिखा है।';

  @override
  String get confirm => 'पुष्टि करें';

  @override
  String get showWordsAgain => 'शब्द फिर दिखाएं';

  @override
  String get selectWidgetAccount => 'विजेट खाता चुनें';

  @override
  String get widgetDescription =>
      'विजेट एक खाते का नाम दिखाता है। ऐप अनलॉक करके वर्तमान कोड देखने के लिए इसे टैप करें।';

  @override
  String get noWidgetAccount => 'कोई खाता नहीं चुना गया।';

  @override
  String get disableWidget => 'विजेट बंद करें';

  @override
  String get addAccountBeforeWidget =>
      'विजेट कॉन्फ़िगर करने से पहले खाता जोड़ें।';

  @override
  String get widgetLauncherInstructions =>
      'खाता चुनने के बाद Android लॉन्चर से Authenticator विजेट जोड़ें।';

  @override
  String get removePinQuestion => 'पिन हटाएं?';

  @override
  String get removePinWarning =>
      'आपके कोड एन्क्रिप्टेड रहेंगे, लेकिन इस डिवाइस को अनलॉक करने वाला व्यक्ति अलग पिन के बिना इन्हें खोल सकता है।';

  @override
  String get keepIt => 'रखें';

  @override
  String get removePin => 'पिन हटाएं';

  @override
  String get pinKeyDescription =>
      'पिन इस डिवाइस की कुंजी के साथ जोड़ा जाता है। कोड खोलने के लिए दोनों आवश्यक हैं।';

  @override
  String get allowBiometricUnlock => 'बायोमेट्रिक अनलॉक की अनुमति दें';

  @override
  String get biometricBindingDescription =>
      'डिवाइस कुंजी को आपके फिंगरप्रिंट या चेहरे से जोड़ता है।';

  @override
  String get accountSyncDescription =>
      'खाता आपके कोड अन्य डिवाइस तक पहुंचाता है। कोड एन्क्रिप्टेड रहते हैं।';

  @override
  String get skipForNow => 'अभी छोड़ें';

  @override
  String get scanQrCodeTitle => 'QR कोड स्कैन करें';

  @override
  String get manualEntryAlternative =>
      'सेटअप कुंजी दर्ज करके भी खाता जोड़ सकते हैं।';

  @override
  String get goBack => 'वापस जाएं';

  @override
  String get moveThisAccount => 'यह खाता भेजें';

  @override
  String get tapToShow => 'दिखाने के लिए टैप करें';

  @override
  String importedCount(int count) {
    return '$count आयात हुए';
  }

  @override
  String get addSkippedManually =>
      'छूटी हुई प्रविष्टियां पुराने ऐप से हाथ से जोड़ें।';

  @override
  String get bringAccountsAcross => 'अपने खाते यहां लाएं';

  @override
  String get typeSetupKeyManually => 'सेटअप कुंजी हाथ से दर्ज करें';

  @override
  String get setupKeyAvailable =>
      'प्रत्येक सेवा QR कोड के बजाय सेटअप कुंजी दिखा सकती है।';

  @override
  String get importAction => 'आयात करें';

  @override
  String get duplicateMovedToTrash => 'डुप्लिकेट ट्रैश में भेजा गया।';

  @override
  String get noDuplicateSecrets => 'कोई डुप्लिकेट गुप्त कुंजी नहीं मिली।';

  @override
  String get sameSecretDescription => 'इन खातों में समान गुप्त कुंजी है।';

  @override
  String get timeBased => 'समय-आधारित';

  @override
  String get counterBased => 'काउंटर-आधारित';

  @override
  String get advanced => 'उन्नत';

  @override
  String secondsValue(int count) {
    return '$count सेकंड';
  }

  @override
  String get stopImportingQuestion => 'आयात रोकें?';

  @override
  String get keepScanning => 'स्कैन जारी रखें';

  @override
  String get stop => 'रोकें';

  @override
  String get importGoogleAuthenticator => 'Google Authenticator से आयात करें';

  @override
  String importReadyCount(int count) {
    return '$count आयात करें';
  }

  @override
  String get quickAccessNoExposedCodes => 'कोड दिखाए बिना त्वरित पहुंच';

  @override
  String widgetSettingReadFailed(String error) {
    return 'विजेट सेटिंग पढ़ी नहीं गई: $error';
  }

  @override
  String get widgetEnabled => 'विजेट चालू है';

  @override
  String get widgetDisabled => 'विजेट बंद है';

  @override
  String get changeAccount => 'खाता बदलें';

  @override
  String get selectAccount => 'खाता चुनें';

  @override
  String get newPinOrPassphrase => 'नया पिन या पासफ़्रेज़';

  @override
  String get enterItAgain => 'फिर दर्ज करें';

  @override
  String get entriesDoNotMatch => 'दोनों प्रविष्टियां मेल नहीं खातीं।';

  @override
  String get biometricInvalidationDescription =>
      'डिवाइस कुंजी को आपके फिंगरप्रिंट या चेहरे से जोड़ता है। नया फिंगरप्रिंट जोड़ने पर यह अमान्य हो जाता है।';

  @override
  String get pinDerivationDescription =>
      'पिन सेट करने में कुछ समय लगता है। कुंजी को जानबूझकर धीरे बनाया जाता है, जिससे अनुमान लगाना धीमा होता है।';

  @override
  String get secretCannotBeChanged => 'गुप्त कुंजी बदली नहीं जा सकती';

  @override
  String get secretCannotBeChangedDescription =>
      'अलग गुप्त कुंजी एक अलग खाता है, केवल नया नाम नहीं। यह प्रविष्टि मिटाएं और नया कोड स्कैन करें।';

  @override
  String get chooseBackupFile => 'बैकअप फ़ाइल चुनें';

  @override
  String get chooseBackupToTest => 'जांचने के लिए बैकअप चुनें';

  @override
  String get password => 'पासवर्ड';

  @override
  String get emailAddress => 'ईमेल पता';

  @override
  String get email => 'ईमेल';

  @override
  String get enterPasswordAgain => 'पासवर्ड फिर दर्ज करें';

  @override
  String get setupKey => 'सेटअप कुंजी';

  @override
  String get startingCounter => 'शुरुआती काउंटर';

  @override
  String get algorithm => 'एल्गोरिदम';

  @override
  String get digits => 'अंक';

  @override
  String get period => 'अवधि';

  @override
  String get folderName => 'फ़ोल्डर का नाम';

  @override
  String get syncServer => 'सिंक सर्वर';

  @override
  String get pinOrPassphrase => 'पिन या पासफ़्रेज़';

  @override
  String wordPosition(int position) {
    return 'शब्द $position';
  }

  @override
  String get signIn => 'साइन इन';

  @override
  String get signInDownloadDescription =>
      'यह डिवाइस आपके कोड डाउनलोड करता है और आपके पासवर्ड से खोलता है। सर्वर कुंजी नहीं देखता।';

  @override
  String get fromDeviceAccount => 'इस डिवाइस के खाते से';

  @override
  String get emailRecoveryDescription =>
      'रिकवरी और नए डिवाइस की मंजूरी के लिए उपयोग होता है।';

  @override
  String get createAccountAction => 'खाता बनाएं';

  @override
  String get addAccount => 'खाता जोड़ें';

  @override
  String get chooseExportFile => 'निर्यात फ़ाइल चुनें';

  @override
  String get cancelSelection => 'चयन रद्द करें';

  @override
  String get changeFavouriteStatus => 'पसंदीदा स्थिति बदलें';

  @override
  String get searchAccountsNotesTags => 'खाते, नोट या टैग खोजें';

  @override
  String get sort => 'क्रम बदलें';

  @override
  String get workExample => 'काम';

  @override
  String get issuerExample => 'GitHub';

  @override
  String get accountExample => 'you@example.com';

  @override
  String get issuerHelper => 'उदाहरण: GitHub। वैकल्पिक।';

  @override
  String get accountHelper => 'उस सेवा का आपका उपयोगकर्ता नाम या ईमेल पता।';

  @override
  String get encryptedEntryOptional =>
      'इस प्रविष्टि के साथ एन्क्रिप्ट होता है। वैकल्पिक।';

  @override
  String get tagsHelper => 'टैग को अल्पविराम से अलग करें। अधिकतम 20 टैग।';

  @override
  String get tagsExample => 'काम, वित्त';

  @override
  String get chooseCustomIcon => 'कस्टम आइकन चुनें';

  @override
  String get saveBackup => 'अपना बैकअप सहेजें';

  @override
  String get syncServerExample => 'https://…';

  @override
  String get chooseQrImage => 'QR कोड वाली छवि चुनें';

  @override
  String get chooseImage => 'छवि चुनें';

  @override
  String get torch => 'टॉर्च';

  @override
  String get welcomeTitle => 'आपके कोड, आपके नियंत्रण में';

  @override
  String get welcomeDescription =>
      'आपका डेटा इस डिवाइस से बाहर जाने से पहले एन्क्रिप्ट होता है। आप इसे किसी भी समय निर्यात कर सकते हैं।';

  @override
  String get bringMyAccountsAcross => 'मेरे खाते आयात करें';

  @override
  String get bringAccountsSources =>
      'Google Authenticator, Aegis, 2FAS, Authy, Microsoft Authenticator या किसी अन्य ऐप से।';

  @override
  String get setUpSync => 'सिंक सेट करें';

  @override
  String get setUpSyncDescription =>
      'आपके कोड आपके सभी डिवाइस पर रखता है। सर्वर केवल एन्क्रिप्ट किया हुआ डेटा रखता है।';

  @override
  String get useOnThisPhone => 'केवल इस फ़ोन पर उपयोग करें';

  @override
  String get useOnThisPhoneDescription =>
      'कोई खाता और नेटवर्क पर कोई डेटा स्थानांतरण नहीं। आप बाद में सिंक चालू कर सकते हैं।';

  @override
  String get changeLaterInSettings =>
      'आप ये विकल्प बाद में सेटिंग्स में बदल सकते हैं।';

  @override
  String get nextCodeTooltip => 'अगला कोड';

  @override
  String get undo => 'पहले जैसा करें';

  @override
  String get folder => 'फ़ोल्डर';

  @override
  String get qrCode => 'QR कोड';

  @override
  String get share => 'साझा करें';

  @override
  String get showIt => 'दिखाएं';

  @override
  String get nameSort => 'नाम';

  @override
  String get issuerSort => 'जारीकर्ता';

  @override
  String get recentlyAddedSort => 'हाल ही में जोड़ा गया';

  @override
  String get manualSort => 'मेरा क्रम';

  @override
  String get noSearchResults => 'कोई प्रविष्टि इस खोज से मेल नहीं खाती।';

  @override
  String get noAccountsYet => 'अभी कोई खाता नहीं है।';

  @override
  String availableAfterSeconds(int count) {
    return '$count सेकंड बाद उपलब्ध।';
  }

  @override
  String get nextCodeCopied =>
      'अगला कोड कॉपी हुआ। क्लिपबोर्ड 30 सेकंड में साफ होगा।';

  @override
  String clockOffsetWarning(int count) {
    return 'इस डिवाइस की घड़ी लगभग $count सेकंड गलत है। घड़ी ठीक करने तक कोड विफल हो सकते हैं।';
  }

  @override
  String selectedCount(int count) {
    return '$count चुने गए';
  }

  @override
  String get vaultOpenFailed => 'वॉल्ट नहीं खुल सका';

  @override
  String get vaultDataSafeAfterOpenFailure =>
      'आपकी प्रविष्टियां नहीं मिटाई गई हैं। फिर प्रयास करने के लिए ऐप बंद करके दोबारा खोलें।';

  @override
  String get unnamedEntry => 'बिना नाम की प्रविष्टि';

  @override
  String get all => 'सभी';

  @override
  String get unfiled => 'बिना फ़ोल्डर';

  @override
  String get holdToManageFolder => 'नाम बदलने या मिटाने के लिए दबाकर रखें';

  @override
  String codeExpiresInSeconds(int count) {
    return 'कोड $count सेकंड में समाप्त होगा';
  }

  @override
  String get codeHiddenAccessibility =>
      'कोड छिपा है। दिखाने के लिए सक्रिय करें।';

  @override
  String duplicatesSkipped(int count) {
    return '$count खाते पहले से सूची में थे और दोबारा नहीं जोड़े गए।';
  }

  @override
  String couldNotImportCount(int count) {
    return '$count आयात नहीं किए जा सके:';
  }

  @override
  String get unreadableExport =>
      'यह फ़ाइल ऐसा निर्यात नहीं है जिसे यह ऐप पढ़ सके।';

  @override
  String encryptedSourceExport(String source) {
    return 'यह $source निर्यात एन्क्रिप्ट किया हुआ है';
  }

  @override
  String get enterBackupPassphrase =>
      'बैकअप बनाते समय सेट किया पासफ़्रेज़ दर्ज करें।';

  @override
  String enterSourceExportPassword(String source) {
    return '$source में निर्यात बनाते समय सेट किया पासवर्ड दर्ज करें।';
  }

  @override
  String get syncCatchUpUnlock =>
      'ऐप दूसरे डिवाइस के बदलाव प्राप्त कर रहा है। कुछ समय बाद फिर अनलॉक करें।';

  @override
  String get removeFromFavourites => 'पसंदीदा से हटाएं';

  @override
  String get addToFavourites => 'पसंदीदा में जोड़ें';

  @override
  String get automaticBackupOnMessage => 'स्वचालित एन्क्रिप्टेड बैकअप चालू है।';

  @override
  String get automaticBackupCancelled => 'स्वचालित बैकअप सेटअप रद्द हुआ।';

  @override
  String get backupDirectoryChanged => 'स्वचालित बैकअप फ़ोल्डर बदला गया।';

  @override
  String get automaticBackupSaved => 'स्वचालित एन्क्रिप्टेड बैकअप सहेजा गया।';

  @override
  String get automaticBackupAndroidOnly => 'Android पर उपलब्ध।';

  @override
  String get automaticBackupOffStatus =>
      'बंद। सात नवीनतम एन्क्रिप्टेड फ़ाइलें रखता है।';

  @override
  String get selectedDirectory => 'चुना हुआ फ़ोल्डर';

  @override
  String automaticBackupOnDirectory(String location) {
    return 'चालू। फ़ोल्डर: $location';
  }

  @override
  String automaticBackupLast(String time, String location) {
    return 'चालू। अंतिम बैकअप: $time।\nफ़ोल्डर: $location';
  }

  @override
  String get backupCancelled => 'बैकअप रद्द हुआ।';

  @override
  String get backupSaved => 'बैकअप सहेजा गया।';

  @override
  String get notApplicationBackup => 'यह फ़ाइल इस ऐप का बैकअप नहीं है।';

  @override
  String get emailRequired => 'ईमेल पता आवश्यक है।';

  @override
  String get emailInvalid => 'मान्य ईमेल पता दर्ज करें।';

  @override
  String get passwordMinimumTen => 'कम से कम 10 अक्षर उपयोग करें।';

  @override
  String get passwordsDoNotMatch => 'दोनों पासवर्ड मेल नहीं खाते।';

  @override
  String get createAccountKeepsCodes =>
      'आपके वर्तमान कोड नहीं बदलते। खाता एन्क्रिप्टेड सिंक और खाता रिकवरी जोड़ता है।';

  @override
  String get accountNameRequired => 'खाते का नाम दर्ज करें।';

  @override
  String get noteTooLong => 'नोट में अधिकतम 512 अक्षर हो सकते हैं।';

  @override
  String get tooManyTags => 'एक प्रविष्टि में अधिकतम 20 टैग हो सकते हैं।';

  @override
  String get tagTooLong => 'एक टैग में अधिकतम 32 वर्ण हो सकते हैं।';

  @override
  String get renameSyncDescription =>
      'प्रविष्टि का नाम बदलने पर सभी डिवाइस पर नाम बदलता है। कोड नहीं बदलते।';

  @override
  String get imageCouldNotOpen => 'छवि नहीं खुल सकी।';

  @override
  String get counterInvalid =>
      'आरंभिक काउंटर शून्य या उससे अधिक पूर्ण संख्या होना चाहिए।';

  @override
  String get enterAccountForCode => 'इस कोड का खाता दर्ज करें।';

  @override
  String get setupKeyHelper =>
      'सेवा के QR कोड के पास दी गई कुंजी दर्ज करें। स्पेस और अक्षरों का केस महत्वपूर्ण नहीं है।';

  @override
  String get enterSetupKeyError => 'सेटअप कुंजी दर्ज करें।';

  @override
  String get timeBasedDescription =>
      'कोड समय के अनुसार बदलता है। लगभग सभी सेवाएं यह प्रकार उपयोग करती हैं।';

  @override
  String get counterBasedDescription => 'अगला कोड मांगने पर कोड बदलता है।';

  @override
  String get counterHelper =>
      'सामान्यतः 0। यह मान सेवा के मान से मेल खाना चाहिए।';

  @override
  String get enterWholeCounter => 'काउंटर को पूर्ण संख्या में दर्ज करें।';

  @override
  String get qrSecretWarning =>
      'यह QR कोड खाते की गुप्त कुंजी है। इसकी फोटो लेने वाला व्यक्ति आपके रूप में साइन इन कर सकता है। इसे रद्द करने के लिए दो-कारक प्रमाणीकरण रीसेट करें।';

  @override
  String get hideSetupKey => 'सेटअप कुंजी छिपाएं';

  @override
  String get showSetupKey => 'सेटअप कुंजी दिखाएं';

  @override
  String get checkScreenPrivacy => 'जांचें कि आपकी स्क्रीन कौन देख सकता है';

  @override
  String get useAtLeastSixDigits => 'कम से कम 6 अंक उपयोग करें।';

  @override
  String get useAtLeastSixCharacters => 'कम से कम 6 अक्षर उपयोग करें।';

  @override
  String get avoidRepeatedPin => 'एक ही अंक को बार-बार उपयोग न करें।';

  @override
  String get avoidSequentialPin => '123456 जैसा क्रम उपयोग न करें।';

  @override
  String get deviceKeyProtectionFailed =>
      'डिवाइस कुंजी सुरक्षित नहीं की जा सकी।';

  @override
  String get wrongExportPart =>
      'यह कोड दूसरे निर्यात का है। पहले निर्यात के बाकी कोड स्कैन करें।';

  @override
  String get migrationCodeAlreadyScanned => 'यह कोड पहले स्कैन हो चुका है।';

  @override
  String partialExportScanned(int count) {
    return 'आपने निर्यात का एक भाग स्कैन किया है। बाहर जाने से पहले $count और स्कैन करें।';
  }

  @override
  String get allCodesScanned => 'सभी कोड स्कैन हो गए।';

  @override
  String scanNextMigrationCode(int count) {
    return 'अगला कोड स्कैन करें। $count बाकी हैं।';
  }

  @override
  String get notSharedAccountQr => 'यह QR कोड साझा खाते का लिंक नहीं है।';

  @override
  String get notOtpSetupQr => 'यह QR कोड दो-कारक सेटअप कोड नहीं है।';

  @override
  String get selectedImageUnavailable => 'डिवाइस ने चुनी हुई छवि नहीं दी।';

  @override
  String get noSharedQrInImage => 'छवि में साझा खाते का QR कोड नहीं मिला।';

  @override
  String get noOtpQrInImage => 'छवि में दो-कारक QR कोड नहीं मिला।';

  @override
  String get imageScanFailed => 'चुनी हुई छवि स्कैन नहीं की जा सकी।';

  @override
  String get cameraPermissionRequired =>
      'ऐप को कैमरा उपयोग करने की अनुमति नहीं है।';

  @override
  String get cameraStartFailed => 'कैमरा चालू नहीं हो सका।';

  @override
  String get enterSyncServer => 'सिंक सर्वर का पता दर्ज करें।';

  @override
  String get syncServerRequiresHttps => 'पता https:// से शुरू होना चाहिए।';

  @override
  String get enterAccountEmail => 'खाते का ईमेल पता दर्ज करें।';

  @override
  String get enterNewAccountPassword =>
      'इस खाते के लिए सेट किया पासवर्ड दर्ज करें।';

  @override
  String get enterPin => 'अपना PIN दर्ज करें।';

  @override
  String get biometricUnlockFailed =>
      'बायोमेट्रिक अनलॉक विफल हुआ। इसके बजाय PIN दर्ज करें।';

  @override
  String get show => 'दिखाएं';

  @override
  String get hide => 'छिपाएं';

  @override
  String get failedAttemptLimitReached =>
      'विफल प्रयासों की सीमा पूरी हो गई है।';

  @override
  String get useRecoveryPhraseTitle => 'रिकवरी वाक्यांश उपयोग करें';

  @override
  String get useAccountPasswordTitle => 'खाता पासवर्ड उपयोग करें';

  @override
  String get recoveryPhraseEntryHelp =>
      'खाता बनाते समय सहेजे गए 24 शब्द दर्ज करें।';

  @override
  String get accountPasswordEntryHelp =>
      'इस डिवाइस के सिंक खाते का पासवर्ड दर्ज करें।';

  @override
  String get recoveryPhraseField => '24 शब्दों का रिकवरी वाक्यांश';

  @override
  String incorrectRecoveryWord(int position) {
    return 'स्थान $position पर यह शब्द नहीं है।';
  }

  @override
  String get writeRecoveryFirst =>
      'पहले ये शब्द लिखें। आपके कोड वापस पाने का यही एक तरीका है।';

  @override
  String get confirmRecoveryKey => 'रिकवरी कुंजी की पुष्टि करें';

  @override
  String get yourRecoveryKey => 'आपकी रिकवरी कुंजी';

  @override
  String get recoveryKeyWarning =>
      'यदि पासवर्ड और डिवाइस खो जाएं, तो आपके कोड वापस पाने का एकमात्र तरीका ये 24 शब्द हैं।';

  @override
  String get paperSaferThanClipboard =>
      'कागज क्लिपबोर्ड से सुरक्षित है। दूसरे ऐप क्लिपबोर्ड डेटा पढ़ सकते हैं।';

  @override
  String failedAttemptsRemaining(int attempts, int remaining) {
    return '$attempts प्रयास विफल हुए। वाइप सुरक्षा चालू होने पर डिवाइस मिटने से पहले $remaining प्रयास बाकी हैं।';
  }

  @override
  String migrationFoundReport(int ready, int refused) {
    return '$ready खाते मिले। $refused पढ़े नहीं जा सके।';
  }

  @override
  String get directImports => 'सीधा आयात';

  @override
  String get googleImportSteps =>
      'Google Authenticator खोलें।\nमेनू खोलें। Transfer accounts और फिर Export accounts चुनें।\nखाते चुनें। फिर Next चुनें।\nदिखाए गए सभी QR कोड स्कैन करें। बड़े निर्यात में एक से अधिक QR कोड होते हैं।';

  @override
  String get scanExportCode => 'निर्यात कोड स्कैन करें';

  @override
  String get aegisImportSteps =>
      'Aegis खोलें।\nSettings, Import & Export और फिर Export चुनें।\nफ़ाइल ऐसी जगह सहेजें जिसे इस ऐप से खोल सकें।\nनीचे फ़ाइल चुनें। पूछे जाने पर निर्यात पासवर्ड दर्ज करें।';

  @override
  String get chooseFile => 'फ़ाइल चुनें';

  @override
  String get twoFasImportSteps =>
      '2FAS खोलें।\nSettings, Backup और फिर Export to file चुनें।\n.2fas फ़ाइल ऐसी जगह सहेजें जिसे इस ऐप से खोल सकें।\nनीचे फ़ाइल चुनें। पासवर्ड-सुरक्षित बैकअप समर्थित हैं।';

  @override
  String get enteImportSteps =>
      'Ente Auth खोलें और कोड निर्यात करें।\nउपलब्ध होने पर पासवर्ड-सुरक्षित निर्यात उपयोग करें।\nनीचे फ़ाइल चुनें। पूछे जाने पर निर्यात पासवर्ड दर्ज करें।\nसादा टेक्स्ट निर्यात भी समर्थित है।';

  @override
  String get protonImportSteps =>
      'Proton Authenticator खोलें और कोड निर्यात करें।\nनिर्यात पासवर्ड सेट करें।\nनीचे JSON फ़ाइल चुनें। पूछे जाने पर निर्यात पासवर्ड दर्ज करें।\nसादा JSON निर्यात भी समर्थित है।';

  @override
  String get bitwardenImportSteps =>
      'वॉल्ट को बिना एन्क्रिप्शन वाले JSON में निर्यात करें।\nनीचे JSON फ़ाइल चुनें। केवल TOTP मान वाले आइटम आयात होंगे।\nआयात जांचने के बाद बिना एन्क्रिप्शन वाली फ़ाइल मिटाएं।';

  @override
  String get standardNotesImportSteps =>
      'Authenticator नोट को JSON में निर्यात करें।\nनीचे JSON फ़ाइल चुनें। प्रत्येक प्रविष्टि के नोट रखे जाएंगे।';

  @override
  String get appsWithoutExport => 'वे ऐप जो निर्यात नहीं देते';

  @override
  String get appsWithoutExportDescription =>
      'Microsoft Authenticator और Authy समर्थित निर्यात नहीं देते। प्रत्येक खाते को उसकी सेवा पर फिर सेट करें।';

  @override
  String get microsoftImportSteps =>
      'Microsoft Authenticator निर्यात नहीं देता।\nप्रत्येक खाते के लिए सेवा में साइन इन करें और सुरक्षा सेटिंग्स खोलें।\nपुराना authenticator हटाएं। उसे फिर सेट करें और नया QR कोड इस ऐप से स्कैन करें।\nपहले महत्वपूर्ण खाते स्थानांतरित करें। सभी खाते स्थानांतरित होने तक पुराना ऐप रखें।';

  @override
  String get authyImportSteps =>
      'Authy निर्यात नहीं देता।\nयदि पुराना Authy डेस्कटॉप ऐप काम करता है, तो Aegis उससे आयात कर सकता है। फिर Aegis से निर्यात करें।\nअन्यथा, प्रत्येक खाते को उसकी सेवा पर फिर सेट करें।';

  @override
  String get otherAuthenticators => 'अन्य authenticator ऐप';

  @override
  String get otherAuthenticatorHelp =>
      'अधिकांश authenticator ऐप QR कोड या फ़ाइल निर्यात करते हैं। यह ऐप दोनों का समर्थन करता है। प्रारूप न पहचाने जाने पर उसे Aegis में आयात करें और Aegis से निर्यात करें।';

  @override
  String get imageFileEmpty => 'छवि फ़ाइल खाली है।';

  @override
  String get imageTooLarge => '5 MB से छोटी छवि चुनें।';

  @override
  String get imageCannotFitEntry =>
      'यह छवि एन्क्रिप्टेड प्रविष्टि में फिट नहीं हो सकती। सरल छवि चुनें।';

  @override
  String get automaticBackupPassphraseMissing =>
      'स्वचालित बैकअप का पासफ़्रेज़ नहीं है। इसे फिर सेट करें।';
}
