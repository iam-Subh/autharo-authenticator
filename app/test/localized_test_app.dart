import 'package:authenticator/l10n/generated/app_localizations.dart';
import 'package:flutter/material.dart';

Widget localizedTestApp({required Widget home}) => MaterialApp(
  localizationsDelegates: AppLocalizations.localizationsDelegates,
  supportedLocales: AppLocalizations.supportedLocales,
  home: home,
);
