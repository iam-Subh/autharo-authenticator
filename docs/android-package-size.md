# Android package size

Measure a release package. Do not use a debug APK as a release-size result.
Flutter debug APKs include the Dart kernel, debug engine data, validation
libraries, and unstripped Rust code.

The production release requires the certificate-pinning values in
[Production security configuration](production-security.md). The build must
stop if those values are absent.

Before you have the production values, build a profile package for a local
size audit:

```powershell
flutter build apk --profile --split-per-abi
```

Do not distribute this profile package. It has no certificate pins. Profile
mode also contains profiling support and does not apply all release shrinking,
so treat its size as an upper estimate.

## Play Store package

Build an Android App Bundle (AAB). Google Play sends only the processor
architecture, language, and screen-density resources that a device needs.

```powershell
flutter build appbundle --release --split-debug-info=build/symbols
```

The AAB file contains files for all supported devices. Its file size is not the
per-device download size. Use the Play Console size report for that value.

## Direct APK package

Build one APK for each application binary interface (ABI). An ABI identifies a
processor architecture.

```powershell
flutter build apk --release --split-per-abi --split-debug-info=build/symbols
```

Install only the APK that matches the device. Do not distribute the universal
APK if package size is a release requirement.

Check a generated APK without rebuilding it:

```powershell
..\scripts\check_android_package_size.ps1 `
  -PackagePath build\app\outputs\flutter-apk\app-arm64-v8a-release.apk
```

The default limit is 50 MiB. Use `-MaxMiB` to set a different limit.

## Implemented size controls

- R8 removes unused Java and Kotlin bytecode.
- Android resource shrinking removes resources that R8 proves unused.
- Native libraries remain in the APK and Android maps them directly. Android
  does not create a second extracted copy.
- Rust release builds use size optimization, whole-program link-time
  optimization, one code generation unit, abort-on-panic, and symbol stripping.
- SQLite3 Multiple Ciphers includes only the ChaCha20 database cipher used by
  the vault.
- The unused Cupertino icon font dependency is removed.

The QR scanner keeps its on-device barcode library. This preserves offline QR
scanning and support for devices without Google Play Services.

## Size analysis

If one release ABI APK exceeds 50 MiB, create a Flutter size report for one
architecture:

```powershell
flutter build apk --release --analyze-size --target-platform=android-arm64 `
  --split-debug-info=build/symbols
```

Open the generated DevTools report. Check `libapp.so`,
`librust_lib_authenticator.so`, `libflutter.so`, and `libbarhopper_v3.so`
first. Do not remove cryptography or offline scanning only to reduce size.
