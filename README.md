# Cross-Platform Authenticator App

Implementation of the PRD, version 0.6. The build order is the dependency
sequence in section 18: each stage is finished before the next starts.

## Stage status

| Stage | Content | State |
|---|---|---|
| S1 — Core | TOTP, HOTP, Base32, the `otpauth://` parser, SQLite storage | **Done.** RFC 6238 and RFC 4226 vectors pass for SHA-1, SHA-256, and SHA-512 |
| S2 — First platform | Android. Flutter UI, QR scan, manual entry, list, copy, application lock | **In progress.** Everything but the application lock (FR-31 to FR-36) |
| S3 — Crypto | Vault key, key slots, Argon2id, XChaCha20-Poly1305, recovery key | Not started |
| S4 — Backend | API, PostgreSQL schema, key slots, quotas, enumeration resistance | Not started |
| S5 — Sync | Sync engine, outbox, HLC, conflict resolution, prune watermark | Not started |
| S6 — Other platforms | Remaining platforms, screen capture, tray and menu bar | Not started |
| S7 — Passkeys | `passkeys` package, domain association, PRF slot, fallback | Not started |

## Layout

```
core/            Rust core library (authcore). Every security-critical rule lives here.
  src/
    base32.rs    RFC 4648 decoding for OTP secrets (FR-09)
    otp.rs       TOTP and HOTP engines (FR-01 to FR-05)
    otpauth.rs   otpauth:// URI parser (FR-10, FR-13)
    entry.rs     EntryPayload and folder payloads (section 12.2)
    secret.rs    SecretString: wiped on drop, redacted in Debug (section 9.4)
    hlc.rs       Hybrid logical clock timestamps (section 10.2)
    store.rs     Local SQLite database (section 12.1)
    vault.rs     The payload/record seam and the RecordCipher trait (9.3)
  tests/         RFC vectors, parser, store, vault, end-to-end pipeline

app/             Flutter application
  lib/src/
    pages/       Code list, QR scan, manual entry
    services/    Clipboard auto-clear (FR-24), reference time (FR-38)
    ui/          Countdown ring (FR-07), code display
    rust/        Generated bridge bindings — do not edit by hand
  rust/          The bridge crate. Translation only; no rules.
  rust_builder/  Vendored cargokit. See "Vendored cargokit" below.
  integration_test/
    vault_test.dart  The core, cross compiled, running on a device
    app_test.dart    The real screens against the real core
```

## Build and test

Requires Rust 1.98+, Flutter 3.44+, and the Android SDK with NDK 28.2.

```sh
# Core. --all-features is required: the vault tests need the S2 cipher feature.
cd core
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings

# Application
cd ../app
flutter test                                        # host widget tests
flutter test integration_test -d <device>           # on device, needs the core
flutter build apk --split-per-abi                   # NFR-04, see below
```

`cargo` is at `%USERPROFILE%\.cargo\bin`, which was added to the user PATH.
Terminals opened before that change will not have it.

## What works today

The stage S2 exit criterion — "You can add a real account and sign in to that
service with the code" — is met on Android. The evidence is
`integration_test/vault_test.dart`, which runs the Rust core cross compiled for
Android and checks it against the published RFC vectors on the device rather
than on the host, and `app_test.dart`, which drives the real screens.

Working: the code list with per-second countdowns, QR scanning, manual entry,
copy with a 30 second clipboard clear, search, delete with confirmation,
favourites, HOTP counter advance, and duplicate detection.

## Known gaps, deliberately

- **The application lock is not built** (FR-31 to FR-36). It is listed in S2
  and it is the remaining piece of that stage.
- **Nothing is encrypted.** There is no vault key until S3, so records are
  written as plaintext JSON. This is not silent: `authcore::vault::NullCipher`
  is the only cipher that exists and it sits behind the non-default feature
  `insecure-null-cipher`, which the bridge crate has to name explicitly. When
  S3 deletes that feature the bridge stops compiling and has to be pointed at
  the real cipher. `core/tests/pipeline.rs` also asserts the payload is still
  readable, so S3 must invert that test.
- **SQLCipher is not linked.** Section 12.1 asks for it; it needs the S3 key.
  Android auto-backup is disabled in the manifest so the plaintext database
  cannot leave the device in the meantime.
- No `otpauth-migration://`, Aegis, or `.2fas` import (S8). The scan screen
  recognises a Google Authenticator export code and says so specifically
  rather than reporting an invalid code.

## Local workarounds

Three, all forced by version skew in the toolchain rather than by choice.

**Vendored cargokit.** `app/rust_builder/cargokit/gradle/plugin.gradle` is
third-party code that ships with `flutter_rust_bridge`. It calls
`project.exec {}` from a task action, which Gradle 9 removed, and Flutter 3.44
ships Gradle 9.1 — so every build failed. It is patched to use an injected
`ExecOperations`, which is what `project.exec` delegated to anyway. The patch
is marked `LOCAL PATCH` in the file and will be overwritten if cargokit is
regenerated.

**compileSdk pinned to 36 for all subprojects.** `flutter_secure_storage`
11.0.0 hardcodes `compileSdk = 37`, but no bare `android-37` platform is
published — only `android-37.0` and `android-37.1` — so the request cannot
resolve. Flutter's own default is 36. See `app/android/build.gradle.kts`.

**Kotlin incremental compilation disabled.** Its cache files could not be
closed under this build directory on Windows, failing every plugin compile.
Costs build time and nothing else. See `app/android/gradle.properties`.

## Notes carried forward

- **`applicationId` is `dev.authcore.authenticator` and is provisional.** It is
  the Play listing identity and it must appear in `assetlinks.json` for S7.
  Cheap to change now, painful after either.
- `flutter build apk` alone produces a universal APK that will exceed NFR-04's
  40 MB once the core ships for four ABIs. Use `--split-per-abi`, or
  `flutter build appbundle` for Play. A `splits { abi { … } }` block in gradle
  conflicts with Flutter's own `abiFilters` and breaks the build.
- **`FLAG_SECURE` makes `adb screencap` return the app's frames blank.** That
  is section 9.4 working, not a hang. SurfaceFlinger reports every layer of the
  activity as `(Secure)`. Screenshots for a store listing will need the flag
  temporarily removed on a throwaway build.
- The clipboard clear in FR-24 reads the clipboard back and only clears it if
  it still holds the code it wrote, so it cannot destroy something the user
  copied since. Android clipboard history and some keyboards retain a copy
  regardless — the 30 seconds narrows the window, it does not erase the code.
- An HOTP URI with no counter is refused rather than defaulted to zero. A
  guessed counter is out of step with the issuer from the first code. FR-15d
  covers reporting this during an import.
- `Store::device_id` generates the 64-bit device identifier once and never
  changes it. The section 10.4 tiebreak depends on that.
