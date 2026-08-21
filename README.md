# Cross-Platform Authenticator App

Implementation of the PRD, version 0.7. The build order is the dependency
sequence in section 18: each stage is finished before the next starts.

## Stage status

| Stage | Content | State |
|---|---|---|
| S1 — Core | TOTP, HOTP, Base32, the `otpauth://` parser, SQLite storage | **Done.** RFC 6238 and RFC 4226 vectors pass for SHA-1, SHA-256, and SHA-512 |
| S2 — First platform | Android. Flutter UI, QR scan, manual entry, list, copy, application lock | **All but the lock interface.** The lock mechanism exists; the PIN, the timeout, and the biometric prompt do not |
| S3 — Crypto | Vault key, key slots, Argon2id, XChaCha20-Poly1305, recovery key | **Device slot, record encryption, and SQLCipher done.** Password and recovery slots not started |
| S4 — Backend | API, PostgreSQL schema, key slots, quotas, enumeration resistance | Not started |
| S5 — Sync | Sync engine, outbox, HLC, conflict resolution, prune watermark | Not started |
| S6 — Other platforms | Remaining platforms, screen capture, tray and menu bar | Not started |
| S7 — Passkeys | `passkeys` package, domain association, PRF slot, fallback | Not started |

## The vault is now encrypted at rest

Section 9.2.4's device slot is built, so a local-only vault is encrypted even
though no sync account exists. The chain is:

```
Android Keystore key (non-exportable, StrongBox where present)
  wraps -> vault key (256-bit, generated on first run)
             |- HKDF "record"    -> XChaCha20-Poly1305 over each entry payload
             \- HKDF "sqlcipher" -> SQLCipher over the whole vault.db file
```

Two layers, two keys. SQLCipher covers the file — the schema, the row count,
the change times, the device identifier in each HLC. The record cipher covers
each payload inside it. Neither key is the vault key and neither is the other,
so a weakness in either construction stays where it is.

The wrapped vault key lives in `meta.db`, which is deliberately unencrypted:
it holds the key that opens `vault.db`, so it cannot live inside it. That split
is enforced by the types — `MetaStore` opens alone, and `Store` cannot be built
without one.

The evidence is on-device, in `integration_test/vault_test.dart`, against a
real Android Keystore rather than a stub: it adds an entry, then reads
`vault.db` back off the device's flash and fails if the secret, the issuer, the
account name, or even a payload field name appears in it.

## Layout

```
core/            Rust core library (authcore). Every security-critical rule lives here.
  src/
    base32.rs       RFC 4648 decoding for OTP secrets (FR-09)
    otp.rs          TOTP and HOTP engines (FR-01 to FR-05)
    otpauth.rs      otpauth:// URI parser (FR-10, FR-13)
    entry.rs        EntryPayload and folder payloads (section 12.2)
    secret.rs       SecretString: wiped on drop, redacted in Debug (section 9.4)
    crypto.rs       Vault key, HKDF subkeys, XChaCha20-Poly1305 records (9.2, 9.3)
    device_slot.rs  The device slot state machine (9.2.4)
    hlc.rs          Hybrid logical clock timestamps (section 10.2)
    store.rs        meta.db and vault.db (section 12.1)
    vault.rs        The payload/record seam and the RecordCipher trait (9.3)

app/             Flutter application
  lib/src/services/
    vault_keystore.dart   Channel to the Android Keystore
    vault_session.dart    Open, lock, and wipe: the three-way handshake
  lib/src/rust/           Generated bridge bindings — do not edit by hand
  android/.../VaultKeystore.kt   The non-exportable wrapping key
  rust_builder/           Vendored cargokit. See "Local workarounds".
  integration_test/
    vault_test.dart       The core on a device, and the bytes it writes to flash
    app_test.dart         The real screens against the real core

scripts/
  verify_build.sh         Checks a build's exit status AND its artifact
```

## Build and test

Requires Rust 1.98+, Flutter 3.44+, the Android SDK with NDK 28.2, and a
**Windows Perl** — SQLCipher is built against vendored OpenSSL, and OpenSSL's
`Configure` is a Perl program that Git Bash's cut-down Perl cannot run.
Strawberry Perl works; put `C:/Strawberry/perl/bin` ahead of Git Bash's
`/usr/bin` on PATH, or `Configure` picks the wrong one and fails with
`IPC/Cmd.pm` errors that do not mention Perl at all.

The first build of OpenSSL takes about ten minutes per target and is cached
afterwards.

```sh
cd core
cargo test
cargo clippy --all-targets -- -D warnings

cd ../app
flutter test                                        # host widget tests
flutter test integration_test -d <device>           # on device, needs the core

# Always through the script, never `flutter build ... | tail`:
sh ../scripts/verify_build.sh build/app/outputs/flutter-apk/app-debug.apk -- \
  flutter build apk --debug
```

`cargo` is at `%USERPROFILE%\.cargo\bin`, which was added to the user PATH.
Terminals opened before that change will not have it.

### Verify the build, do not trust the log

`flutter build apk | tail -20` reports the exit status of `tail`. A failed
build reads as a successful one, and it did: a broken build was reported here
as working until the artifact was checked by hand.

`scripts/verify_build.sh` checks both halves — the build tool's exit status,
and that the artifact exists and was written by *this* run rather than left
over from an earlier one. Use it for anything whose success matters.

## Known gaps, deliberately

- **The application lock has a mechanism but no interface.** `lock_vault`
  genuinely drops the vault key rather than hiding the screen, and the
  integration tests prove the entries become unreachable while locked. What is
  missing is FR-31's PIN, FR-33's timeout, and FR-32's biometric prompt. The
  `keystore-pin-v1` scheme is defined and refused at startup rather than
  silently treated as an ordinary slot.

- **The vault key crosses into Dart.** A non-exportable keystore key can only
  be driven from platform code, so the raw key passes through Dart once at
  setup and once at each unlock. Dart cannot wipe memory the way `Zeroizing`
  can — `VaultKeystore.wipe` overwrites the buffer we own and returns false
  when handed an unmodifiable channel buffer it cannot touch. Closing this
  means calling the keystore from Rust over JNI, which needs a handle to the
  JVM that `flutter_rust_bridge` does not currently hand out.

- **No password slot, no recovery key.** Sections 9.2.1 and 9.2.3, needed
  before S4. Argon2 is already a dependency.

- No `otpauth-migration://`, Aegis, or `.2fas` import (S8).

## Local workarounds

**Vendored cargokit.** `app/rust_builder/cargokit/gradle/plugin.gradle` is
third-party code shipped with `flutter_rust_bridge`. It called `project.exec {}`
from a task action, which Gradle 9 removed, and Flutter 3.44 ships Gradle 9.1 —
so every build failed. It is patched to use an injected `ExecOperations`.

Regenerating the bridge overwrites that directory and silently reverts the
patch, and the resulting build failure names nothing about cargokit. So
`app/test/cargokit_patch_test.dart` fails loudly if `project.exec` reappears at
a call site, or if the replacement or the `LOCAL PATCH` marker goes missing.
Re-apply the patch rather than deleting the test.

**compileSdk pinned to 36 for all subprojects.** `flutter_secure_storage`
11.0.0 hardcodes `compileSdk = 37`, but no bare `android-37` platform is
published — only `android-37.0` and `android-37.1` — so the request cannot
resolve. Flutter's own default is 36.

*Revisit when a bare `android-37` platform publishes* — check with
`sdkmanager --list | grep "platforms;android-37"` for an entry with no minor
version — or when `flutter_secure_storage` stops pinning 37. Until one of those
happens the pin must stay, and raising it will fail the same way.

**Perl must come from Strawberry, not Git Bash.** Covered under "Build and
test" above; repeated here because the failure names `IPC/Cmd.pm` and gives no
hint that the wrong Perl is on PATH.

**Kotlin incremental compilation disabled.** Its cache files could not be
closed under this build directory on Windows, failing every plugin compile.
Costs build time and nothing else. See `app/android/gradle.properties`.

## Notes carried forward

- **`applicationId` is `dev.authcore.authenticator` and is provisional.** It is
  the Play listing identity and must appear in `assetlinks.json` for S7. Cheap
  to change now, painful after either.
- **The stage S2 plaintext database is discarded, not migrated.** Development
  data only, and a migration would have to read every plaintext secret and
  rewrite it, leaving plaintext in the old file's free pages if it failed part
  way. `discard_legacy_plaintext_vault` detects the S2 layout structurally — an
  S2 vault has a `meta` table inside it, an S3 vault never does — and deletes
  the file along with its journal and write-ahead copies.
- **Losing the keystore key loses the vault.** Clearing the application's data,
  reinstalling, and on some devices removing the screen lock destroy the
  wrapping key, and the wrapped vault key becomes permanently unopenable. That
  is inherent to a local-only vault, and it is why section 9.2.4 warns that a
  synced account can be restored and a local-only one cannot.
- `flutter build apk` alone produces a universal APK that will exceed NFR-04's
  40 MB. Use `--split-per-abi`, or `flutter build appbundle` for Play. A
  `splits { abi { ... } }` block conflicts with Flutter's own `abiFilters`.
- **`FLAG_SECURE` makes `adb screencap` return the app's frames blank.** That
  is section 9.4 working, not a hang — SurfaceFlinger reports every layer of
  the activity as `(Secure)`. Store screenshots need the flag temporarily
  removed on a throwaway build.
- The clipboard clear in FR-24 reads the clipboard back and only clears it if
  it still holds the code it wrote. Android clipboard history and some
  keyboards retain a copy regardless.
- An HOTP URI with no counter is refused rather than defaulted to zero. FR-15d
  covers reporting this during an import.
- `MetaStore::device_id` generates the 64-bit device identifier once and never
  changes it. The section 10.4 tiebreak depends on that.
