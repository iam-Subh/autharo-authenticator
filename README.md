# Cross-Platform Authenticator App

Implementation of the PRD, version 0.11. The build order is the dependency
sequence in section 18: each stage is finished before the next starts.

## Stage status

| Stage | Content | State |
|---|---|---|
| S1 — Core | TOTP, HOTP, Base32, the `otpauth://` parser, SQLite storage | **Done.** RFC 6238 and RFC 4226 vectors pass for SHA-1, SHA-256, and SHA-512 |
| S2 — First platform | Android. Flutter UI, QR scan, manual entry, list, copy, application lock | **Done**, verified on a physical device |
| S3 — Crypto | Vault key, key slots, Argon2id, XChaCha20-Poly1305, recovery key | **Done except database encryption** (below). Device slot, record encryption, password slot, recovery key all built |
| S4 — Backend | API, PostgreSQL schema, key slots, quotas, enumeration resistance | Not started |
| S5 — Sync | Sync engine, outbox, HLC, conflict resolution, prune watermark | Not started |
| S6 — Other platforms | Remaining platforms, screen capture, tray and menu bar | Not started |
| S7 — Passkeys | `passkeys` package, domain association, PRF slot, fallback | Not started |

## The lock releases the key, it does not hide the screen

FR-31: "Locking zeroes the vault key in memory. Do not implement a lock that
only hides the screen." So locking drops the key, and while locked the records
are ciphertext that nothing on the device can read.

With a PIN set, two things are needed to get the key back, per section 9.2.4
step 4:

```
PIN --Argon2id(64 MiB, t=3, p=4)--> KEK --seals--> vault key
                                                       |
                        Android Keystore key --wraps--/  (the sealed blob)
```

The keystore is the **outer** layer, and that ordering is the point. Someone
who copies `meta.db` off the device cannot start guessing the PIN, because
every attempt has to pass a non-exportable hardware key first — which confines
guessing to the device, at its rate. Reverse the two and the PIN-sealed blob
would be exposed the moment the file was read, and six digits is a million
guesses at whatever KDF cost a user will sit through.

Nothing about the PIN is stored in the clear: the salt and the cost parameters
travel *inside* the sealed blob, so `meta.db` reveals only the scheme name.
There is no PIN verifier either — a wrong PIN derives a wrong KEK and Poly1305
refuses the unwrap, which is what OFF-03 asks for without storing a second,
weaker thing to attack.

Turning the PIN on or off rewraps the same vault key. No record is
re-encrypted, so a half-finished change cannot orphan the vault.

### The timeout measures sleep, not taps

FR-33 requires a monotonic clock that counts across device sleep. Three clocks
were available and only one is correct:

| Clock | Why not |
|---|---|
| Wall clock (`DateTime.now`) | The user can set it backwards, which would hold the vault open |
| `CLOCK_MONOTONIC` (Dart's `Stopwatch`) | Stops during deep sleep. A phone in a pocket overnight returns as though no time passed |
| **`SystemClock.elapsedRealtime()`** (`CLOCK_BOOTTIME`) | Counts through both. Chosen |

It resets to zero on reboot, so a reading *lower* than the stored one is
treated as expired — a reboot cannot mean less time passed.

FR-33a puts the policy in `meta.db`, which is the unencrypted file, because the
application has to know whether it may open without asking *before* it opens
anything. A setting that reset at every start would do nothing.

FR-33a in 0.10 makes this explicit: the file holds the *whole* lock policy —
the timeout, FR-34's background flag, and any later lock option — and no secret
and no vault content.

## The vault is now encrypted at rest

Section 9.2.4's device slot is built, so a local-only vault is encrypted even
though no sync account exists. The chain is:

```
Android Keystore key (non-exportable, StrongBox where present)
  wraps -> vault key (256-bit, generated on first run)
             |- HKDF "record"    -> XChaCha20-Poly1305 over each entry payload
             \- HKDF "database"  -> derived, ready, and currently unused
```

Section 12.1 defines two layers doing different jobs, and is explicit that one
is not a substitute for the other:

| Layer | Protects | Status |
|---|---|---|
| Record encryption (XChaCha20-Poly1305, §9.3) | The secret, the issuer, the account name | **Linked and verified on-device.** Mandatory |
| Database encryption (§12.1) | The row structure: entry count, change times, the device identifier in each HLC | **Not linked.** Defence in depth; see below |

Neither subkey is the vault key and neither is the other, so a weakness in one
construction stays there. The second key is derived and unused rather than
absent, so linking a library is a dependency change, not a redesign.

### Database encryption is not linked

Section 12.1 asks that the chosen library and the reason be recorded here. The
honest record is that there is no page-encrypting build linked today, and the
reason is worth writing down because it was not obvious.

SQLCipher (`bundled-sqlcipher-vendored-openssl`) was linked and **working on
the host**: `core/tests/store.rs` asserted on the file's bytes and confirmed no
`SQLite format 3` header and a file that refused to open unkeyed or under a
wrong key. Getting there needed Strawberry Perl, since OpenSSL's `Configure` is
a Perl program that Git Bash's cut-down Perl cannot run.

It was then removed, because **it cannot cross-compile to Android from
Windows**. OpenSSL's `android-arm64` configuration wants a compiler named
`aarch64-linux-android-clang`; the Windows NDK ships
`aarch64-linux-android26-clang.cmd`, and `Configure` exits 255. Android is the
platform that ships, so a database layer that only works on the development
host is not the layer section 12.1 is asking for.

Worse, the failure was quiet. Cargokit's error did not fail the gradle build,
so the APK was packaged with the **previous** `librust_lib_authenticator.so` and
reported success. See "Verify the build" below for what now catches that.

**The way back is SQLite3 Multiple Ciphers**, which section 12.1 names: it
carries its own crypto, needs no OpenSSL and therefore no Perl, and supports
ChaCha20, which the core already uses. No `rusqlite`-compatible crate wraps it
today, so it means vendoring the amalgamation and compiling it with `cc` — but
`cc` already cross-compiles cleanly with the NDK clang cargokit configures,
which is exactly the step OpenSSL fails at.

What this costs meanwhile, from section 12.1's table: the entry count, the
change times, and the device identifier inside each HLC are visible in
`vault.db`. **No secret, issuer, or account name is** — the record layer is
mandatory, is linked, and is verified on-device by reading the file back off
the phone's flash. Section 12.1: "The database layer is defence in depth. Ship
it, but do not block the record layer on it."

`VaultKey::sqlcipher_key` and `Store::open`'s key parameter are kept, so
relinking is a dependency change rather than a redesign.
`core/tests/store.rs` asserts the gap rather than hiding it: one test fails the
moment the file stops having a plain SQLite header, which is the signal to
invert it.

## The account slots

Sections 9.2.1 and 9.2.3, built locally. No server exists until S4, so the
slots are created and stored ready to upload, and nothing is sent.

The rule with the worst failure mode is section 9.2.4's: **creating an account
must not generate a new vault key**. Every entry is already encrypted under the
device slot's key, so a fresh one would leave all of them unreadable with
nothing to announce it. `create_account` therefore takes the existing key as an
argument — there is no code path in `account.rs` that makes one — and both a
host test and an on-device test add an entry *before* sign-up and check it is
still readable after.

| Piece | Where | Note |
|---|---|---|
| Argon2id salt | Generated locally, 128 bits, stored with the slot | Never derived from the email address (§9.2.1). Two accounts with the same address get different salts, and a test asserts it |
| Master key | Argon2id, 64 MiB / 3 / 4 | Parameters stored with the slot, so raising them later stays compatible |
| Authentication key | HKDF `auth`, derived on demand | **Never stored.** It exists only to be sent, and there is nowhere to send it yet |
| KEK | HKDF `kek` | Never leaves the device. Wraps the vault key |
| Recovery key | Random 256-bit, 24 BIP-39 words | Shown once, never stored. Three random positions to confirm (§9.2.3 step 4) |

A test wraps with the recovery key, unwraps, and compares the vault key
**byte for byte**. A recovery path that returns a valid but different key would
pass every other test and fail only when someone finally needed it.

A typo in the phrase is reported as a typo, not as a wrong vault: BIP-39's
checksum catches it, and the difference matters — one message says check your
spelling, the other says your vault is gone.

**No sign-up screen yet, deliberately.** §16.2 is "enable sync later", and
there is no sync to enable. The recovery slot exists for synced accounts only;
a local-only vault explicitly cannot be recovered (§9.2.4). Building the screen
now would mean building it against an account flow S4 has not settled. The
derivation is done and tested so S4 inherits it.

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
    pin.rs          Argon2id over the PIN, and FR-31's rules
    lock_policy.rs  FR-33a: the lock policy, readable before the vault opens
    account.rs      Password and recovery slots (9.2.1, 9.2.3)
    hlc.rs          Hybrid logical clock timestamps (section 10.2)
    store.rs        meta.db and vault.db (section 12.1)
    vault.rs        The payload/record seam and the RecordCipher trait (9.3)

app/             Flutter application
  lib/src/services/
    vault_keystore.dart   Channel to the Android Keystore
    vault_session.dart    Open, lock, and wipe: the three-way handshake
    lock_controller.dart  FR-33 and FR-34: when the vault locks itself
    monotonic_clock.dart  FR-33's clock, and why the other two are wrong
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

Requires Rust 1.98+, Flutter 3.44+, and the Android SDK with NDK 28.2.

No Perl is needed. It was, briefly, while SQLCipher was linked; see "Database
encryption is not linked" for why that came back out.

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

### Two guards on the native build (NFR-13)

A stale `.so` was packaged and reported as a successful build, and three
reports in a row were wrong because of it. `--contains` catches the symptom.
These two catch the cause.

**The exit code now propagates.** `run_build_tool.cmd` returned the status of
its last command, which was an `If` that succeeds whether or not the build
failed. So `build_tool.dart` called `exit(1)`, gradle's `exec` would have
thrown on a non-zero status — and the wrapper between them turned the failure
into a success. It now ends in `exit /b %TOOL_EXIT%`. `run_build_tool.sh`
already did this, so the defect was Windows-only, which is why it survived
upstream. Verified by breaking the Rust build on purpose and watching gradle
fail.

**The library is stamped.** `app/rust/build.rs` compiles in the git commit, a
dirty flag, and a build timestamp; `build_info()` returns them. A device test
compares the commit against the source it should have been built from:

```sh
flutter test integration_test -d <device>   --dart-define=EXPECTED_COMMIT=$(git rev-parse HEAD)
```

A mismatch fails the test naming both hashes. This is the guard that keeps
working when the packaging path changes again, because it does not depend on
knowing which step went wrong — it asks the library what it is. A build from a
dirty tree cannot be matched to a commit, so the test falls back to checking
the library's age and says that is what it did.

### Verify the build, do not trust the log

`flutter build apk | tail -20` reports the exit status of `tail`. A failed
build reads as a successful one, and it did: a broken build was reported here
as working until the artifact was checked by hand.

`scripts/verify_build.sh` checks both halves — the build tool's exit status,
and that the artifact exists and was written by *this* run rather than left
over from an earlier one.

It also checks *inside* the artifact, which the first version did not, and that
gap cost real time. An APK is a container: when the Rust step failed, gradle
still produced a valid, newer APK carrying the previous `.so`, and the script
passed it. Use `--contains` for anything whose contents matter:

```sh
sh ../scripts/verify_build.sh --contains librust_lib_authenticator.so   build/app/outputs/flutter-apk/app-debug.apk -- flutter build apk --debug
```

## Known gaps, deliberately

- **FR-35 counts failures but does not act on them.** The wipe after ten
  failed attempts is P1 and off by default; the counter and the warning exist,
  the automatic wipe does not.

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
