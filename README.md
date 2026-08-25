# Cross-Platform Authenticator App

Implementation of the PRD, version 0.22. The build order is the dependency
sequence in section 18: each stage is finished before the next starts.

## Stage status

| Stage | Content | State |
|---|---|---|
| S1 — Core | TOTP, HOTP, Base32, the `otpauth://` parser, SQLite storage | **Done.** RFC 6238 and RFC 4226 vectors pass for SHA-1, SHA-256, and SHA-512 |
| S2 — First platform | Android. Flutter UI, QR scan, manual entry, list, copy, application lock | **Done**, verified on a physical device |
| S3 — Crypto | Vault key, key slots, Argon2id, XChaCha20-Poly1305, recovery key | **Done.** Device slot, record encryption, page encryption, password slot, recovery key |
| S4 — Backend | API, PostgreSQL schema, key slots, quotas, enumeration resistance | **In progress.** Exit criterion met; sign-up UI built. No sync engine — that is S5 |
| S5 — Sync | Sync engine, outbox, HLC, conflict resolution, prune watermark | **In progress.** Cycle, HLC with a drift bound, deferred HOTP reconcile, full re-sync, and a seeded property harness. Not yet wired into the app |
| S6 — Other platforms | Remaining platforms, screen capture, tray and menu bar | Not started |
| S7 — Passkeys | Android Credential Manager bridge, ceremony schema, domain association, PRF slot, fallback | **In progress.** Native bridge and schema are present; production domain and WebAuthn verification remain |

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

### Database library: SQLite3 Multiple Ciphers

Section 12.1 asks that the chosen library and the reason be recorded here.

**Chosen: SQLite3 Multiple Ciphers 2.5.0** (SQLite 3.53.4), vendored as a C
amalgamation in `sqlite3mc-sys/vendor/` and compiled with `cc`.

**Why not SQLCipher.** It was linked first and worked on the host, then came
out: its vendored OpenSSL cannot cross-compile to Android from Windows.
OpenSSL's `Configure` wants a compiler named `aarch64-linux-android-clang`, the
Windows NDK ships `aarch64-linux-android26-clang.cmd`, and `Configure` exits
255. SQLite3MC has no OpenSSL, no Perl, and no `Configure` — one C file and
`cc`, which cross-compiles with the NDK clang cargokit already sets up. That is
the exact step OpenSSL failed at, and it is why the Perl dependency is gone.

**How it takes over.** `rusqlite` is used without `bundled`, so
`libsqlite3-sys` compiles no SQLite and only emits the link request; its
default features use pregenerated bindings, so no header and no bindgen are
needed. `sqlite3mc-sys` produces the `sqlite3` static library that request
resolves to.

#### The five rules from section 12.1, and where each one lives

| Rule | Where it is enforced |
|---|---|
| 1. Test the bytes, not the open | `core/tests/store.rs` asserts the file has no `SQLite format 3` header, refuses an unkeyed open, refuses a wrong key, and refuses to adopt a leftover plaintext file. An on-device test asserts the header too |
| 2. Set the cipher and KDF explicitly | `PRAGMA cipher = 'chacha20'` and `PRAGMA kdf_iter = 64007` in `apply_encryption`, before the key. Never the default |
| 3. `temp_store` in memory | `SQLITE_TEMP_STORE=3` at compile time — always memory, not overridable — plus the PRAGMA |
| 4. Wipe, do not migrate | `discard_unencrypted_vault` deletes any vault whose header is plain SQLite, with its journal and WAL |
| 5. One SQLite only | `sqlite3mc-sys` declares `links = "sqlite3mc"` and its build script panics if `bundled` reappears. `cargo tree` shows a single `libsqlite3-sys` |

**Rule 1 is the one that matters here.** SQLite3MC opens an unencrypted
database *transparently*: if the key were never applied, or applied wrongly,
the old plaintext file would open and every query would work. A test that
checks the database opens proves nothing. Only the header does.

Rule 2 has a second consequence worth stating: the key is supplied with
`PRAGMA hexkey`, not `PRAGMA key`. `key` would treat the hex as a passphrase
and run it through the KDF, deriving a different key — and every existing
vault would stop opening.

**One-time effect of rule 4.** The first run after this change found a
plaintext vault on the test device and deleted it, along with `meta.db` and the
device slot inside it. That is the intended behaviour and it is why the first
device run after the switch showed failures partway through: the vault the
earlier tests had opened no longer existed. Runs after it are stable.

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

**No sign-up screen yet, deliberately — and it is an S4 deliverable.** §16.2
is "enable sync later", and there is no sync to enable. The recovery slot
exists for synced accounts only; a local-only vault explicitly cannot be
recovered (§9.2.4). Building the screen now would mean building it against an
account flow S4 has not settled.

Both are now built. FR-29 and FR-55 show the 24 words once, numbered, with the
warning that they cannot be shown again; §9.2.3 step 4's three-word
confirmation gates the end of sign-up, at the positions the core picked at
random. Eight widget tests cover the gate, including that a wrong word names
its position and does not complete sign-up.

FR-29's second half is now built too, as **rotation rather than reprinting** —
see the backup section below for why that is the only honest version of it.

## Backup and export (FR-26 to FR-29, FR-36)

Microsoft Authenticator will not export its secrets. The stated reason is
security; the effect is that leaving it means retyping every account by hand.
An authenticator holds the keys to everything its user owns, and one that makes
those hard to move is holding them hostage. So this app can be left, and that
is why FR-27's plain-text export exists despite being the most dangerous action
in the application.

`core/src/backup.rs` writes two kinds of file:

| Kind | FR | Protection |
|---|---|---|
| Encrypted | FR-26 | Argon2id (64 MiB, t=3, p=4) then XChaCha20-Poly1305 |
| Plain | FR-27 | None, and the filename says so |

FR-28 reads both back. FR-36 is the `with_vault` guard: every export path fails
while locked, the same gate `reveal_secret_for_export` already sat behind.

**The derivation parameters are written into the file.** §12.1 rule 2 in the
export direction, and reading Aegis is what taught it: their exports carry the
scrypt cost precisely so raising it does not orphan an old backup, and a reader
that assumed a value would fail on every newer file — reporting a *wrong
password*, on a correct password. `a_file_written_with_other_parameters_still_opens`
holds it, and reverting `read` to `KdfParams::default()` fails that test and
only that test.

### Two dangers, pulling opposite ways

A backup can leak, or it can fail to exist. The safest backup is the one nobody
made, which is why leaning entirely on the first danger is how you end up with
Microsoft's design.

Leaking is what users can see afterwards, so it gets the friction: FR-27's
export is behind two dialogs, and the second cannot be tapped through — it asks
the user to type `EXPORT`, because a second identical "are you sure" is one
dialog with an extra tap, and the reflex that dismissed the first dismisses the
second. `test/plain_export_gate_test.dart` holds this with eight tests; deleting
the second dialog fails five of them.

Failing to exist is what actually loses the vault, so nothing here hides behind
an expert-mode toggle, and an empty vault **refuses** to produce a backup rather
than writing an empty one — a file with no accounts in it is indistinguishable
from a working one until the day it is needed.

### FR-29 rotates, it does not reprint

The recovery phrase *is* the recovery key — 256 bits encoded as 24 BIP-39 words
— and §9.2.3 stores only the vault key sealed under it. That direction does not
run backwards, so there is no old phrase to fetch, and a function claiming to
reprint one would have had to keep it.

Rotation is the honest version, and the better one: a user asking for their
phrase again has lost their copy, destroyed it, or had it seen. In all three the
right answer is a new phrase with the old one dead. The new slot is saved
*before* the phrase is returned, so there is no window where the user has been
shown words that were never stored.

### What the device proves

`integration_test/backup_test.dart` asserts on the restored **codes**, not on
counts. An entry round-trips with the right name and a mangled secret while the
report cheerfully says "1 imported"; only the code at t=59 catches that. It also
asserts absence on the exported bytes — no secret, no issuer, no account name —
in the same shape as the check that the server database holds no plaintext.

## Devices and account safety (§9.5)

The question this answers is "I lost my phone". Until it existed the honest
answer was that nothing could be done: the vault on that device is encrypted
behind a hardware key, so it is not an emergency — but it holds a refresh token
good for thirty days, and every change made anywhere else keeps syncing to it.

On Android, that session pair does not live in `meta.db`. Kotlin encrypts both
tokens as one AES-256-GCM value under a non-exportable Android Keystore key.
Rust calls that store through JNI, so Dart never receives the tokens. The key
does not require biometric approval because background sync must work while the
application vault is locked. An older plaintext pair is migrated once and its
metadata rows are deleted with SQLite `secure_delete` enabled. The next online
operation also forces refresh-token rotation. The server then revokes the old
pair, including copies recovered from an old journal or storage block.

| Route | Does |
|---|---|
| `GET /v1/devices` | Lists every device, revoked ones included |
| `DELETE /v1/devices/{id}` | Revokes one and ends its sessions in the same request |
| `POST /v1/auth/logout` | Ends the calling session |
| `POST /v1/auth/logout-all` | Ends every session on the account |
| `DELETE /v1/account` | Deletes the account and everything under it |

**A revoke has to bite immediately.** A device that keeps working for another
fifteen minutes has not been revoked, because those fifteen minutes are the
whole reason someone pressed the button. So the update marks the device and
kills its sessions in one request, `refresh` refuses a revoked device rather
than minting tokens it cannot use, and `session_for_token` joins to `device` so
a session that somehow survived is still refused.

**Revoked devices stay in the list.** Someone checking whether the lost phone is
really cut off needs to see it listed as cut off. A list that has simply stopped
mentioning it proves nothing.

**Deleting the account does not delete the codes.** The most confusable pair in
the product. Deleting a sync account means "stop storing my encrypted blobs" —
the codes on the device keep working. Wiping the device is a different action on
a different screen; putting the two most destructive operations behind one button
would make the wrong outcome unrecoverable in both directions.

**Deletion requires the password, not just the session.** A stolen access token
is exactly the situation the rest of this section exists for, and whoever holds
one must not be able to destroy the account its owner is trying to save. There
is no soft delete: the server cannot decrypt a record, so a "recoverable"
account would be an encrypted blob whose key the user has already been told to
destroy — kept only to be stolen later.

## The server (S4)

Axum over PostgreSQL 16, per section 14.2. `server/` is its own crate, run
against a development database in Docker:

```sh
docker run -d --name authcore-pg -e POSTGRES_PASSWORD=devonly   -e POSTGRES_USER=authcore -e POSTGRES_DB=authcore -p 15432:5432 postgres:16-alpine
cd server && cargo run
```

Port 15432 rather than 55432: Windows reserves 55400–55499, and Docker's bind
fails there with a permissions error that does not mention the reservation.
`netsh interface ipv4 show excludedportrange protocol=tcp` lists the ranges.

Migrations are numbered from `0001` and applied by sqlx at startup, embedded at
compile time so a deployment cannot run against a schema it was not built for.
`0002` adds the session table as its own step rather than an edit to `0001` —
S7 will alter `key_slot` the same way.

### The exit criterion, and the test that nearly did not work

The criterion is that a database dump holds no plaintext issuer, account name,
or secret. `server/tests/dump.rs` runs the whole sign-up and record push, then
searches `pg_dump` output — the artifact the criterion is about, rather than
the endpoints, because an endpoint can be correct while the database still
holds something it should not.

**The first version passed while the server leaked everything.** It had a
control — a marker stored in the clear and asserted present, so a broken search
would be caught. But the control was a device name, a `text` column that
`pg_dump` writes as readable text, while the secret lives in
`record.ciphertext`, a `bytea` column that `pg_dump` writes as hex. An ASCII
search could not see a plaintext secret at all. Pushing the payload unencrypted
on purpose produced a **passing** test.

Two fixes: the search now looks for each marker as literal text *and* as the
hex a `bytea` dump carries, and there is a second control written into the
`bytea` column itself. Both were re-verified the way the fault was found — with
the payload pushed in the clear the test fails naming the secret, and with it
sealed it passes.

The lesson generalises: a control has to be in the same column type, and
through the same path, as the thing it is standing in for.

### Enumeration resistance has two halves

Section 9.5 is easy to half-build. The body and the timing both have to match:

| Half | How |
|---|---|
| Body | The fabricated salt is an HMAC over the normalised address with a server-held key: stable per address, unpredictable without the key, and the same 128-bit length as a real one |
| Timing | Both paths are padded to a fixed floor above either branch. A matching body with a distinguishable response time still answers the question |

The test compares status, response shape, salt length, parameters, stability
across two calls, and elapsed time over five requests each.

`SERVER_KEY` is required in a release build. A key generated at startup would
change the fake salts on every restart — and a real account's salt does not
change, so the instability would itself be the answer.

If a reverse proxy terminates HTTPS, set `TRUSTED_PROXY_CIDRS` to the proxy
socket networks. Separate multiple CIDRs with commas. For example:

```text
TRUSTED_PROXY_CIDRS=10.0.0.0/24,fd00:1234::/64
```

Do not put public client networks in this value. The server ignores
`X-Forwarded-For` when the direct socket peer is outside these networks.

### What is deliberately absent

The sync engine. S4 ends at the dump test; the cycle, the conflict rules in
section 10.4, and the outbox drain are S5, with a 1000-operation convergence
test of their own. The record endpoints store rows and report a base-revision
mismatch — they do not merge.

## The convergence harness (S5)

`core/tests/harness/` drives three devices through random adds, counter bumps,
deletes, syncs, locks, unlocks, partitions, prunes and replayed pushes, then
syncs everything to quiescence and asserts that the devices agree, and that
what they agree on is right.

Run it:

```sh
cd core
cargo test --test convergence                       # 1 000 operations, six seeds
CONVERGENCE_OPS=100000 cargo test --release --test convergence -- --ignored --nocapture

# Over the real transport. Needs the development database and a server on it.
cargo run -p authserver &
cargo test --test convergence_http -- --ignored --nocapture
```

The hundred-thousand-operation run takes about nine seconds and produces, for
one seed, 1 988 conflicts, 492 of them three-way, 848 stale cursors, 848 full
re-syncs, 2 791 replayed pushes and 343 counters corrected.

Every failure prints its seed and a shrunk operation trace, so a hundred
thousand operations reduce to something short enough to read. Everything random
comes from that seed, including the record nonces and the device identifiers —
a run that reached for the operating system anywhere would not replay.

### Three ways a property test lies, and what stops each

**It passes because it never reached the interesting case.** So every event that
makes a run meaningful is counted, and the run fails naming the one that did not
happen often enough. That floor came first, before the oracle and before the
invariants, because without it they both report success on a run that produced
no conflict. It has since failed three times for three different reasons — a
generator whose partitions healed faster than they opened, so nothing diverged
far enough for the counter rule to correct; a hundred-thousand-operation run
that deleted all eight of its entry identifiers within a few hundred operations
and spent the remaining ninety-nine thousand doing nothing; and a run that was
simply too short. None of those would have shown up as a failure.

**It checks the devices against each other.** Three devices can converge on a
state that has lost an entry, and every convergence invariant still passes. So
there is a model outside the implementation: the entry set is every add minus
every delete, and each counter is the largest any device ever wrote. The devices
are checked against each other and then against that.

**The transport hides the wire.** `SyncTransport` hands `WireRecord` values
straight across in the in-memory run, so no amount of it says anything about
serialisation, base64url, UUID parsing, or status codes.
`core/tests/convergence_http.rs` runs the same harness — the same operations,
the same invariants, the same oracle — against a real server over real HTTP.

### What it found

Five things, each of which would have been quiet in production. The last two
needed scale: they appear only past forty thousand operations, once the vault
crosses one page of records.

1. **A record coming back unchanged was treated as a conflict.** A push does not
   move the cursor, so the next pull returns what the device just sent. That was
   recorded as a discarded rival version, and section 10.4 step 5 stops an entry
   with one outstanding from producing a code. Every HOTP entry a device had
   pushed refused to produce a code until the next unlock — permanently, on a
   device that is never locked. Nothing looked wrong: the records agreed and the
   counters agreed. One `Add` reproduced it. Fixed in `sync::apply_remote`.

2. **A conflict resolved while unlocked was never reconciled.** Section 10.4
   defers the counter rule because the cycle may have no key. A cycle on an
   unlocked device has one, and deferring there left the candidate waiting for
   an unlock that was not coming. `Vault::sync` now runs the reconcile at the
   end of a cycle, so the deferral lasts exactly as long as the absence of a key.

3. **A stale cursor resurrected a deleted entry.** A cursor goes stale because
   the device has been away, and a device that has been away is the one with
   local changes still waiting. The full re-sync replaced every record with the
   server's, so an unpushed tombstone vanished and the server's live copy came
   back — which section 10.4 forbids outright. Six operations reproduced it.
   `sync::full_resync` now applies the server's records through the ordinary
   rules and drops a local record only if the server does not have it *and* this
   device is not waiting to push it. `Store::replace_all` keeps the old wholesale
   behaviour for **Wipe and re-download**, where the user asked for exactly that.

4. **The stale cursor was a `409`.** The same status and the same `conflict`
   error code as "this email is already registered", separated only by the
   message string. A client that guessed wrong either re-syncs for nothing or
   loops forever on a cursor it can never advance. It is `410 Gone` under
   `cursor_too_old` now. Only the HTTP run could find this: the in-memory
   transport returns `SyncError::CursorTooOld` directly and no status is
   involved. Held by `server/tests/stale_cursor.rs` on one side and
   `only_a_410_means_the_cursor_is_unusable` on the other.

5. **A full re-sync could not read its own second page.** The prune-watermark
   check exists to tell a *lagging* client it may have missed a delete. It was
   applied to every cursor — including the ones a re-sync walks through on its
   way up from zero, which are below the watermark by construction. So page one
   was served and page two was refused with a 410, and `full_resync` failed
   before storing a cursor, so the next attempt began at the same place and
   failed identically. **The device never synced again**, kept making local
   changes, never saw anyone else's, and reported nothing a user would notice.
   Under five hundred records a re-sync is a single request from zero and none
   of it happens, which is why every smaller test passed. `pull` now carries a
   `PullMode`, and the server a matching `full` parameter — a parameter rather
   than a second method, so no transport can be written that forgets to
   distinguish them. Both halves are pinned, and both tests were checked to fail
   without their fix.

### What it does not cover

Nothing in the HTTP run can move the server's prune watermark — no endpoint
writes it, and the test holds no database connection — so the stale-cursor and
full-re-sync parts of the floor are switched off there through
`Backend::can_prune` rather than quietly left at zero. Those rules are exercised
against the in-memory server, which can, and the 410 itself is pinned by the two
directed tests above.

Clock drift is kept under section 10.2's five-minute bound on purpose. A clamped
timestamp is *stored* clamped, so two devices that disagreed about whether to
clamp would hold different timestamps for one record and no amount of syncing
would fix it. That rule has its own tests in `core/tests/sync.rs`; mixing the two
questions would mean neither failure named itself.

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

One command runs every gate below, and is the one to use:

```sh
sh scripts/check_all.sh                 # add --device <id> for the on-device tests
```

It exists because the individual commands are correct and nobody runs all six.
Two of them also take arguments that are wrong in a way that still exits zero —
see the comments in the script. Each gate has been proved by breaking something
it should catch and watching it fail: a failing core test, a clippy lint, an
error reachable only from `integration_test/`, a failing widget test, a
forgotten bridge regeneration, and a stopped database.

The individual commands, for when only one matters:

```sh
cd core
cargo test
cargo clippy --all-targets -- -D warnings

# The server's tests need the development database running.
cd ../server && cargo test

cd ../app
# --no-fatal-infos, and no path.
#
# No path, because `flutter analyze lib/ test/` silently skips
# `integration_test/`. That is how a required parameter added to the bridge
# reached a phone: every analyze was green, over a subset that did not include
# the caller that broke.
#
# --no-fatal-infos, because a bare `flutter analyze` exits non-zero on
# info-level lints, of which this project has several deliberate ones. A gate
# that always fails is a gate everyone learns to skip, and then it is not
# catching the errors either.
flutter analyze --no-fatal-infos
flutter test                                        # host widget tests
flutter test integration_test -d <device>           # on device, needs the core

# Generated code must match the Rust API. `flutter_rust_bridge` dispatches on
# numeric identifiers rather than exported symbols, so a forgotten regeneration
# builds green and leaves Dart unable to reach the new function.
sh ../scripts/check_bridge.sh

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

## Android vault-key JNI bridge

Android vault-key bytes do not enter Dart. Rust stores setup material behind a
random one-time handle. Kotlin consumes that handle through JNI and wraps the
bytes with Android Keystore. During unlock, Kotlin gives the unwrapped bytes
directly to Rust through JNI and returns only another handle to Dart. Handles
expire after five minutes, work once, and are cleared on lock, wipe,
authentication cancellation, and Activity destruction.

The old `wrap` and `unwrap` platform-channel methods no longer exist. The
channel accepts only `wrapHandle` and `unwrapToHandle`.

## Known gaps, deliberately

- **No certificate pinning**, and the sync token has no scope limit. Both are
  open from the security audit; see the S9 hardening list.

- **No trademark logo pack.** Every entry gets a colour and a letter derived
  from its issuer. The user can enable bundled service symbols or set an emoji.
  The application performs no online icon lookup. See `EntryAvatar`.

- **Passkeys (FR-48 to FR-55) still need a production domain.** The Android
  Credential Manager bridge, ceremony table, and `assetlinks.json` template
  exist. Server verification and PRF vault-key wrapping stay disabled until
  the relying-party domain and release signing certificate are final.

- **No push signalling (§10.5).** A device learns about a change on the next
  scheduled cycle rather than immediately. Needs a Firebase project.

## Local workarounds

**Vendored cargokit.** `app/rust_builder/cargokit/gradle/plugin.gradle` is
third-party code shipped with `flutter_rust_bridge`. It called `project.exec {}`
from a task action, which Gradle 9 removed, and Flutter 3.44 ships Gradle 9.1 —
so every build failed. It is patched to use an injected `ExecOperations`.

The exit-code half of this patch is a defect in upstream cargokit, not a local
choice. [docs/upstream-cargokit-issue.md](docs/upstream-cargokit-issue.md)
holds the issue text, the reproduction, and the pull request body, drafted and
waiting to be posted by a person. Getting it merged removes one line from the
local patch burden.

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
