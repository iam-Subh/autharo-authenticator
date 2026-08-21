# Cross-Platform Authenticator App

Implementation of the PRD, version 0.5. The build order is the dependency
sequence in section 18 of the PRD: each stage is finished before the next
starts.

## Stage status

| Stage | Content | State |
|---|---|---|
| S1 — Core | TOTP, HOTP, Base32, the `otpauth://` parser, SQLite storage | **Done.** Exit criterion met: the RFC 6238 and RFC 4226 vectors pass for SHA-1, SHA-256, and SHA-512 |
| S2 — First platform | Flutter UI, QR scan, manual entry, list, copy, app lock | Not started |
| S3 — Crypto | Vault key, key slots, Argon2id, XChaCha20-Poly1305, recovery key | Not started |
| S4 — Backend | API, PostgreSQL schema, key slots, quotas, enumeration resistance | Not started |
| S5 — Sync | Sync engine, outbox, HLC, conflict resolution, prune watermark | Not started |
| S6 — Other platforms | Remaining platforms, screen capture, tray and menu bar | Not started |
| S7 — Passkeys | `passkeys` package, domain association, PRF slot, fallback | Not started |

## Layout

```
core/          Rust core library (authcore). All security-critical logic lives here.
  src/
    base32.rs  RFC 4648 decoding for OTP secrets (FR-09)
    otp.rs     TOTP and HOTP engines (FR-01 to FR-05)
    otpauth.rs otpauth:// URI parser (FR-10, FR-13)
    entry.rs   EntryPayload and folder payloads (section 12.2)
    hlc.rs     Hybrid logical clock timestamps (section 10.2)
    store.rs   Local SQLite database (section 12.1)
  tests/
    rfc4226.rs RFC 4226 Appendix D vectors
    rfc6238.rs RFC 6238 Appendix B vectors
    otpauth.rs Parser behaviour against real-world export shapes
    store.rs   Database, outbox, tombstones, full re-sync
    pipeline.rs Scanned QR through to a generated code
```

## Build

Requires Rust 1.98 or later. On Windows the MSVC toolchain needs Visual Studio
build tools, which are already present on this machine.

```sh
cd core
cargo test                                  # 66 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

If `cargo` is not on the path, it is at `%USERPROFILE%\.cargo\bin`. The
installer was run with `--no-modify-path`, so this is not set permanently.

## What S1 does and does not do

Done:

- TOTP (RFC 6238) and HOTP (RFC 4226) for SHA-1, SHA-256, and SHA-512, at 6 to
  8 digits and any period from 10 to 300 seconds.
- Base32 decoding that accepts padded, unpadded, lowercase, and space-separated
  secrets, and rejects anything else with a message naming the reason (FR-09).
- The `otpauth://` parser, including the label variations that Google
  Authenticator, Aegis, and 2FAS emit, and a one-URI-per-line file reader.
- `EntryPayload` with the exact field names in section 12.2, including
  preservation of fields written by a newer client.
- The local `entry`, `outbox`, and `meta` tables, tombstones, and full re-sync.

Deliberately not done at this stage:

- **The local database is not encrypted at rest.** Section 12.1 calls for
  SQLCipher, which needs the vault key from S3. `core/src/store.rs` links plain
  SQLite until then. `tests/pipeline.rs` asserts this gap explicitly, so S3
  must invert that test.
- No key slots, no vault key, no Argon2id, no XChaCha20-Poly1305 (S3).
- No sync cycle. The HLC type and the outbox exist because the schema needs
  them; the cycle that uses them is S5.
- No Steam format (FR-06, P1), no `otpauth-migration://`, Aegis, or `.2fas`
  importers (S8).

## Notes carried forward

- `Store::device_id` generates the 64-bit device identifier on first use and
  never changes it. Section 10.4's tiebreak depends on it being stable and
  distinct per install.
- `Payload::to_json` enforces the 512-character note limit and the 3 KiB
  payload limit so the client refuses before the NFR-11 server quota does.
- An HOTP URI with no counter is refused rather than defaulted to zero. A
  guessed counter is out of step with the issuer from the first code.
