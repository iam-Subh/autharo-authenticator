# Vendored SQLite3 Multiple Ciphers

Source: <https://github.com/utelle/SQLite3MultipleCiphers> release `v2.5.0`,
asset `sqlite3mc-2.5.0-sqlite-3.53.4-amalgamation.zip`.

SQLite version: 3.53.4. SQLite3MC version: 2.5.0.

The release archive's SHA-256 was checked against the project's published
`sqlite3mc-2.5.0-SHA256SUMS` before extraction:

    cd3a598b667dea206b6c5319d4ecb9d687ee40565f9fd2ba280d0c2f93790f58

`CHECKSUMS.txt` holds the SHA-256 of each extracted file as vendored here, so a
later change to these files is visible.

Only three files are kept. `shell3mc_amalgamation.c` is the command-line shell
and is not needed.

## Why vendored rather than downloaded at build time

A build script that fetches source needs network access on every build host,
including CI, and makes the build unreproducible when the release is retagged.
14 MB in git is the cheaper of the two.

## Updating

1. Download the new amalgamation zip and its `SHA256SUMS` from the release.
2. Verify the zip against the published sum.
3. Replace the three files, regenerate `CHECKSUMS.txt`, and update this file.
4. Re-run `cargo test -p authcore --test store`. The encryption tests there
   assert on the file's bytes, so a build that quietly stopped encrypting
   fails them.
