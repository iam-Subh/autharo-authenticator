//! Compiles SQLite3 Multiple Ciphers as the SQLite that `rusqlite` links
//! against (PRD section 12.1).
//!
//! # Why this crate exists
//!
//! Section 12.1 requires a SQLite build with page-level encryption. SQLCipher
//! was tried first and removed: its vendored OpenSSL cannot cross-compile to
//! Android from Windows, because OpenSSL's `Configure` wants a compiler named
//! `aarch64-linux-android-clang` that the Windows NDK does not ship under that
//! name. SQLite3 Multiple Ciphers carries its own crypto, so there is no
//! OpenSSL, no Perl, and no `Configure` — just one C file and `cc`, which
//! cross-compiles with the NDK clang that cargokit already configures.
//!
//! # How it takes over from libsqlite3-sys
//!
//! `libsqlite3-sys` is used **without** its `bundled` feature, so it compiles
//! no SQLite of its own and only emits the link request. Its default features
//! use pregenerated bindings, so it needs no header either. This crate then
//! produces the `sqlite3` static library that the request resolves to.
//!
//! That arrangement is the point of section 12.1's fifth rule: exactly one
//! SQLite may be linked. Two would either fail to link or, worse, silently
//! resolve to the wrong one — and the wrong one here is the copy with no
//! encryption. `duplicate_symbol_guard` below fails the build rather than
//! letting that happen quietly.

use std::path::PathBuf;

fn main() {
    let vendor = PathBuf::from("vendor");
    let amalgamation = vendor.join("sqlite3mc_amalgamation.c");

    println!("cargo:rerun-if-changed={}", amalgamation.display());
    println!("cargo:rerun-if-changed=build.rs");

    duplicate_symbol_guard();

    let mut build = cc::Build::new();
    build
        .file(&amalgamation)
        .include(&vendor)
        .warnings(false)
        // Compiled in, not linked in: the encryption extension has to be part
        // of the SQLite core to see the page layer.
        .define("SQLITE_CORE", "1")
        .define("SQLITE_THREADSAFE", "1")
        // Section 12.1 rule 3, enforced at compile time rather than by PRAGMA.
        // 3 means temporary tables and sort spills are ALWAYS held in memory
        // and cannot be moved to disk by a later `PRAGMA temp_store`. A PRAGMA
        // alone would leave a window before it runs, and anything that reset
        // it would start writing plaintext pages beside the encrypted file.
        .define("SQLITE_TEMP_STORE", "3")
        // rusqlite reads column origins for some APIs.
        .define("SQLITE_ENABLE_COLUMN_METADATA", "1")
        // The cipher configuration travels as URI parameters in some paths.
        .define("SQLITE_USE_URI", "1")
        // The vault always selects ChaCha20 before it supplies the key. Do not
        // compile unused database ciphers into every Android native library.
        .define("WXSQLITE3_HAVE_CIPHER_AES_128_CBC", "0")
        .define("WXSQLITE3_HAVE_CIPHER_AES_256_CBC", "0")
        .define("WXSQLITE3_HAVE_CIPHER_CHACHA20", "1")
        .define("WXSQLITE3_HAVE_CIPHER_SQLCIPHER", "0")
        .define("WXSQLITE3_HAVE_CIPHER_RC4", "0")
        .define("WXSQLITE3_HAVE_CIPHER_ASCON128", "0")
        .define("WXSQLITE3_HAVE_CIPHER_AEGIS", "0")
        // Not wanted, and each one is attack surface in a file format parser.
        .define("SQLITE_OMIT_DEPRECATED", "1")
        .define("SQLITE_OMIT_LOAD_EXTENSION", "1")
        .define("SQLITE_DQS", "0");

    // Android's Bionic has no `localtime_r` guard problem, but it does need
    // this to avoid pulling in a `posix_fallocate` that older API levels lack.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        build.define("SQLITE_DISABLE_LFS", None);
    }

    // Named `sqlite3` on purpose: this is what libsqlite3-sys's link request
    // resolves to. `cc` emits the link-lib and link-search directives.
    build.compile("sqlite3");
}

/// Fails the build if another crate is also compiling SQLite.
///
/// Section 12.1 rule 5. The failure this prevents is not a link error — those
/// announce themselves — but the quiet one: two SQLite copies where the linker
/// picks the one without encryption, and every test still passes because the
/// database opens fine.
fn duplicate_symbol_guard() {
    // libsqlite3-sys sets this when its `bundled` feature is on, which is the
    // only way a second copy enters this tree.
    let bundled = std::env::vars()
        .any(|(key, _)| key == "CARGO_FEATURE_BUNDLED" || key == "DEP_SQLITE3_BUNDLED");

    if bundled {
        panic!(
            "libsqlite3-sys is bundling its own SQLite while this crate is \
             compiling SQLite3 Multiple Ciphers. Two SQLite libraries would be \
             linked and the one without encryption could win silently. Remove \
             the `bundled` feature from rusqlite."
        );
    }
}
