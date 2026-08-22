//! SQLite3 Multiple Ciphers, compiled by this crate's build script.
//!
//! There is no Rust API here on purpose. The crate exists to compile the C
//! amalgamation and emit the link directives; `rusqlite` provides the bindings
//! and does the talking. See `build.rs` for why this arrangement is necessary
//! and what it guards against.
//!
//! The vendored source is `vendor/sqlite3mc_amalgamation.c`, with the upstream
//! SHA-256 sums recorded in `vendor/CHECKSUMS.txt`. It came from the official
//! release archive, whose own published checksum was verified before use.

/// Linking this crate is a side effect of its build script, so a dependent
/// crate that never names anything from it can be dropped by the linker on
/// some targets. Calling this once keeps the dependency real.
///
/// It does nothing and returns nothing.
pub fn link_me() {}
