//! Stamps the native library with what it was built from (PRD NFR-13).
//!
//! # Why
//!
//! A gradle build packaged a stale `librust_lib_authenticator.so` and reported
//! success, and the tests that ran against it were testing the previous
//! commit's code. The immediate cause is fixed — the cargokit wrapper now
//! propagates its exit code — but that fix only covers the one path that
//! failed. This stamp covers every path: whatever route a `.so` takes into an
//! APK, a device test can ask it what it was built from and refuse to trust it
//! if the answer is wrong.
//!
//! The stamp is not secret and reveals nothing about a vault. It is a commit
//! hash and a timestamp.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Without these, cargo caches the build script's output and the stamp
    // would keep naming the commit it was first built at. `HEAD` moves on
    // checkout and commit; `index` moves on `git add`, which is what changes
    // the dirty flag below.
    let git_dir = Path::new("../../.git");
    for file in ["HEAD", "index"] {
        let path = git_dir.join(file);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());

    // A dirty tree cannot be pinned to a commit: the library was built from
    // something that does not exist in history. Recorded rather than hidden,
    // so a test can weaken its check honestly instead of comparing a hash that
    // was never going to match.
    let dirty = git(&["status", "--porcelain"])
        .map(|out| !out.trim().is_empty())
        .unwrap_or(false);

    let built_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=AUTHCORE_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=AUTHCORE_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=AUTHCORE_BUILD_TIME={built_at}");
}

/// Runs git, returning `None` when it is unavailable or fails.
///
/// A build outside a git checkout — a published crate, a source tarball — must
/// still work. It stamps "unknown", and the device test says so rather than
/// failing on something the builder cannot control.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir("../..")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
