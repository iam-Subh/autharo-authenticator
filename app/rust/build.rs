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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::env;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    configure_production_security();
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

fn configure_production_security() {
    println!("cargo:rerun-if-env-changed=AUTHCORE_PINNED_HOST");
    println!("cargo:rerun-if-env-changed=AUTHCORE_SPKI_PINS");
    println!("cargo:rerun-if-env-changed=CARGOKIT_CONFIGURATION");

    let host = env::var("AUTHCORE_PINNED_HOST")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let pins = env::var("AUTHCORE_SPKI_PINS").unwrap_or_default();
    // Cargokit compiles Rust with Cargo's release profile for both Flutter
    // release and Flutter profile builds. The Flutter mode distinguishes the
    // distributable release from a local profile size audit. A direct Cargo
    // Android release has no Cargokit mode and remains a production release.
    let cargo_release_android = env::var("PROFILE").as_deref() == Ok("release")
        && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android");
    let flutter_mode = env::var("CARGOKIT_CONFIGURATION")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let release_android = cargo_release_android && flutter_mode != "profile";

    let host_set = !host.is_empty();
    let pins_set = !pins.trim().is_empty();
    if host_set != pins_set {
        panic!("AUTHCORE_PINNED_HOST and AUTHCORE_SPKI_PINS must be set together");
    }
    let configured = host_set && pins_set;
    if release_android && !configured {
        panic!(
            "Android release builds require AUTHCORE_PINNED_HOST and exactly two comma-separated AUTHCORE_SPKI_PINS values"
        );
    }
    if cargo_release_android && flutter_mode == "profile" && !configured {
        println!(
            "cargo:warning=Flutter profile size-audit build has no certificate pins; do not distribute it"
        );
    }
    if configured {
        if host.contains("://") || host.contains('/') || host.contains(':') {
            panic!("AUTHCORE_PINNED_HOST must be one DNS hostname without a scheme, path, or port");
        }
        let values = pins.split(',').map(str::trim).collect::<Vec<_>>();
        if values.len() != 2 || values.iter().any(|value| value.is_empty()) {
            panic!("AUTHCORE_SPKI_PINS must contain exactly two comma-separated SHA-256 pins");
        }
        let decoded = values
            .iter()
            .map(|value| B64.decode(value).unwrap_or_default())
            .collect::<Vec<_>>();
        if decoded.iter().any(|value| value.len() != 32) {
            panic!("each AUTHCORE_SPKI_PINS value must be one base64-encoded SHA-256 digest");
        }
        if decoded[0] == decoded[1] {
            panic!("AUTHCORE_SPKI_PINS must contain different current and backup pins");
        }
    }

    println!("cargo:rustc-env=AUTHCORE_PINNED_HOST={host}");
    println!("cargo:rustc-env=AUTHCORE_SPKI_PINS={}", pins.trim());
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
