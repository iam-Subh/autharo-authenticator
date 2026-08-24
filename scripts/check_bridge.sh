#!/usr/bin/env sh
#
# Fails when the generated Rust-to-Dart bridge is out of date with the Rust API.
#
# Why this exists, and why it is not the symbol check NFR-13 asks for
# -------------------------------------------------------------------
# NFR-13 says the build check should assert that the packaged library exports
# the symbols the application expects, because a forgotten bridge regeneration
# otherwise produces a green build with an interface the caller cannot reach.
# The reasoning is right and the failure is real — it happened here, with the
# whole sync API compiled, packaged and shipped to a phone before anyone
# noticed Dart could not reach a line of it.
#
# The named mechanism does not work for this bridge. `flutter_rust_bridge` 2.12
# does not export one symbol per function. The packaged library exports
# twenty-five symbols in total, and every call goes through one of them:
#
#     frb_pde_ffi_dispatcher_primary      <- dispatches on a numeric identifier
#     frb_get_rust_content_hash
#
# Adding or removing an API function changes no exported symbol. A symbol check
# would therefore read identically before and after a forgotten regeneration —
# a check that cannot fail, which is worse than no check, because it makes the
# gap look covered.
#
# What does catch it is asking the generator. If the generated files change
# when it runs, they were stale. That cannot be vacuous: the diff is the
# evidence.
#
# The content hash both sides carry is not enough either. It lives in the
# generated files, so if neither side was regenerated the two still agree. It
# catches a half-finished regeneration, not a forgotten one.
#
# Note that a changed *struct* does break the build on its own, because the
# generated code constructs it. A changed or added *function* does not. The
# second case is the one this script is for, and it is the one that reaches a
# phone.
#
# Why it snapshots instead of reading git
# ---------------------------------------
# The first version required a clean working tree, so that an unrelated edit to
# a generated file would not be reported as a stale bridge. That made it
# unusable during the work it exists to guard: regenerating is part of the
# change, so the tree is legitimately dirty exactly when someone would run it.
#
# Copying the files aside and putting them back compares the same thing without
# caring what git thinks, and works in a tree that was never a repository.
#
# Usage
# -----
#   scripts/check_bridge.sh [--fix]
#
# With --fix, leaves the regenerated files in place instead of failing.

set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
app="$root/app"

# Everything the generator owns. Listed rather than globbed, so a new generated
# path has to be added here deliberately — a silently unchecked file is the
# same gap one level down.
generated="rust/src/frb_generated.rs lib/src/rust"

fix=0
if [ "${1:-}" = "--fix" ]; then
    fix=1
fi

if ! command -v flutter_rust_bridge_codegen >/dev/null 2>&1; then
    printf 'FAILED: flutter_rust_bridge_codegen is not on PATH.\n' >&2
    printf 'Install the version pinned in app/pubspec.yaml:\n' >&2
    printf '  cargo install flutter_rust_bridge_codegen --version 2.12.0\n' >&2
    exit 1
fi

cd "$app"

for path in $generated; do
    if [ ! -e "$path" ]; then
        printf 'FAILED: %s does not exist. The bridge has never been generated.\n' \
            "$path" >&2
        exit 1
    fi
done

snapshot="$(mktemp -d)"
restore() {
    if [ "$fix" -eq 0 ]; then
        for path in $generated; do
            rm -rf "$path"
            cp -R "$snapshot/$(basename "$path")" "$path"
        done
    fi
    rm -rf "$snapshot"
}
trap restore EXIT

for path in $generated; do
    cp -R "$path" "$snapshot/$(basename "$path")"
done

printf '=== regenerating the bridge to see whether anything moves\n' >&2
if ! flutter_rust_bridge_codegen generate >/dev/null 2>&1; then
    printf '\nFAILED: the code generator itself failed.\n' >&2
    flutter_rust_bridge_codegen generate >&2 || true
    exit 1
fi

# The generator uses UNKNOWN when `cargo metadata` fails while it computes the
# native library name. Generation can still return success in that case. The
# Android package contains librust_lib_authenticator.so, so normalize this
# known generated value before the stale-file comparison.
loader_config="lib/src/rust/frb_generated.dart"
if grep -F "stem: 'UNKNOWN'" "$loader_config" >/dev/null 2>&1; then
    patched_loader_config="$loader_config.loader-name.tmp"
    sed "s/stem: 'UNKNOWN'/stem: 'rust_lib_authenticator'/" \
        "$loader_config" > "$patched_loader_config"
    mv "$patched_loader_config" "$loader_config"
fi
if ! grep -F "stem: 'rust_lib_authenticator'" "$loader_config" >/dev/null 2>&1; then
    printf '\nFAILED: the generated bridge does not load rust_lib_authenticator.\n' >&2
    exit 1
fi

stale=""
for path in $generated; do
    if ! diff -r -q "$snapshot/$(basename "$path")" "$path" >/dev/null 2>&1; then
        stale="$stale $path"
    fi
done

if [ -z "$stale" ]; then
    printf '\nOK: the bridge is up to date with the Rust API\n' >&2
    exit 0
fi

if [ "$fix" -eq 1 ]; then
    printf '\nThe bridge was out of date and has been regenerated:%s\n' "$stale" >&2
    exit 0
fi

printf '\nFAILED: the bridge is out of date with the Rust API.\n' >&2
printf 'Something in app/rust/src/api changed and the bridge was not\n' >&2
printf 'regenerated, so Dart cannot reach it. The build would still be green.\n' >&2
printf '\nStale:%s\n' "$stale" >&2
printf '\nFix it with:\n  scripts/check_bridge.sh --fix\n' >&2
exit 1
