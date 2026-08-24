#!/usr/bin/env sh
#
# Runs a build command and verifies two things: the exit status of the build
# tool, and that the artifact it was supposed to produce actually exists and
# was written by this run.
#
# Why this exists
# ---------------
# `flutter build apk ... | tail -20` reports the exit status of `tail`, not of
# the build. A failed build looks like a successful one. That happened, and it
# was reported as a success until the artifact was checked.
#
# Both halves of the check matter. The exit status alone misses a tool that
# fails silently; the artifact alone misses a stale file left by an earlier
# run, which is why the timestamp is compared against the start of this run.
#
# A second lesson, learned the same way. An APK is a container: gradle will
# happily package a stale native library and report success, so a fresh
# artifact does not mean fresh contents. `--contains` checks that a named entry
# inside the archive was also rebuilt by this run. Without it, an Android build
# whose Rust step failed still produced a valid, newer APK carrying the
# previous `.so`, and the tests that ran against it were testing old code.
#
# A third check, and a correction to how NFR-13 describes it.
#
# NFR-13 asks the build to assert that the packaged library exports the symbols
# the application expects, because a forgotten bridge regeneration otherwise
# produces a green build with an interface the caller cannot reach. That
# failure is real and it happened here: the whole sync API was compiled,
# packaged and shipped to a phone before anyone noticed Dart could not reach a
# line of it.
#
# The named mechanism does not detect it. `flutter_rust_bridge` 2.12 exports no
# symbol per function — the packaged library exports twenty-five symbols in
# total, and every call goes through `frb_pde_ffi_dispatcher_primary` on a
# numeric identifier. Adding or removing an API function changes nothing in the
# symbol table, so that check reads the same before and after. Use
# `scripts/check_bridge.sh` for the regeneration case: it runs the generator and
# fails if anything moves, which is evidence rather than inference.
#
# `--exports` is still worth having, for a different failure: a library that is
# not the bridge at all. A wrong crate-type, an over-eager strip, or a
# mis-merged `.so` from another project all produce a file of the right name in
# the right place that exports none of these. Name the entry points the loader
# needs, not the functions the application calls.
#
# Usage
# -----
#   scripts/verify_build.sh [--contains <entry>] [--exports <symbol>]... #       <artifact-path> -- <command> [args...]
#
# Example
#   scripts/verify_build.sh #     --contains lib/arm64-v8a/librust_lib_authenticator.so #     --exports frb_pde_ffi_dispatcher_primary #     --exports frb_get_rust_content_hash #     app/build/app/outputs/flutter-apk/app-debug.apk -- #     flutter build apk --debug
#
# Output is streamed, not captured, so a long build stays visible. Do not pipe
# this script's own output into `head` or `tail` — that reintroduces the exact
# bug it exists to prevent.

set -eu

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <artifact-path> -- <command> [args...]" >&2
    exit 2
fi

contains=""
exports=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --contains) contains="$2"; shift 2 ;;
        --exports)  exports="$exports $2"; shift 2 ;;
        *) break ;;
    esac
done

artifact="$1"
shift

if [ "$1" != "--" ]; then
    echo "error: expected '--' after the artifact path" >&2
    exit 2
fi
shift

# A marker file written now. Comparing the artifact against it with `-nt` is
# portable, where reading and comparing mtimes is not.
marker="$(mktemp)"
trap 'rm -f "$marker"' EXIT

printf '\n=== building: %s\n' "$*" >&2
printf '=== expecting: %s\n\n' "$artifact" >&2

status=0
"$@" || status=$?

if [ "$status" -ne 0 ]; then
    printf '\nFAILED: the build tool exited %s\n' "$status" >&2
    exit "$status"
fi

if [ ! -e "$artifact" ]; then
    printf '\nFAILED: the build tool reported success but %s does not exist\n' \
        "$artifact" >&2
    exit 1
fi

if [ ! "$artifact" -nt "$marker" ]; then
    printf '\nFAILED: %s exists but was not written by this run.\n' "$artifact" >&2
    printf 'It is left over from an earlier build. Treat this as a failure.\n' >&2
    exit 1
fi

size=$(wc -c < "$artifact" | tr -d ' ')
if [ "$size" -eq 0 ]; then
    printf '\nFAILED: %s was written but is empty\n' "$artifact" >&2
    exit 1
fi

if [ -n "$contains" ]; then
    if ! command -v unzip >/dev/null 2>&1; then
        printf '\nWARNING: unzip is unavailable, so %s was not checked for %s\n' \
            "$artifact" "$contains" >&2
    elif ! unzip -l "$artifact" 2>/dev/null | grep -q -- "$contains"; then
        printf '\nFAILED: %s does not contain %s.\n' "$artifact" "$contains" >&2
        printf 'The build reported success but did not package it.\n' >&2
        exit 1
    else
        printf 'contains: %s\n' "$contains" >&2
    fi
fi

# NFR-13: the packaged library must export what the application calls.
#
# Read out of the archive rather than off the build directory, because the
# archive is the artefact that reaches the device — the same reason `--contains`
# checks the archive. A `.so` sitting in `target/` proves nothing about what was
# packaged.
if [ -n "$exports" ]; then
    if [ -z "$contains" ]; then
        printf '\nFAILED: --exports needs --contains to name the library to read\n' >&2
        exit 2
    fi

    reader=""
    for candidate in llvm-nm nm llvm-objdump objdump; do
        if command -v "$candidate" >/dev/null 2>&1; then
            reader="$candidate"
            break
        fi
    done

    if [ -z "$reader" ]; then
        # Deliberately fatal, not a warning. A symbol check that quietly skips
        # itself on the machine where it matters is the same defect it exists
        # to catch: a green result that proves nothing. The NDK ships
        # llvm-nm; put it on PATH.
        printf '\nFAILED: no symbol reader found (llvm-nm, nm, llvm-objdump, objdump).\n' >&2
        printf 'The NDK ships llvm-nm under toolchains/llvm/prebuilt/*/bin.\n' >&2
        exit 1
    fi

    workdir="$(mktemp -d)"
    trap 'rm -f "$marker"; rm -rf "$workdir"' EXIT

    if ! unzip -o -q -j "$artifact" "$contains" -d "$workdir" 2>/dev/null; then
        printf '\nFAILED: could not extract %s from %s\n' "$contains" "$artifact" >&2
        exit 1
    fi

    library="$workdir/$(basename "$contains")"
    case "$reader" in
        *nm)      table=$("$reader" --defined-only --extern-only "$library" 2>/dev/null || "$reader" -D "$library" 2>/dev/null) ;;
        *objdump) table=$("$reader" -T "$library" 2>/dev/null) ;;
    esac

    if [ -z "$table" ]; then
        printf '\nFAILED: %s read no symbols from %s\n' "$reader" "$library" >&2
        exit 1
    fi

    for symbol in $exports; do
        if ! printf '%s' "$table" | grep -q -- "$symbol"; then
            printf '\nFAILED: %s does not export %s.\n' "$contains" "$symbol" >&2
            printf 'The build is green and the interface is unreachable. If the\n' >&2
            printf 'Rust side changed, regenerate the bridge:\n' >&2
            printf '  cd app && flutter_rust_bridge_codegen generate\n' >&2
            exit 1
        fi
        printf 'exports: %s\n' "$symbol" >&2
    done
fi

printf '\nOK: %s (%s bytes), written by this run\n' "$artifact" "$size" >&2
