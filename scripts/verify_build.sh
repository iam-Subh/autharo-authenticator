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
# Usage
# -----
#   scripts/verify_build.sh <artifact-path> -- <command> [args...]
#
# Example
#   scripts/verify_build.sh app/build/app/outputs/flutter-apk/app-debug.apk -- \
#     flutter build apk --debug
#
# Output is streamed, not captured, so a long build stays visible. Do not pipe
# this script's own output into `head` or `tail` — that reintroduces the exact
# bug it exists to prevent.

set -eu

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <artifact-path> -- <command> [args...]" >&2
    exit 2
fi

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

printf '\nOK: %s (%s bytes), written by this run\n' "$artifact" "$size" >&2
