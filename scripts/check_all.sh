#!/usr/bin/env sh
#
# Every gate this project has, in one command.
#
# Why this exists
# ---------------
# The gates were correct and nobody could run them all. Six commands across
# three directories, two of which take arguments that are wrong in a way that
# still exits zero:
#
#   * `flutter analyze lib/ test/` silently skips `integration_test/`. That is
#     how a required parameter added to the bridge reached a phone — every
#     analyze was green, over a subset that did not contain the caller it broke.
#   * a bare `flutter analyze` exits non-zero on info-level lints, of which this
#     project has several deliberate ones, so used as a gate it always fails,
#     and a gate that always fails is one everyone learns to skip.
#   * `scripts/check_bridge.sh` was not in the README's test section at all.
#
# Each of those is the same shape as the defects the gates exist to catch: a
# check that reports success over less than it appears to cover. Remembering
# six commands correctly is not a control. This is.
#
# How it reports
# --------------
# Every step runs, even after one fails. Stopping at the first means fixing
# them one round trip at a time, and the second failure is often the
# explanation for the first.
#
# Output is captured to files and printed only for the steps that failed, so a
# passing run is short enough to read and a failing one shows the reason
# without a scroll. Nothing here is piped through `head` or `tail` before its
# exit status is taken — that is the defect `verify_build.sh` was written for,
# and it is easy to reintroduce in a script like this one.
#
# Usage
# -----
#   scripts/check_all.sh [--no-server] [--device <id>]
#
#   --no-server   Skip the server tests, which need the development database.
#                 The skip is printed and the run is marked incomplete, because
#                 a quiet skip is indistinguishable from a pass.
#   --device      Also run the on-device integration tests. Needs a connected
#                 device and, for the sync test, a reachable server.

set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
logs="$(mktemp -d)"
trap 'rm -rf "$logs"' EXIT

skip_server=0
device=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-server) skip_server=1; shift ;;
        --device) device="${2:-}"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

failures=""
skipped=""

# Runs one step. `slug` names its log; `dir` is where it runs.
run() {
    slug="$1"
    label="$2"
    dir="$3"
    shift 3

    printf '%-34s' "$label"
    ( cd "$root/$dir" && "$@" ) > "$logs/$slug.log" 2>&1
    status=$?

    if [ "$status" -eq 0 ]; then
        printf 'ok\n'
    else
        printf 'FAILED (exit %s)\n' "$status"
        failures="$failures $slug"
    fi
}

printf '\n'

# ---------------------------------------------------------------- the core
run core-test    'core: tests'                  core cargo test

# Read against files the real applications produced, rather than fixtures this
# project wrote for itself. Not committed — they come from a GPL project — so
# the step names how to get them rather than skipping quietly.
if [ -d "$root/.fixtures" ]; then
    printf '%-34s' 'core: real export files'
    ( cd "$root/core" && AUTHCORE_IMPORT_FIXTURES="$root/.fixtures"         cargo test --test real_exports -- --ignored ) > "$logs/real-exports.log" 2>&1
    status=$?
    if [ "$status" -eq 0 ]; then
        printf 'ok
'
    else
        printf 'FAILED (exit %s)
' "$status"
        failures="$failures real-exports"
    fi
else
    printf '%-34sskipped (sh scripts/fetch_import_fixtures.sh)
' 'core: real export files'
    skipped="$skipped real-exports"
fi
run core-clippy  'core: clippy'                 core cargo clippy --all-targets -- -D warnings

# -------------------------------------------------------------- the server
#
# The tests need the development database. Checked first so the failure names
# the cause rather than arriving as a connection error inside sqlx.
if [ "$skip_server" -eq 1 ]; then
    printf '%-34sskipped\n' 'server: tests'
    skipped="$skipped server"
elif ! docker exec authcore-pg pg_isready -U authcore >/dev/null 2>&1; then
    printf '%-34sFAILED (no database)\n' 'server: tests'
    printf '    Start it with: docker start authcore-pg\n'
    printf '    Or skip deliberately with --no-server.\n'
    failures="$failures server-db"
else
    run server-test 'server: tests' server cargo test
fi

# ----------------------------------------------------------------- the app
# The bridge crate has tests of its own — the HTTPS scheme rule lives here, not
# in the core. `clippy --all-targets` compiles them and never runs them, which
# is how four tests sat in this crate untouched by every green run.
run bridge-test   'bridge: tests'                app/rust cargo test
run bridge-clippy 'bridge: clippy'              app/rust cargo clippy --all-targets -- -D warnings

# No path: a path silently drops `integration_test/`.
# --no-fatal-infos: otherwise info-level lints make a clean tree exit 1.
run app-analyze   'app: analyze'                app flutter analyze --no-fatal-infos
run app-test      'app: host tests'             app flutter test

# The generated bridge must match the Rust API. Nothing else catches a
# forgotten regeneration: the dispatch is by numeric identifier, so the symbol
# table is unchanged and the build stays green.
run bridge-current 'app: bridge is current'     . sh scripts/check_bridge.sh

# --------------------------------------------------------------- on device
if [ -n "$device" ]; then
    # Enumerated, never listed. This block named two files by hand, and the
    # consequence was silent: `import_test.dart` was written, passed when run
    # directly, and sat outside every "OK: every gate passed" this project ever
    # printed. A third file would have joined it.
    #
    # It is the same defect as `flutter analyze lib/ test/` skipping
    # `integration_test/`, and it fails the same way -- by proving less than it
    # claims while looking identical to a run that proved it.
    #
    # `sync_test.dart` is the one exclusion, because it needs a server address
    # only the operator has. It is named below rather than skipped in silence.
    for file in app/integration_test/*_test.dart; do
        name=$(basename "$file" .dart)
        if [ "$name" = "sync_test" ]; then
            continue
        fi
        run "device-$name" "device: $name" app \
            flutter test "integration_test/$name.dart" -d "$device"
    done
    printf '%-34s' 'device: sync test'
    printf 'run separately, it needs a server address:\n'
    printf '    flutter test integration_test/sync_test.dart -d %s \\\n' "$device"
    printf '      --dart-define=SYNC_URL=http://<this machine>:8080\n'
else
    printf '%-34sskipped (pass --device <id>)\n' 'device: tests'
    skipped="$skipped device"
fi

# ------------------------------------------------------------------ report
printf '\n'

if [ -n "$failures" ]; then
    for slug in $failures; do
        if [ -f "$logs/$slug.log" ]; then
            printf '=== %s ===\n' "$slug"
            # The status was taken long before this line, so trimming the
            # output here cannot hide a failure the way a pipe would.
            tail -40 "$logs/$slug.log"
            printf '\n'
        fi
    done
    printf 'FAILED:%s\n' "$failures" >&2
    exit 1
fi

if [ -n "$skipped" ]; then
    # Named, and non-zero is not used: a skip is not a failure, but it must not
    # read as a full pass either.
    printf 'OK, but these were skipped and prove nothing:%s\n' "$skipped" >&2
    exit 0
fi

printf 'OK: every gate passed\n' >&2
