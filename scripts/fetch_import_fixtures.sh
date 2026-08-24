#!/usr/bin/env sh
#
# Downloads real export files produced by the applications this project
# imports from.
#
# Why these are not committed
# ---------------------------
# They come from Aegis, which is GPLv3. Copying test data out of a GPL project
# into this one is a licensing question nobody here has answered, and test
# fixtures are not worth answering it over. Fetching them keeps the question
# from arising.
#
# Why they are needed at all
# --------------------------
# The unit tests build their own encrypted fixtures with the same primitives
# that read them. That proves the reader round-trips with the writer. It says
# nothing about whether it reads what Aegis and 2FAS actually produce — and if
# either differs in a detail that was guessed, every test passes and every real
# import fails.
#
# These files close that gap. They are the real exporters' output, and the
# passwords are the ones Aegis uses in its own tests.
#
# Running the tests against them
# ------------------------------
#   sh scripts/fetch_import_fixtures.sh
#   cd core && AUTHCORE_IMPORT_FIXTURES=../.fixtures cargo test --test real_exports

set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
target="$root/.fixtures"
base="https://raw.githubusercontent.com/beemdevelopment/Aegis/master/app/src/test/resources/com/beemdevelopment/aegis/importers"

mkdir -p "$target"

for file in \
    aegis_plain.json \
    aegis_encrypted.json \
    2fas_authenticator_plain_v4.2fas \
    2fas_authenticator_encrypted_v4.2fas
do
    printf '%-40s' "$file"
    if curl -fsSL -o "$target/$file" "$base/$file"; then
        printf '%s bytes\n' "$(wc -c < "$target/$file" | tr -d ' ')"
    else
        printf 'FAILED\n' >&2
        exit 1
    fi
done

printf '\nFetched into %s\n' "$target"
