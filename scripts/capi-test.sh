#!/bin/sh
# Builds the C interface (capi/) as a static library and runs capi/tests/c/test.c against it,
# with the header in capi/include. Needs a C compiler (cc).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
cargo build --release --locked -p kzcrypto-capi
target=$(cargo metadata --format-version 1 --no-deps | sed 's/.*"target_directory":"\([^"]*\)".*/\1/')
out=$(mktemp -d)
cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -I capi/include capi/tests/c/test.c \
    "$target/release/libkzcrypto_capi.a" -lpthread -ldl -lm -o "$out/capi-test"
"$out/capi-test" "$root/tests/fixtures"
