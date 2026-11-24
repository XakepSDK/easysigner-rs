#!/bin/sh
# The size of the cryptography on its own (Markdown, for the CI job summary): the C library
# (kzcrypto-capi) as a shared library, stripped. Release profile: opt-level z, LTO,
# panic = abort.
set -eu
cd "$(dirname "$0")/.."
cargo build --release --locked -p kzcrypto-capi >&2
target=$(cargo metadata --format-version 1 --no-deps | sed 's/.*"target_directory":"\([^"]*\)".*/\1/')
so="$target/release/libkzcrypto_capi.so"
tmp=$(mktemp -d)
strip -o "$tmp/lib.so" "$so"
kb() { echo $(( ($(wc -c < "$1") + 1023) / 1024 )); }
echo "## kzcrypto sizes"
echo
echo "| What | Size |"
echo "|---|---|"
echo "| C library, shared, stripped (x86-64 Linux, libkzcrypto_capi.so) | $(kb "$tmp/lib.so") KB |"
