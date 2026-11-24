#!/bin/sh
# Writes capi/include/kzcrypto.h from capi/src/lib.rs (cbindgen 0.29). With --check, fails
# when the committed header is out of date instead.
set -eu
cd "$(dirname "$0")/../capi"
out=include/kzcrypto.h
if [ "${1:-}" = --check ]; then
    tmp=$(mktemp)
    cbindgen --quiet --config cbindgen.toml --output "$tmp" .
    if ! diff -u "$out" "$tmp"; then
        echo "capi/include/kzcrypto.h is out of date: run scripts/capi-header.sh" >&2
        exit 1
    fi
else
    cbindgen --quiet --config cbindgen.toml --output "$out" .
fi
