#!/bin/sh
# Screenshots of signing in person, two phones side by side (docs/in-person-signing.md):
# the app's screens drawn by Robolectric (apps/android/compose/src/screenshots, InPersonScreenshots)
# over the core built for this machine, against the fake NCA servers. PNGs go to $1
# (default target/screenshots).
#
#   ANDROID_HOME=... sh scripts/screenshots.sh [folder]
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
OUT=$(realpath -m "${1:-target/screenshots}")
GRADLE=${KZSIGNER_GRADLE:-${XDG_CACHE_HOME:-$HOME/.cache}/kzsigner-gradle/gradle-9.9.2/bin/gradle}
[ -x "$GRADLE" ] || { echo "run scripts/apk.sh once first (it fetches Gradle)" >&2; exit 1; }

cargo build --locked -p kzsigner-ffi
cargo build --locked -p kzsigner --example fake_nca
rm -rf target/uniffi-kotlin
cargo run -q --locked -p kzsigner-ffi --features bindgen --bin uniffi-bindgen -- generate \
    --library target/debug/libkzsigner_ffi.so --language kotlin --no-format --out-dir target/uniffi-kotlin

target/debug/examples/fake_nca > target/fake-nca.log 2>&1 &
nca=$!
trap 'kill $nca 2>/dev/null' EXIT
sleep 1

# shellcheck disable=SC2086
"$GRADLE" -q -p apps/android ${KZSIGNER_GRADLE_ARGS:-} --no-daemon --console=plain :compose:testDebugUnitTest \
    --tests 'kz.kzsigner.InPersonScreenshots' \
    -Pkzsigner.screenshots="$OUT" -Pkzsigner.ffiKotlin="$(pwd)/target/uniffi-kotlin"
ls "$OUT"
