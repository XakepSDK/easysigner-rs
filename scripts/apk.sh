#!/bin/sh
# Builds the Android app: dist/kzsigner-<version>-android.apk, for phones (arm64) and the
# emulator (x86_64). cargo builds the Rust library (through scripts/cargo.sh); Gradle
# (android/build.gradle.kts, pinned versions) adds the Java side, AndroidX and signs.
#
#   ANDROID_HOME=... ANDROID_NDK_ROOT=... sh scripts/apk.sh
#
# Needs: the NDK (r27), build-tools 35.0.0, platforms;android-35 and a JDK 17 or newer. Gradle
# itself is downloaded once (pinned version, checked against its SHA-256) into
# ~/.cache/kzsigner-gradle, or taken from KZSIGNER_GRADLE. Two builds of a commit give the same
# APK.
#
# KZSIGNER_SELFTEST=1 builds the emulator test copy instead: x86_64 only, with the in-app test
# of the real screens (src/android/selftest.rs), signed with the development key, written to
# target/apk-selftest/kzsigner-selftest.apk. CI runs it with scripts/android-selftest.sh.
#
# Signing: with KZSIGNER_KEYSTORE (+ KZSIGNER_KEYSTORE_PASS, KZSIGNER_KEY_ALIAS) when set,
# else with android/dev.keystore, a development key whose password is in build.gradle.kts. A
# phone keeps an app only while updates come with the same key: a dev build has to be
# uninstalled before a release build can be installed.
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
: "${ANDROID_NDK_ROOT:?set ANDROID_NDK_ROOT to the NDK}"
export ANDROID_HOME
TC=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
V=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
GRADLE_VERSION=8.14.3
GRADLE_SHA256=bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531

TARGETS="aarch64-linux-android x86_64-linux-android"
FEATURES=
JNI=target/android-jni
OUT=dist/kzsigner-$V-android.apk
if [ -n "${KZSIGNER_SELFTEST:-}" ]; then
    TARGETS=x86_64-linux-android
    FEATURES="--features selftest"
    JNI=target/android-jni-selftest
    OUT=target/apk-selftest/kzsigner-selftest.apk
    unset KZSIGNER_KEYSTORE
    V=$V-selftest
fi
# a release must not be signed with the development key, whose password is public
case "$V" in
*-*) ;;
*) [ -n "${KZSIGNER_KEYSTORE:-}" ] || {
    echo "release $V: set KZSIGNER_KEYSTORE (the release signing key); the dev key is for -dev versions only" >&2
    exit 1
} ;;
esac

# the Rust library, for each phone architecture
rm -rf "$JNI"
for t in $TARGETS; do
    T=$(echo "$t" | tr 'a-z-' 'A-Z_')
    export "CARGO_TARGET_${T}_LINKER=$TC/${t}30-clang"
    # android-activity builds GameActivity's C glue
    tt=$(echo "$t" | tr '-' '_')
    export "CC_${tt}=$TC/${t}30-clang" "CXX_${tt}=$TC/${t}30-clang++" "AR_${tt}=$TC/llvm-ar"
    # shellcheck disable=SC2086
    sh scripts/cargo.sh build --release --locked --target "$t" -p kzsigner-android $FEATURES
    case $t in
    aarch64-*) abi=arm64-v8a ;;
    x86_64-*) abi=x86_64 ;;
    esac
    mkdir -p "$JNI/$abi"
    cp "target/$t/release/libkzsigner_android.so" "$JNI/$abi/"
done

# Gradle, pinned and checked
if [ -n "${KZSIGNER_GRADLE:-}" ]; then
    GRADLE=$KZSIGNER_GRADLE
else
    G=${XDG_CACHE_HOME:-$HOME/.cache}/kzsigner-gradle
    GRADLE=$G/gradle-$GRADLE_VERSION/bin/gradle
    if [ ! -x "$GRADLE" ]; then
        mkdir -p "$G"
        zip=$G/gradle-$GRADLE_VERSION-bin.zip
        [ -f "$zip" ] || curl -sSfL -o "$zip" "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"
        echo "$GRADLE_SHA256  $zip" | sha256sum -c - > /dev/null || {
            echo "gradle-$GRADLE_VERSION-bin.zip: wrong SHA-256" >&2
            rm -f "$zip"
            exit 1
        }
        (cd "$G" && unzip -q -o "gradle-$GRADLE_VERSION-bin.zip")
    fi
fi

"$GRADLE" -q -p android --no-daemon --console=plain assembleRelease \
    -Pkzsigner.version="$V" -Pkzsigner.jniLibs="$(pwd)/$JNI"
mkdir -p "$(dirname "$OUT")"
cp target/gradle/outputs/apk/release/kzsigner-release.apk "$OUT"
"$ANDROID_HOME/build-tools/35.0.0/apksigner" verify --print-certs "$OUT" | head -3
ls -la "$OUT"
