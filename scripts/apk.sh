#!/bin/sh
# Builds the Android app: dist/kzsigner-<version>-android.apk, for phones (arm64) and the
# emulator (x86_64). No Gradle: the Android SDK's own tools put the APK together.
#
#   ANDROID_HOME=... ANDROID_NDK_ROOT=... sh scripts/apk.sh
#
# Needs: the NDK (r27), build-tools 35.0.0, platforms;android-35 and a JDK (javac).
# The libraries go through scripts/cargo.sh, so two builds of a commit give the same APK.
#
# Signing: with KZSIGNER_KEYSTORE (+ KZSIGNER_KEYSTORE_PASS, KZSIGNER_KEY_ALIAS) when set,
# else with android/dev.keystore, a development key whose password is in this file. A phone
# keeps an app only while updates come with the same key: a dev build has to be uninstalled
# before a release build can be installed.
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
: "${ANDROID_NDK_ROOT:?set ANDROID_NDK_ROOT to the NDK}"
BT=$ANDROID_HOME/build-tools/35.0.0
JAR=$ANDROID_HOME/platforms/android-35/android.jar
TC=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
V=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
# zip stores local times: the same on every machine only in one time zone
export TZ=UTC
# a release must not be signed with the development key, whose password is public
case "$V" in
*-*) ;;
*) [ -n "${KZSIGNER_KEYSTORE:-}" ] || {
    echo "release $V: set KZSIGNER_KEYSTORE (the release signing key); the dev key is for -dev versions only" >&2
    exit 1
} ;;
esac

# the Rust library, for each phone architecture
for t in aarch64-linux-android x86_64-linux-android; do
    T=$(echo "$t" | tr 'a-z-' 'A-Z_')
    export "CARGO_TARGET_${T}_LINKER=$TC/${t}26-clang"
    sh scripts/cargo.sh build --release --locked --target "$t" -p kzsigner-android
done

W=target/apk
rm -rf "$W"
mkdir -p "$W/classes" "$W/dex" "$W/res" "$W/lib/arm64-v8a" "$W/lib/x86_64" dist

# the Java side: compiled, then turned into Android's classes.dex
javac --release 8 -nowarn -encoding UTF-8 -classpath "$JAR" \
    -d "$W/classes" android/java/kz/kzsigner/*.java
"$BT/d8" --release --min-api 26 --lib "$JAR" --output "$W/dex" $(find "$W/classes" -name '*.class' | sort)

# resources and manifest
"$BT/aapt2" compile --no-crunch --dir android/res -o "$W/res.zip"
sed "s/android:versionName=\"[^\"]*\"/android:versionName=\"$V\"/" android/AndroidManifest.xml > "$W/AndroidManifest.xml"
"$BT/aapt2" link -o "$W/base.apk" -I "$JAR" --manifest "$W/AndroidManifest.xml" "$W/res.zip"

# code and libraries; fixed file times so the archive does not depend on when it was built
cp target/aarch64-linux-android/release/libkzsigner_android.so "$W/lib/arm64-v8a/"
cp target/x86_64-linux-android/release/libkzsigner_android.so "$W/lib/x86_64/"
cp "$W/dex/classes.dex" "$W/"
find "$W/lib" "$W/classes.dex" -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$W" && zip -q -X -D -9 base.apk classes.dex &&
    zip -q -X -D -0 base.apk lib/arm64-v8a/libkzsigner_android.so lib/x86_64/libkzsigner_android.so)
# native libraries stay uncompressed and 16 KB aligned (loaded straight from the APK)
"$BT/zipalign" -f -P 16 4 "$W/base.apk" "$W/aligned.apk"

OUT=dist/kzsigner-$V-android.apk
if [ -n "${KZSIGNER_KEYSTORE:-}" ]; then
    "$BT/apksigner" sign --ks "$KZSIGNER_KEYSTORE" --ks-pass env:KZSIGNER_KEYSTORE_PASS \
        --ks-key-alias "${KZSIGNER_KEY_ALIAS:-kzsigner}" --out "$OUT" "$W/aligned.apk"
else
    "$BT/apksigner" sign --ks android/dev.keystore --ks-pass pass:kzsigner-dev \
        --ks-key-alias kzsigner-dev --out "$OUT" "$W/aligned.apk"
fi
"$BT/apksigner" verify --print-certs "$OUT" | head -3
cp "$W/aligned.apk" "$W/unsigned.apk"
ls -la "$OUT"
