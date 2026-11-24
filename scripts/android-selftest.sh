#!/bin/sh
# Runs on CI's Android emulators (see .github/workflows/build.yml):
#
#   sh scripts/android-selftest.sh APK UITEST_APK FAKE_NCA
#
# APK is the app's test build (kzsigner-test-app.apk): the released app, except that it talks
# to fake NCA servers on this machine (the emulator's 10.0.2.2) and trusts the test keys' CAs,
# so the tests can add a test key and sign with it. FAKE_NCA is those servers
# (examples/fake_nca.rs, built for this machine); this script starts them, from the checkout's
# root (they read tests/fixtures).
# The tests are UI Automator tests in android/uitest (UITEST_APK, built by
# KZSIGNER_UITEST=1 sh scripts/apk.sh); they run on the emulator in their own process. This
# script only installs the APKs, runs the tests (AppFlows), and does the one thing a test on
# the phone can't: touching the virtual fingerprint sensor, while a test logs "FINGER n".
# Screenshots: android-*.png, also printed into the log.
set -u
APK=$1
UITEST_APK=$2
FAKE_NCA=$3
RUNNER=kz.kzsigner.uitest/androidx.test.runner.AndroidJUnitRunner

# a screenshot, also printed into the log (base64 between markers): CI's artifacts are not
# reachable from everywhere the log is
shots() {
    for f in $(adb shell ls /data/local/tmp/kzuitest/ 2>/dev/null); do
        adb pull -q "/data/local/tmp/kzuitest/$f" "$f" > /dev/null 2>&1 || continue
        echo "--- screenshot $f"
        base64 -w 0 "$f"
        echo
        echo "--- end $f"
    done
    adb shell rm -rf /data/local/tmp/kzuitest
}

# runs one test class; touches the fingerprint sensor while the test asks for it
run() {
    adb logcat -c
    adb shell am instrument -w -r -e class "kz.kzsigner.uitest.$1" "$RUNNER" > instrument.txt 2>&1 &
    test=$!
    while kill -0 "$test" 2>/dev/null; do
        sleep 2
        f=$(adb logcat -d -s KZUITEST:* | grep -o 'FINGER [0-9]*' | tail -1 | cut -d' ' -f2)
        [ -n "$f" ] && [ "$f" != 0 ] && adb emu finger touch "$f" > /dev/null 2>&1
    done
    wait "$test"
    adb logcat -d -s KZUITEST:* KZSELFTEST:*
    grep -E 'INSTRUMENTATION_STATUS: (test|stack)=|^OK|FAILURES|Tests run' instrument.txt
    shots
    grep -q '^OK (' instrument.txt || {
        echo "FAIL: $1"
        cat instrument.txt
        exit 1
    }
    echo "$1 PASS"
}

chmod +x "$FAKE_NCA"
"$FAKE_NCA" > fake-nca.log 2>&1 &
nca=$!
trap 'kill $nca 2>/dev/null; echo "--- fake NCA log"; cat fake-nca.log' EXIT
sleep 1
kill -0 "$nca" || { cat fake-nca.log; exit 1; }

adb install -r "$UITEST_APK" || exit 1
adb install -r "$APK" || exit 1
run AppFlows
