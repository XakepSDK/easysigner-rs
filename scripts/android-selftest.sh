#!/bin/sh
# Runs on CI's Android emulators (see .github/workflows/build.yml):
#
#   sh scripts/android-selftest.sh APK SELFTEST_APK
#
# 1. APK (the one released): starts, keeps running after Back on the start screen, and its
#    security chip code passes MainActivity.selfTest with a screen PIN set.
# 2. SELFTEST_APK (the test copy, KZSIGNER_SELFTEST=1 sh scripts/apk.sh): its test of the real
#    screens (src/android/selftest.rs) keeps a key, signs with it, closes a prompt, removes
#    it, and does the same with no screen lock. This script answers what it asks for in the
#    log: types the PIN into the prompt, closes the prompt, removes and sets the screen PIN.
# Screenshots: android-*.png. Fails unless both log PASS and the app still runs.
set -u
APK=$1
TEST_APK=$2
PIN=1111
fail() {
    echo "FAIL: $*"
    shot android-fail.png
    adb logcat -d -s KZSELFTEST:* kzsigner:* RustStdoutStderr:* AndroidRuntime:* DEBUG:* | tail -120
    exit 1
}
# a screenshot, also printed into the log (base64 between markers): CI's artifacts are not
# reachable from everywhere the log is
shot() {
    adb exec-out screencap -p > "$1"
    echo "--- screenshot $1"
    base64 -w 0 "$1"
    echo
    echo "--- end $1"
}
pin() { adb shell input text "$PIN"; adb shell input keyevent KEYCODE_ENTER; }

adb shell svc power stayon true
adb shell settings put system screen_off_timeout 1800000
adb shell locksettings set-pin "$PIN" || fail "could not set a screen PIN"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
echo "Android $(adb shell getprop ro.build.version.release)"

# --- the released APK
adb install -r "$APK" || fail "install"
adb logcat -c
adb shell am start -W -n kz.kzsigner/.MainActivity
sleep 20
adb shell pidof kz.kzsigner >/dev/null || fail "the app stopped after starting"
shot android-start.png
adb shell input keyevent KEYCODE_BACK
sleep 3
adb shell pidof kz.kzsigner >/dev/null || fail "the app stopped on Back"

adb shell am start -W -n kz.kzsigner/.MainActivity --ez selftest true
# the self-test shows the PIN prompt three times (seal, open, and a changed box)
i=0
log=
while [ $i -lt 40 ]; do
    i=$((i + 1))
    sleep 3
    log=$(adb logcat -d -s KZSELFTEST:*)
    case "$log" in
    *PASS*) break ;;
    *FAIL*) fail "chip self-test" ;;
    esac
    # the PIN, whether or not a prompt is up: with none, the start screen ignores it
    pin
done
echo "$log"
echo "$log" | grep -q PASS || fail "chip self-test did not finish"
adb shell pidof kz.kzsigner >/dev/null || fail "the app stopped"
echo "chip self-test PASS"

# --- the test copy: the real screens
adb uninstall kz.kzsigner > /dev/null
adb install -r "$TEST_APK" || fail "install the test copy"
adb logcat -c
adb shell am start -W -n kz.kzsigner/.MainActivity
sleep 10
adb shell am start -W -n kz.kzsigner/.MainActivity --ez uitest true
answered=0
last=$(date +%s)
while :; do
    sleep 2
    log=$(adb logcat -d -s KZSELFTEST:*)
    case "$log" in
    *"UI PASS"*) break ;;
    *"UI FAIL"*) fail "screens: $(echo "$log" | grep -o 'UI FAIL.*' | head -1)" ;;
    esac
    [ $(($(date +%s) - last)) -lt 600 ] || fail "screens: no progress for 10 minutes"
    # the newest request, and whether it is done
    req=$(echo "$log" | grep -o 'NEED [0-9]* [a-z]*' | tail -1)
    [ -n "$req" ] || continue
    n=$(echo "$req" | cut -d' ' -f2)
    what=$(echo "$req" | cut -d' ' -f3)
    if echo "$log" | grep -qE "DONE $n[[:space:]]*$"; then
        continue
    fi
    if [ "$n" != "$answered" ]; then
        echo "screens ask $n: $what"
        answered=$n
        last=$(date +%s)
        sleep 3
    fi
    case $what in
    pin) pin ;;
    cancel) adb shell input keyevent KEYCODE_BACK ;;
    nolock) adb shell locksettings clear --old "$PIN" ;;
    lock) adb shell locksettings set-pin "$PIN" ;;
    esac
    sleep 4
done
echo "$log" | grep -E "UI |NEED|DONE"
shot android-screens.png
adb shell pidof kz.kzsigner >/dev/null || fail "the test copy stopped"
echo "screens PASS"
