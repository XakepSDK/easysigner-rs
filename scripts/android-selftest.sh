#!/bin/sh
# Runs on CI's Android emulator (see .github/workflows/build.yml), with the APK in dist/.
# Sets a screen PIN, starts the app, checks the back button, takes a screenshot, then runs
# the app's self-test of the security chip code (MainActivity.selfTest), typing the PIN into
# each system prompt it shows. Fails unless the self-test logs PASS and the app still runs.
set -u
PIN=1111
fail() { echo "FAIL: $*"; adb logcat -d -s KZSELFTEST:* kzsigner:* RustStdoutStderr:* AndroidRuntime:* | tail -80; exit 1; }

adb shell svc power stayon true
adb shell locksettings set-pin "$PIN" || fail "could not set a screen PIN"
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
adb install -r dist/*.apk || fail "install"
adb logcat -c

adb shell am start -W -n kz.kzsigner/.MainActivity
sleep 20
adb shell pidof kz.kzsigner >/dev/null || fail "the app stopped after starting"
adb exec-out screencap -p > android-start.png

# back on the start screen: the app goes behind the others and keeps running
adb shell input keyevent KEYCODE_BACK
sleep 3
adb shell pidof kz.kzsigner >/dev/null || fail "the app stopped on Back"

adb shell am start -W -n kz.kzsigner/.MainActivity --ez selftest true
# the self-test shows the PIN prompt three times (seal, open, and a changed box)
i=0
while [ $i -lt 40 ]; do
    i=$((i + 1))
    sleep 3
    log=$(adb logcat -d -s KZSELFTEST:*)
    case "$log" in
    *PASS*) break ;;
    *FAIL*) fail "self-test" ;;
    esac
    # the PIN, whether or not a prompt is up: with none, the start screen ignores it
    adb shell input text "$PIN"
    adb shell input keyevent KEYCODE_ENTER
done
adb logcat -d -s KZSELFTEST:*
adb exec-out screencap -p > android-selftest.png
echo "$log" | grep -q PASS || fail "self-test did not finish"
adb shell pidof kz.kzsigner >/dev/null || fail "the app stopped"
echo "self-test PASS"
