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
# 3. Fingerprint (with the test copy still installed): enrolls a finger through Settings,
#    then a fingerprint-only key works with a touch of the virtual sensor, and is gone after
#    another finger is enrolled.
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
# taps the first thing on screen whose text or description matches $1 (a regex, any case)
tap_text() {
    adb shell uiautomator dump /sdcard/ui.xml > /dev/null 2>&1 || return 1
    xy=$(adb shell cat /sdcard/ui.xml | python3 -c '
import re, sys
x = sys.stdin.read()
p = re.compile(sys.argv[1], re.I)
for n in re.findall(r"<node [^>]*>", x):
    t = re.search(r"\btext=\"([^\"]*)\"", n)
    d = re.search(r"content-desc=\"([^\"]*)\"", n)
    if any(m and p.fullmatch(m.group(1).strip()) for m in (t, d)):
        b = re.search(r"bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", n)
        if b:
            a = list(map(int, b.groups()))
            print((a[0] + a[2]) // 2, (a[1] + a[3]) // 2)
            break
' "$1")
    [ -n "$xy" ] || return 1
    # shellcheck disable=SC2086
    adb shell input tap $xy
}
# whether the screen shows text matching $1
shows() {
    adb shell uiautomator dump /sdcard/ui.xml > /dev/null 2>&1
    adb shell cat /sdcard/ui.xml | grep -qiE "$1"
}
fingers() {
    adb shell dumpsys fingerprint | grep -oE '"count":[0-9]+' | head -1 | cut -d: -f2
}
# enrolls virtual finger $1 through Settings, touching the sensor until it is added
enroll() {
    want=$(($(fingers || echo 0) + 1))
    adb shell am start -a android.settings.FINGERPRINT_ENROLL > /dev/null
    i=0
    while [ $i -lt 90 ]; do
        i=$((i + 1))
        sleep 2
        [ "$(fingers || echo 0)" -ge "$want" ] 2>/dev/null && break
        if shows '(Re-enter|Confirm|Enter) your (device )?PIN'; then pin; continue; fi
        tap_text '(I agree|Agree|Next|Continue|Start|More|Accept|OK|Got it)' || true
        adb emu finger touch "$1" > /dev/null 2>&1
    done
    tap_text '(Done|Next|Finish)' || true
    adb shell input keyevent KEYCODE_HOME
    [ "$(fingers || echo 0)" -ge "$want" ] 2>/dev/null || fail "could not enroll finger $1"
    echo "enrolled finger $1"
}
# locks the screen and unlocks it with the PIN: the Keystore lets keys that need an unlocked
# device work only after a real unlock with the screen lock
unlock() {
    adb shell input keyevent KEYCODE_SLEEP
    sleep 2
    adb shell input keyevent KEYCODE_WAKEUP
    sleep 1
    adb shell wm dismiss-keyguard
    sleep 1
    adb shell input swipe 500 1500 500 300
    sleep 1
    pin
    sleep 3
}
pin() { adb shell input text "$PIN"; adb shell input keyevent KEYCODE_ENTER; }

adb shell svc power stayon true
adb shell settings put system screen_off_timeout 1800000
adb shell locksettings set-pin "$PIN" || fail "could not set a screen PIN"
unlock
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
    lock) adb shell locksettings set-pin "$PIN" && unlock ;;
    esac
    sleep 4
done
echo "$log" | grep -E "UI |NEED|DONE"
shot android-screens.png
adb shell pidof kz.kzsigner >/dev/null || fail "the test copy stopped"
echo "screens PASS"

# --- fingerprint
enroll 1
fp_step() {
    adb logcat -c
    adb shell am start -W -n kz.kzsigner/.MainActivity --es fptest "$1" > /dev/null
    i=0
    while [ $i -lt 30 ]; do
        i=$((i + 1))
        sleep 3
        log=$(adb logcat -d -s KZSELFTEST:*)
        case "$log" in
        *"FP PASS $1"*) echo "$log"; return 0 ;;
        *"FP FAIL"*) fail "fingerprint $1" ;;
        esac
        adb emu finger touch 1 > /dev/null 2>&1
    done
    fail "fingerprint $1 did not finish"
}
fp_step seal
enroll 2
fp_step reset
echo "fingerprint PASS"
