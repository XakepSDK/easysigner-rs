package kz.kzsigner.uitest;

import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The test copy (KZSIGNER_SELFTEST=1 sh scripts/apk.sh). Its test of the real screens
 * (src/android/selftest.rs) keeps a key, signs with it, closes a prompt, removes it, and does
 * the same with no screen lock; this answers what it asks for in its log ("NEED n what"):
 * types the PIN, closes the prompt, removes and sets the screen PIN. Then the fingerprint:
 * a fingerprint-only key works with a touch of the virtual sensor and is gone after another
 * finger is enrolled.
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING) // the steps build on each other
public class TestCopy {
    private final Phone phone = new Phone();

    @Test
    public void step1Screens() {
        phone.clearLog();
        phone.start("");
        Phone.sleep(10000);
        phone.start("--ez uitest true");
        Pattern need = Pattern.compile("NEED (\\d+) ([a-z]+)");
        String answered = "";
        long last = SystemClock.uptimeMillis();
        while (true) {
            Phone.sleep(2000);
            String log = phone.appLog();
            if (log.contains("UI PASS")) {
                break;
            }
            if (log.contains("UI FAIL")) {
                phone.fail("screens: " + Phone.line(log, "UI FAIL"));
            }
            if (SystemClock.uptimeMillis() - last > 600_000) {
                phone.fail("screens: no progress for 10 minutes");
            }
            // the newest request, and whether it is done
            String n = null;
            String what = null;
            Matcher m = need.matcher(log);
            while (m.find()) {
                n = m.group(1);
                what = m.group(2);
            }
            if (n == null || Pattern.compile("DONE " + n + "\\s*$", Pattern.MULTILINE).matcher(log).find()) {
                continue;
            }
            if (!n.equals(answered)) {
                Phone.say("screens ask " + n + ": " + what);
                answered = n;
                last = SystemClock.uptimeMillis();
                Phone.sleep(3000);
            }
            switch (what) {
                case "pin":
                    phone.pin();
                    break;
                case "cancel":
                    phone.device.pressBack();
                    break;
                case "nolock":
                    phone.clearPin();
                    break;
                case "lock":
                    phone.setPin();
                    phone.unlock();
                    break;
                default:
                    phone.fail("screens ask for something unknown: " + what);
            }
            Phone.sleep(4000);
        }
        phone.shot("android-screens");
        if (!phone.running()) {
            phone.fail("the test copy stopped");
        }
        Phone.say("screens PASS");
    }

    @Test
    public void step2Fingerprint() {
        phone.enroll(1);
        step("seal");
        phone.enroll(2);
        step("reset");
        Phone.say("fingerprint PASS");
    }

    private void step(String step) {
        for (int attempt = 1; ; attempt++) {
            phone.clearLog();
            phone.start("--es fptest " + step);
            try {
                Phone.say(phone.waitLog("FP PASS " + step, "FP FAIL", 90, () -> Phone.say("FINGER 1")));
                Phone.say("FINGER 0");
                return;
            } catch (AssertionError e) {
                Phone.say("FINGER 0");
                // "status 1": the prompt closed at once, as Android does when it is asked for
                // before the app is in front (right after Settings); once more
                if (attempt >= 2 || String.valueOf(e.getMessage()).indexOf("status 1") < 0) {
                    throw e;
                }
                Phone.say("the prompt closed at once; again");
                Phone.sleep(3000);
            }
        }
    }
}
