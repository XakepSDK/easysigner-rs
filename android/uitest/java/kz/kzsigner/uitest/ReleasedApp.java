package kz.kzsigner.uitest;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

/**
 * The APK as released: it starts, shows its start screen to screen readers, keeps running
 * after Back on the start screen, and its security chip code passes MainActivity.selfTest
 * with a screen PIN set.
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING) // the steps build on each other
public class ReleasedApp {
    private final Phone phone = new Phone();

    @Test
    public void step1StartsAndReadsAloud() {
        phone.sh("svc power stayon true");
        phone.sh("settings put system screen_off_timeout 1800000");
        phone.setPin();
        phone.unlock();
        Phone.say("Android " + phone.sh("getprop ro.build.version.release").trim());

        phone.clearLog();
        phone.start("");
        phone.device.wait(androidx.test.uiautomator.Until.hasObject(
                androidx.test.uiautomator.By.pkg(phone.app)), 20000);
        Phone.sleep(5000);
        if (!phone.running()) {
            phone.fail("the app stopped after starting");
        }
        phone.shot("android-start");
        // what TalkBack reads: Android's accessibility tree (AccessKit) must name the start
        // screen's choices and the language menu
        for (String want : new String[] {"Sign a document", "Check a signed file", "English"}) {
            if (!phone.appNames(want)) {
                phone.fail("the accessibility tree has no \"" + want + "\": a screen reader can't see it. The tree:\n" + phone.tree());
            }
        }
        Phone.say("accessibility tree OK");

        phone.device.pressBack();
        Phone.sleep(3000);
        if (!phone.running()) {
            phone.fail("the app stopped on Back");
        }
    }

    @Test
    public void step2ChipWorks() {
        phone.clearLog();
        phone.start("--ez selftest true");
        // the self-test shows the PIN prompt three times (seal, open, and a changed box); the
        // PIN goes in whether or not a prompt is up: with none, the start screen ignores it
        String log = phone.waitLog("PASS", "FAIL", 120, phone::pin);
        Phone.say(log);
        if (!phone.running()) {
            phone.fail("the app stopped");
        }
        Phone.say("chip self-test PASS");
    }
}
