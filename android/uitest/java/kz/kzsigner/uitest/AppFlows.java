package kz.kzsigner.uitest;

import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

/**
 * The app (android/compose) on an emulator, as a person uses it. First the phone gets a
 * screen PIN and one enrolled finger, as most phones have.
 *
 * Keys: a key file opened with the app goes to Add key; a GOST 2004 key gets "too old to
 * sign"; a password typed with a Russian keyboard gets the keyboard hint; the right password
 * and a touch of the fingerprint sensor keep the key, which Your keys then lists.
 *
 * Signing: a PDF shared to the app opens on Sign, with its first page and the in-app reader;
 * signing with the test key stops at "isn't recognized" before anything is signed (the test
 * CA is not NCA's; the core's tests sign against fake NCA servers). Removing the key leads
 * back to Add key; a PDF shared then waits there (2c) and comes back once a key is added.
 *
 * Checking: an unsigned PDF is "isn't signed"; a .cms signed with a test key is "do not
 * trust" (not recognized in Kazakhstan), with its details.
 *
 * Then the chip itself: the app's emulator-only check makes keys that open with the
 * fingerprint or PIN, and with the fingerprint only, and uses them. Last, a fingerprint-only
 * key is gone for good once another finger is enrolled (someone who learns the PIN can't add
 * their finger and sign).
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING) // the steps build on each other
public class AppFlows {
    private final Phone phone = new Phone();

    /** Opens a test key file with the app, as "Open with kzsigner" does. */
    private void open(String keyFile) {
        Context c = InstrumentationRegistry.getInstrumentation().getContext();
        Intent i = new Intent(Intent.ACTION_VIEW)
                .setDataAndType(KeyFiles.uri(keyFile), "application/x-pkcs12")
                .setPackage(Phone.APP)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        c.startActivity(i);
        phone.device.wait(Until.hasObject(By.pkg(Phone.APP)), 10000);
    }

    /** Shares a test file to the app, as Share in a messenger does. */
    private void share(String file) {
        Context c = InstrumentationRegistry.getInstrumentation().getContext();
        Intent i = new Intent(Intent.ACTION_SEND)
                .setType("application/pdf")
                .putExtra(Intent.EXTRA_STREAM, KeyFiles.uri(file))
                .setPackage(Phone.APP)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        i.setClipData(android.content.ClipData.newRawUri(file, KeyFiles.uri(file)));
        c.startActivity(i);
        phone.device.wait(Until.hasObject(By.pkg(Phone.APP)), 10000);
    }

    /**
     * Waits for text while answering the chip's prompt: a touch of the fingerprint sensor
     * (scripts/android-selftest.sh), or the PIN on a phone without one.
     */
    private void throughPrompt(String what) {
        long until = SystemClock.uptimeMillis() + 90_000;
        boolean pinTried = false;
        while (!phone.shows(what)) {
            if (SystemClock.uptimeMillis() > until) {
                Phone.say("FINGER 0");
                phone.fail("the Compose app does not show \"" + what + "\". The tree:\n" + phone.tree());
            }
            Phone.say("FINGER 1");
            Phone.sleep(2000);
            if (!pinTried && SystemClock.uptimeMillis() > until - 60_000 && phone.tap("Use PIN")) {
                pinTried = true;
                Phone.sleep(1500);
                phone.pin();
            }
        }
        Phone.say("FINGER 0");
    }

    /** Opens a test file on the app's Check screens (its CHECK action). */
    private void checkFile(String file) {
        Context c = InstrumentationRegistry.getInstrumentation().getContext();
        Intent i = new Intent("kz.kzsigner.action.CHECK")
                .setData(KeyFiles.uri(file))
                .setClassName(Phone.APP, Phone.APP + ".MainActivity")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        c.startActivity(i);
        phone.device.wait(Until.hasObject(By.pkg(Phone.APP)), 10000);
    }

    /** Waits up to 20 seconds for text on screen. */
    private void see(String what) {
        for (int i = 0; i < 20; i++) {
            if (phone.shows(what)) {
                return;
            }
            Phone.sleep(1000);
        }
        phone.fail("the Compose app does not show \"" + what + "\". The tree:\n" + phone.tree());
    }

    private void type(String password) {
        UiObject2 field = phone.device.wait(Until.findObject(By.clazz("android.widget.EditText")), 10000);
        if (field == null) {
            phone.fail("no password field. The tree:\n" + phone.tree());
        }
        field.setText(password);
    }

    /**
     * A screenshot of the screen, and its accessibility check (Phone.a11yProblems): every
     * control named for TalkBack and at least 48 dp.
     */
    private void screen(String name) {
        Phone.sleep(800);
        phone.shot(name);
        String problems = phone.a11yProblems();
        if (!problems.isEmpty()) {
            phone.fail(name + ": accessibility problems:\n" + problems + "The tree:\n" + phone.tree());
        }
    }

    private void tap(String regex) {
        if (!phone.tap(regex)) {
            phone.fail("nothing to tap matches \"" + regex + "\". The tree:\n" + phone.tree());
        }
    }

    @Test
    public void step1StartsOnHome() {
        phone.sh("svc power stayon true");
        phone.sh("settings put system screen_off_timeout 1800000");
        Phone.say("Android " + phone.sh("getprop ro.build.version.release").trim());
        phone.setPin();
        phone.unlock();
        if (phone.fingers() == 0) {
            phone.enroll(1);
        }
        phone.sh("pm clear " + Phone.APP);
        phone.unlock();
        phone.start("");
        phone.device.wait(Until.hasObject(By.pkg(phone.app)), 20000);
        // Home, even with no key: checking needs none, and signing asks for one when needed
        see("Sign a document");
        see("Check a signature");
        see("PDF, Word or any file");
        screen("android-1-home-no-key");
        // signing with no key: two different files to pick, so the key comes first, and says so
        tap("Sign a document");
        see("To sign, first add your key");
        see("Choose the key file");
        screen("android-1-sign-no-key");
        phone.device.pressBack();
        see("Sign a document");
        // what TalkBack reads, through Compose's semantics
        if (!phone.appNames("Add key")) {
            phone.fail("the accessibility tree has no Add key. The tree:\n" + phone.tree());
        }
        tap("Add key");
        see("Add your signature key");
        see("Choose the key file");
        screen("android-1-add");
        phone.device.pressBack();
        see("Sign a document");
    }

    @Test
    public void step2OldKeyCantSign() {
        open("alice_gost2004.p12");
        see("alice_gost2004.p12");
        type("Qwerty12");
        tap("Continue");
        see("This key is too old to sign");
        screen("android-2-old-key");
        tap("Add a new key");
        see("Choose the key file");
    }

    @Test
    public void step3WrongPasswordThenAdd() {
        open("alice_rsa.p12");
        see("alice_rsa.p12");
        // the password typed with the keyboard in Russian: the same keys, other letters
        type("Йцукен12");
        tap("Continue");
        see("That password doesn't open this key");
        see("Is the keyboard in Russian or Kazakh");
        screen("android-3-wrong-password");

        type("Qwerty12");
        tap("Try again");
        // the first key: on to Home
        throughPrompt("Sign a document");
        screen("android-4-home");
        tap("Your keys");
        see("Иванов Алибек");
        // emulators keep keys in software only, so the core uses the key's password there
        // (step6 checks the fingerprint prompt itself)
        see("Opens with");
        screen("android-5-keys");
        phone.device.pressBack();
        see("Sign a document");
    }

    @Test
    public void step4SignSharedPdf() {
        share("plain.pdf");
        see("Sign this document");
        see("plain.pdf");
        see("Иванов Алибек");
        screen("android-6-sign");

        tap("Read it");
        see("Page 1 of");
        screen("android-7-read");
        phone.device.pressBack();
        see("Sign this document");

        // a key kept under its password (emulator) asks for it on this screen
        if (phone.device.wait(Until.hasObject(By.clazz("android.widget.EditText")), 3000)) {
            type("Qwerty12");
        }
        tap("Sign");
        throughPrompt("isn't recognized");
        screen("android-8-not-recognized");
        phone.device.pressBack();
        see("Sign this document");
        phone.device.pressBack();
        see("Sign a document");
        Phone.say("the Compose app takes a shared PDF to Sign and asks NCA before signing");
    }

    @Test
    public void step4bCheck() {
        // an unsigned PDF
        checkFile("plain.pdf");
        see("This file isn't signed");
        screen("android-check-1-not-signed");
        tap("Check another file");
        see("Sign a document");

        // a .cms signed with a test key: its CA is not NCA's
        checkFile("lta.cms");
        see("Do not trust this document");
        see("isn't recognized in Kazakhstan");
        screen("android-check-2-not-recognized");
        tap("Details");
        see("Signature details");
        see("CAdES");
        screen("android-check-3-details");
        phone.device.pressBack();
        see("Do not trust this document");
        phone.device.pressBack();
        see("Sign a document");
        Phone.say("the Compose app checks an unsigned and a signed file");
    }

    @Test
    public void step5RemoveThenSharedBeforeKey() {
        tap("Your keys");
        // the screen slides in: wait for it
        see("Opens with");
        Phone.sleep(1000);
        tap("Remove from this phone");
        see("from this phone\\?");
        screen("android-9-remove");
        tap("Remove");
        see("PDF, Word or any file");
        Phone.say("the Compose app adds, lists and removes a key");

        // 2c: a PDF shared with no key waits on Add key, and comes back once one is added
        share("plain.pdf");
        see("To sign plain.pdf, first add your key");
        screen("android-10-shared-no-key");
        open("alice_rsa.p12");
        see("alice_rsa.p12");
        type("Qwerty12");
        tap("Continue");
        throughPrompt("Sign this document");
        see("plain.pdf");
        Phone.say("the Compose app brings a shared PDF back after adding the first key");
    }

    @Test
    public void step6ChipPrompts() {
        phone.clearLog();
        phone.start("--ez chiptest true");
        Phone.say(phone.waitLog("CHIP PASS", "CHIP FAIL", 120, () -> Phone.say("FINGER 1")));
        Phone.say("FINGER 0");
    }

    /**
     * Text at 200 % (Settings > Display > Font size, and the accessibility setting beyond
     * it): the main screens still show their titles and actions, reachable by scrolling, and
     * pass the same accessibility check.
     */
    @Test
    public void step6bLargeText() {
        phone.sh("settings put system font_scale 2.0");
        try {
            phone.device.pressBack();
            phone.start("");
            see("Sign a document");
            screen("android-big-1-home");
            share("plain.pdf");
            see("Sign this document");
            screen("android-big-2-sign");
            scrollTo("^Sign$");
            screen("android-big-3-sign-button");
            phone.device.pressBack();
            see("Sign a document");
            tap("Your keys");
            see("Иванов Алибек");
            screen("android-big-4-keys");
            phone.device.pressBack();
        } finally {
            phone.sh("settings put system font_scale 1.0");
        }
        Phone.say("the app works with text at 200 %");
    }

    /** Scrolls the screen's list until something matching `regex` (whole text) shows. */
    private void scrollTo(String regex) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.CASE_INSENSITIVE);
        for (int i = 0; i < 8; i++) {
            if (phone.device.hasObject(By.text(p)) || phone.device.hasObject(By.desc(p))) {
                return;
            }
            UiObject2 list = phone.device.findObject(By.scrollable(true));
            if (list == null) {
                break;
            }
            list.scroll(androidx.test.uiautomator.Direction.DOWN, 0.8f);
            Phone.sleep(500);
        }
        if (!phone.device.hasObject(By.text(p)) && !phone.device.hasObject(By.desc(p))) {
            phone.fail("\"" + regex + "\" can't be reached by scrolling. The tree:\n" + phone.tree());
        }
    }

    @Test
    public void step7NewFingerResetsFingerprintOnlyKeys() {
        reset("seal");
        phone.enroll(2);
        reset("check");
        Phone.say("a new finger resets fingerprint-only keys");
    }

    private void reset(String step) {
        for (int attempt = 1; ; attempt++) {
            phone.clearLog();
            phone.start("--es chipreset " + step);
            try {
                Phone.say(phone.waitLog("RESET PASS " + step, "RESET FAIL", 90, () -> Phone.say("FINGER 1")));
                Phone.say("FINGER 0");
                return;
            } catch (AssertionError e) {
                Phone.say("FINGER 0");
                // the prompt closes at once when asked for before the app is in front (right
                // after Settings); once more
                if (attempt >= 2) {
                    throw e;
                }
                Phone.say("again");
                Phone.sleep(3000);
            }
        }
    }
}
