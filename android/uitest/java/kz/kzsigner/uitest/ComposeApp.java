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
 * The Kotlin + Compose app (docs/compose-plan.md), installed next to the released app as
 * kz.kzsigner.next. Runs after TestCopy, which leaves a screen PIN and two enrolled fingers.
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
 * Then the chip itself: the app's emulator-only check makes keys that open with the
 * fingerprint or PIN, and with the fingerprint only, and uses them.
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING) // the steps build on each other
public class ComposeApp {
    private final Phone phone = new Phone(Phone.NEXT);

    /** Opens a test key file with the app, as "Open with kzsigner" does. */
    private void open(String keyFile) {
        Context c = InstrumentationRegistry.getInstrumentation().getContext();
        Intent i = new Intent(Intent.ACTION_VIEW)
                .setDataAndType(KeyFiles.uri(keyFile), "application/x-pkcs12")
                .setPackage(Phone.NEXT)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        c.startActivity(i);
        phone.device.wait(Until.hasObject(By.pkg(Phone.NEXT)), 10000);
    }

    /** Shares a test file to the app, as Share in a messenger does. */
    private void share(String file) {
        Context c = InstrumentationRegistry.getInstrumentation().getContext();
        Intent i = new Intent(Intent.ACTION_SEND)
                .setType("application/pdf")
                .putExtra(Intent.EXTRA_STREAM, KeyFiles.uri(file))
                .setPackage(Phone.NEXT)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        i.setClipData(android.content.ClipData.newRawUri(file, KeyFiles.uri(file)));
        c.startActivity(i);
        phone.device.wait(Until.hasObject(By.pkg(Phone.NEXT)), 10000);
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

    private void tap(String regex) {
        if (!phone.tap(regex)) {
            phone.fail("nothing to tap matches \"" + regex + "\". The tree:\n" + phone.tree());
        }
    }

    @Test
    public void step1StartsOnAddKey() {
        phone.sh("svc power stayon true");
        phone.sh("pm clear " + Phone.NEXT);
        phone.unlock();
        phone.start("");
        phone.device.wait(Until.hasObject(By.pkg(phone.app)), 20000);
        see("Add your signature key");
        see("Choose the key file");
        phone.shot("android-next-1-add");
        // what TalkBack reads, through Compose's semantics
        if (!phone.appNames("Add your signature key")) {
            phone.fail("the accessibility tree has no title. The tree:\n" + phone.tree());
        }
    }

    @Test
    public void step2OldKeyCantSign() {
        open("alice_gost2004.p12");
        see("alice_gost2004.p12");
        type("Qwerty12");
        tap("Continue");
        see("This key is too old to sign");
        phone.shot("android-next-2-old-key");
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
        phone.shot("android-next-3-wrong-password");

        type("Qwerty12");
        tap("Try again");
        // the first key: on to Home
        throughPrompt("Sign a document");
        phone.shot("android-next-4-home");
        tap("Your keys");
        see("Иванов Алибек");
        // emulators keep keys in software only, so the core uses the key's password there
        // (step6 checks the fingerprint prompt itself)
        see("Opens with");
        phone.shot("android-next-5-keys");
        phone.device.pressBack();
        see("Sign a document");
    }

    @Test
    public void step4SignSharedPdf() {
        share("plain.pdf");
        see("Sign this document");
        see("plain.pdf");
        see("Иванов Алибек");
        phone.shot("android-next-6-sign");

        tap("Read it");
        see("Page 1 of");
        phone.shot("android-next-7-read");
        phone.device.pressBack();
        see("Sign this document");

        // a key kept under its password (emulator) asks for it on this screen
        if (phone.device.wait(Until.hasObject(By.clazz("android.widget.EditText")), 3000)) {
            type("Qwerty12");
        }
        tap("Sign");
        throughPrompt("isn't recognized");
        phone.shot("android-next-8-not-recognized");
        phone.device.pressBack();
        see("Sign this document");
        phone.device.pressBack();
        see("Sign a document");
        Phone.say("the Compose app takes a shared PDF to Sign and asks NCA before signing");
    }

    @Test
    public void step5RemoveThenSharedBeforeKey() {
        tap("Your keys");
        tap("Remove from this phone");
        see("from this phone\\?");
        phone.shot("android-next-9-remove");
        tap("Remove");
        see("Choose the key file");
        Phone.say("the Compose app adds, lists and removes a key");

        // 2c: a PDF shared with no key waits on Add key, and comes back once one is added
        share("plain.pdf");
        see("To sign plain.pdf, first add your key");
        phone.shot("android-next-10-shared-no-key");
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
}
