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
 * The app (android/compose) on an emulator, as a person uses it, every flow. First the phone
 * gets a screen PIN and one enrolled finger, as most phones have. The app is the test build
 * (build type "uitest"): it talks to fake NCA servers on the test machine
 * (examples/fake_nca.rs, started by scripts/android-selftest.sh) and trusts the test CAs, so
 * the test key carol.p12 signs for real. {@link #nca} switches what those servers answer.
 *
 * Start: Home with no key; Sign then asks for the key first, and Add key says so.
 *
 * Keys: a key file opened with the app goes to Add key; a GOST 2004 key gets "too old to
 * sign"; a password typed with a Russian keyboard gets the keyboard hint; the right password
 * (and the fingerprint, on a phone that keeps keys in its chip) keeps the key, which Your keys
 * then lists.
 *
 * Signing: a shared PDF (read in the app, signed, sent), a text file (a new .cms), an XML file,
 * a signed .cms and a signed PDF (the signature joins theirs), and a detached .cms (can't be
 * signed here). NCA says the key is revoked: refused. NCA's OCSP or time server is down: "Can't
 * reach NCA", and Try again signs once it is back.
 *
 * Checking: not signed (then "Sign it myself"), valid (with its details), revoked, valid with
 * NCA's kept answer while NCA is down, changed, a key not recognized in Kazakhstan, and a
 * detached .cms: alone, with its document, and with another document.
 *
 * Then removing the key, a PDF shared before any key, About and the language, and text at
 * 200 %. Last the chip itself: the app's emulator-only check makes keys that open with the
 * fingerprint or PIN, and with the fingerprint only, and uses them; a fingerprint-only key is
 * gone for good once another finger is enrolled. The chip's own prompt at signing (and its
 * cancel and reset there) can't be reached through the app on an emulator, which keeps keys
 * in software and so uses the password; ChipSelfTest covers the chip.
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
                .setType(KeyFiles.mime(file))
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
        checkFile(file, null);
    }

    /** The same, for a detached .cms with the document it signs. */
    private void checkFile(String file, String document) {
        Context c = InstrumentationRegistry.getInstrumentation().getContext();
        Intent i = new Intent("kz.kzsigner.action.CHECK")
                .setData(KeyFiles.uri(file))
                .setClassName(Phone.APP, Phone.APP + ".MainActivity")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        if (document != null) {
            android.content.ClipData clip = android.content.ClipData.newRawUri(file, KeyFiles.uri(file));
            clip.addItem(new android.content.ClipData.Item(KeyFiles.uri(document)));
            i.setClipData(clip);
        }
        c.startActivity(i);
        phone.device.wait(Until.hasObject(By.pkg(Phone.APP)), 10000);
    }

    /**
     * Waits up to 20 seconds for text on screen, scrolling the screen's list to find it (down
     * to the end, then back to the top).
     */
    private void see(String what) {
        boolean down = true;
        for (int i = 0; i < 20; i++) {
            if (phone.shows(what)) {
                return;
            }
            Phone.sleep(1000);
            UiObject2 list = i >= 1 ? phone.device.findObject(By.scrollable(true)) : null;
            if (list != null) {
                try {
                    if (!list.scroll(down ? androidx.test.uiautomator.Direction.DOWN : androidx.test.uiautomator.Direction.UP, 0.6f)) {
                        down = !down;
                    }
                } catch (RuntimeException e) {
                    // the screen changed meanwhile
                }
            }
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

    /**
     * What the fake NCA servers answer: "good", "revoked" (OCSP says every key is revoked),
     * "ocsp-down", "tsa-down" (HTTP 500) or "up" (all good again).
     */
    private void nca(String mode) {
        try {
            java.net.HttpURLConnection h = (java.net.HttpURLConnection)
                    new java.net.URL("http://10.0.2.2:18082/").openConnection();
            h.setDoOutput(true);
            h.setConnectTimeout(10000);
            h.setReadTimeout(10000);
            h.getOutputStream().write(mode.getBytes("UTF-8"));
            int code = h.getResponseCode();
            h.disconnect();
            if (code != 200) {
                phone.fail("the fake NCA servers refused \"" + mode + "\": HTTP " + code);
            }
            Phone.say("fake NCA: " + mode);
        } catch (java.io.IOException e) {
            phone.fail("can't reach the fake NCA servers (scripts/android-selftest.sh starts them): " + e);
        }
    }

    /** Signs on the Sign screen: the key's password where it asks (emulator), then `button`. */
    private void signWith(String button) {
        if (phone.device.wait(Until.hasObject(By.clazz("android.widget.EditText")), 3000)) {
            type("Qwerty12");
        }
        scrollTo(button);
        tap(button);
    }

    /** After signing: the Signed screen with NCA's time, then Done back to Home. */
    private void signed(String shot) {
        throughPrompt("Signing time confirmed by NCA");
        see("^Signed$");
        see("Send the file, not a printout");
        screen(shot);
        tap("Done");
        see("Sign a document");
    }

    /** carol's name, as Your keys and the Sign screen show it. */
    private static final String CAROL = "(?iu)данияр";

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
        nca("up");
        open("carol.p12");
        see("carol.p12");
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
        see(CAROL);
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
        see(CAROL);
        see("Who signed");
        screen("android-6-sign");

        tap("Read it");
        see("Page 1 of");
        screen("android-7-read");
        phone.device.pressBack();
        see("Sign this document");

        // not read again: Sign doesn't wait for it
        signWith("Sign");
        throughPrompt("Signing time confirmed by NCA");
        see("^Signed$");
        screen("android-8-signed");
        // Send hands the file to the phone's share sheet
        tap("Send");
        Phone.sleep(2500);
        screen("android-8b-send");
        phone.device.pressBack();
        see("Done");
        tap("Done");
        see("Sign a document");
        Phone.say("the Compose app signs a shared PDF with NCA's time");
    }

    @Test
    public void step4aSignOtherFiles() {
        // any other file: a new .cms with it inside
        share("doc.txt");
        see("Sign this document");
        see("one .cms file");
        see("Opens in another app");
        signWith("Sign");
        signed("android-sign-txt");

        // XML: the signature goes inside it
        share("act.xml");
        see("Sign this document");
        see("inside this XML file");
        signWith("Sign");
        signed("android-sign-xml");

        // a signed .cms: the signature joins theirs
        share("act.txt.cms");
        see("Add your signature");
        see("Already signed by");
        see("joins");
        screen("android-sign-join-cms");
        signWith("Add my signature");
        signed("android-sign-join-cms-done");

        // a signed PDF: the name joins the "Who signed" page
        share("contract-signed.pdf");
        see("Add your signature");
        see("Already signed by");
        see("Who signed");
        screen("android-sign-join-pdf");
        signWith("Add my signature");
        signed("android-sign-join-pdf-done");

        // a detached .cms holds no document: nothing to sign here
        share("doc.txt.cms");
        see("holds only signatures");
        screen("android-sign-detached");
        phone.device.pressBack();
        see("Sign a document");
        Phone.say("the Compose app signs text, XML, and joins signed .cms and PDF files");
    }

    @Test
    public void step4bNcaRefusesOrIsDown() {
        try {
            // NCA says the key is revoked: nothing is signed
            nca("revoked");
            share("plain.pdf");
            see("Sign this document");
            signWith("Sign");
            throughPrompt("Your key was revoked");
            see("NCA says this key no longer works");
            screen("android-sign-revoked");
            phone.device.pressBack();
            see("Sign this document");

            // NCA's OCSP server is down, then its time server: Try again once it's back
            for (String down : new String[] {"ocsp-down", "tsa-down"}) {
                nca("up");
                nca(down);
                signWith("Sign");
                // NCA down; "No internet" if the emulator's network isn't validated
                throughPrompt("reach NCA right now|^No internet$");
                screen("android-sign-" + down);
                nca("up");
                tap("Try again");
                throughPrompt("Signing time confirmed by NCA");
                see("^Signed$");
                tap("Done");
                see("Sign a document");
                if (down.equals("ocsp-down")) {
                    share("plain.pdf");
                    see("Sign this document");
                }
            }
        } finally {
            nca("up");
        }
        Phone.say("the Compose app refuses a revoked key and retries when NCA is back");
    }

    @Test
    public void step4cCheck() {
        // an unsigned PDF; then signing it from there
        checkFile("plain.pdf");
        see("This file isn't signed");
        screen("android-check-1-not-signed");
        tap("Sign it myself");
        see("Sign this document");
        see("plain.pdf");
        phone.device.pressBack();
        see("Sign a document");

        // signed by carol: valid, with NCA's answer in the details
        checkFile("contract-signed.pdf");
        see("The signature is valid");
        see(CAROL);
        screen("android-check-2-valid");
        scrollTo("Details");
        tap("Details");
        see("Signature details");
        see("PAdES");
        see("Not revoked: NCA confirmed the key");
        see("timestamp by NCA");
        screen("android-check-3-details");
        phone.device.pressBack();
        see("The signature is valid");
        phone.device.pressBack();
        see("Sign a document");

        try {
            // NCA says carol's key is revoked
            nca("revoked");
            checkFile("contract-signed.pdf");
            see("Do not trust this document");
            see("The signer's key was revoked");
            screen("android-check-4-revoked");
            scrollTo("Details");
            tap("Details");
            see("Revoked: NCA cancelled this key");
            phone.device.pressBack();
            phone.device.pressBack();
            see("Sign a document");

            // NCA is down: the answer kept in the signature at signing still counts
            nca("ocsp-down");
            checkFile("contract-signed.pdf");
            see("The signature is valid");
            scrollTo("Details");
            tap("Details");
            see("answer kept in the signature");
            screen("android-check-5-kept");
            phone.device.pressBack();
            phone.device.pressBack();
            see("Sign a document");
        } finally {
            nca("up");
        }

        // changed after it was signed
        checkFile("act-changed.txt.cms");
        see("Do not trust this document");
        see("Changed after it was signed");
        screen("android-check-6-changed");
        tap("Check another file");
        see("Sign a document");

        // a .cms signed with a test key whose CA is not NCA's
        checkFile("lta.cms");
        see("Do not trust this document");
        see("isn't recognized in Kazakhstan");
        screen("android-check-7-not-recognized");
        scrollTo("Details");
        tap("Details");
        see("CAdES");
        phone.device.pressBack();
        phone.device.pressBack();
        see("Sign a document");

        // a detached .cms: asks for its document
        checkFile("doc.txt.cms");
        see("Choose the signed document");
        see("Choose the document");
        screen("android-check-8-needs-document");
        phone.device.pressBack();
        see("Sign a document");
        // with it: NCA's answer for this key (a Kalkan test key) can't be confirmed
        checkFile("doc.txt.cms", "doc.txt");
        see("Couldn't confirm the signature");
        screen("android-check-9-unknown");
        tap("Check again");
        see("Couldn't confirm the signature");
        phone.device.pressBack();
        see("Sign a document");
        // with another document: changed
        checkFile("doc.txt.cms", "plain.pdf");
        see("Changed after it was signed");
        phone.device.pressBack();
        see("Sign a document");
        Phone.say("the Compose app checks unsigned, valid, revoked, changed, unrecognized and detached files");
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
        open("carol.p12");
        see("carol.p12");
        type("Qwerty12");
        tap("Continue");
        throughPrompt("Sign this document");
        see("plain.pdf");
        phone.device.pressBack();
        see("Sign a document");
        Phone.say("the Compose app brings a shared PDF back after adding the first key");
    }

    @Test
    public void step5bAboutAndLanguage() {
        tap("Your keys");
        see("Opens with");
        Phone.sleep(1000);
        scrollTo("About kzsigner.*");
        tap("About kzsigner.*");
        see("Your documents stay on your phone");
        screen("android-about");
        phone.device.pressBack();
        see("Opens with");

        // the app in Russian, then back to the phone's language
        scrollTo("Same as the phone");
        tap("Same as the phone");
        tap("Русский");
        see("Ваши ключи");
        screen("android-keys-ru");
        // the app restarts its screen in the new language: back to Home if still on the keys
        if (!phone.shows("Подписать документ")) {
            phone.device.pressBack();
        }
        see("Подписать документ");
        screen("android-home-ru");
        tap("Ваши ключи");
        Phone.sleep(1000);
        scrollTo("Русский");
        tap("Русский");
        tap("Как на телефоне");
        see("Your keys");
        if (!phone.shows("Sign a document")) {
            phone.device.pressBack();
        }
        see("Sign a document");
        Phone.say("the Compose app shows About and switches language");
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
            see(CAROL);
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
