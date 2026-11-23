package kz.kzsigner.uitest;

import android.os.SystemClock;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The emulator, as the tests drive it: the screen lock, kzsigner's process and log, Settings.
 * Shell commands run as adb's shell user. Only the virtual fingerprint sensor is out of reach
 * from here: the test logs "FINGER n" while it wants finger n touched, and
 * scripts/android-selftest.sh touches it from the host.
 */
final class Phone {
    static final String PIN = "1111";
    static final String APP = "kz.kzsigner";
    static final String TAG = "KZUITEST";

    final UiDevice device =
            UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());

    String sh(String command) {
        try {
            return device.executeShellCommand(command);
        } catch (IOException e) {
            throw new AssertionError(command + ": " + e, e);
        }
    }

    static void say(String what) {
        Log.i(TAG, what);
    }

    static void sleep(long ms) {
        SystemClock.sleep(ms);
    }

    /** Fails the test with a screenshot and the app's log. */
    void fail(String why) {
        shot("android-fail");
        say("app log:\n" + sh("logcat -d -s KZSELFTEST:* kzsigner:* RustStdoutStderr:* AndroidRuntime:* DEBUG:*"));
        org.junit.Assert.fail(why);
    }

    /** A screenshot that the script copies off the emulator: /data/local/tmp/kzuitest/NAME.png. */
    void shot(String name) {
        sh("mkdir -p /data/local/tmp/kzuitest");
        sh("screencap -p /data/local/tmp/kzuitest/" + name + ".png");
    }

    boolean running() {
        return !sh("pidof " + APP).trim().isEmpty();
    }

    /** Starts kzsigner's activity, with extras as in "am start" (e.g. "--ez selftest true"). */
    void start(String extras) {
        sh("am start -W -n " + APP + "/.MainActivity " + extras);
    }

    /** When the tests last forgot the app's log, in seconds since 1970 (the emulator's clock). */
    private double since;

    /** The app's log (tag KZSELFTEST) since clearLog. */
    String appLog() {
        StringBuilder out = new StringBuilder();
        for (String line : sh("logcat -d -v epoch -s KZSELFTEST:*").split("\n")) {
            String[] f = line.trim().split("\\s+", 2);
            try {
                if (Double.parseDouble(f[0]) >= since) {
                    out.append(line).append('\n');
                }
            } catch (NumberFormatException e) {
                // "--------- beginning of main"
            }
        }
        return out.toString();
    }

    /** Forgets the app's log so far (the log itself stays, with the tests' own lines). */
    void clearLog() {
        since = Double.parseDouble(sh("date +%s").trim());
    }

    /** Types the PIN and Enter: into a PIN prompt if one is up, else ignored by the screen. */
    void pin() {
        sh("input text " + PIN);
        device.pressEnter();
    }

    void setPin() {
        String out = sh("locksettings set-pin " + PIN);
        if (out.toLowerCase().contains("error")) {
            fail("could not set a screen PIN: " + out);
        }
    }

    void clearPin() {
        sh("locksettings clear --old " + PIN);
    }

    boolean locked() {
        String w = sh("dumpsys window");
        return w.contains("mDreamingLockscreen=true") || w.contains("isKeyguardShowing=true")
                || w.contains("mShowingLockscreen=true");
    }

    /**
     * Locks the screen and unlocks it with the PIN: the Keystore lets keys that need an
     * unlocked device work only after a real unlock with the screen lock.
     */
    void unlock() {
        for (int attempt = 1; attempt <= 5; attempt++) {
            try {
                device.sleep();
                sleep(2000);
                device.wakeUp();
            } catch (android.os.RemoteException e) {
                throw new AssertionError(e);
            }
            sleep(2000);
            sh("wm dismiss-keyguard");
            sleep(2000);
            int w = device.getDisplayWidth();
            int h = device.getDisplayHeight();
            device.swipe(w / 2, h * 4 / 5, w / 2, h / 5, 20);
            sleep(2000);
            pin();
            sleep(4000);
            if (!locked()) {
                say("unlocked (attempt " + attempt + ")");
                return;
            }
            say("the lock screen is still up after unlocking (attempt " + attempt + ")");
        }
        fail("could not unlock the screen with the PIN");
    }

    /** The first thing on screen whose text or description matches the pattern. */
    UiObject2 find(Pattern p) {
        UiObject2 o = device.findObject(By.text(p));
        return o != null ? o : device.findObject(By.desc(p));
    }

    boolean shows(String regex) {
        return find(Pattern.compile(".*(" + regex + ").*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL)) != null;
    }

    boolean tap(String regex) {
        UiObject2 o = find(Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
        if (o == null) {
            return false;
        }
        o.click();
        return true;
    }

    /**
     * Whether kzsigner's accessibility tree has something whose text or description contains
     * the name: what TalkBack reads (a button's label may carry its explanation too). The tree
     * is walked node by node, as a screen reader does, hidden nodes included (UI Automator's
     * own search leaves some out). The app builds its tree once a reader first asks for it, so
     * this asks for up to 15 seconds.
     */
    boolean appNames(String name) {
        for (int i = 0; i < 15; i++) {
            for (android.view.accessibility.AccessibilityWindowInfo w : automation().getWindows()) {
                android.view.accessibility.AccessibilityNodeInfo root = w.getRoot();
                if (root != null && APP.contentEquals(String.valueOf(root.getPackageName()))
                        && has(root, name, 0)) {
                    return true;
                }
            }
            sleep(1000);
        }
        return false;
    }

    private static android.app.UiAutomation automation() {
        android.app.UiAutomation a = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        android.accessibilityservice.AccessibilityServiceInfo info = a.getServiceInfo();
        int want = android.accessibilityservice.AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
                | android.accessibilityservice.AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        if ((info.flags & want) != want) {
            info.flags |= want;
            a.setServiceInfo(info);
        }
        return a;
    }

    private static boolean has(android.view.accessibility.AccessibilityNodeInfo n, String name, int depth) {
        if (n == null || depth > 40) {
            return false;
        }
        if (String.valueOf(n.getText()).contains(name)
                || String.valueOf(n.getContentDescription()).contains(name)) {
            return true;
        }
        for (int i = 0; i < n.getChildCount(); i++) {
            if (has(n.getChild(i), name, depth + 1)) {
                return true;
            }
        }
        return false;
    }

    /** kzsigner's accessibility tree, one node a line, hidden nodes included. */
    String tree() {
        StringBuilder out = new StringBuilder();
        for (android.view.accessibility.AccessibilityWindowInfo w : automation().getWindows()) {
            android.view.accessibility.AccessibilityNodeInfo root = w.getRoot();
            if (root != null && APP.contentEquals(String.valueOf(root.getPackageName()))) {
                print(root, 0, out);
            }
        }
        return out.length() > 0 ? out.toString() : "(no kzsigner window)";
    }

    private static void print(android.view.accessibility.AccessibilityNodeInfo n, int depth, StringBuilder out) {
        if (n == null || depth > 40) {
            return;
        }
        out.append("  ".repeat(depth)).append(n.getClassName())
                .append(" text=").append(n.getText())
                .append(" desc=").append(n.getContentDescription())
                .append(" visible=").append(n.isVisibleToUser())
                .append(" important=").append(n.isImportantForAccessibility())
                .append(" children=").append(n.getChildCount()).append('\n');
        for (int i = 0; i < n.getChildCount(); i++) {
            print(n.getChild(i), depth + 1, out);
        }
    }

    int fingers() {
        Matcher m = Pattern.compile("\"count\":(\\d+)").matcher(sh("dumpsys fingerprint"));
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    /** Enrolls virtual finger n through Settings; the script touches the sensor meanwhile. */
    void enroll(int n) {
        int want = fingers() + 1;
        // a fresh Settings: one left from the last enrollment only comes back to the front
        sh("am force-stop com.android.settings");
        sh("am start -a android.settings.FINGERPRINT_ENROLL");
        for (int i = 0; i < 90 && fingers() < want; i++) {
            say("FINGER " + n);
            sleep(2000);
            if (shows("(Re-enter|Confirm|Enter) your (device )?PIN")) {
                pin();
                continue;
            }
            tap("I agree|Agree|Next|Continue|Start|More|Accept|OK|Got it");
        }
        say("FINGER 0");
        tap("Done|Next|Finish");
        device.pressHome();
        if (fingers() < want) {
            fail("could not enroll finger " + n);
        }
        say("enrolled finger " + n);
    }

    /** Waits for the app's log to show one of the endings; the log, or a failure. */
    String waitLog(String pass, String failure, int seconds, Runnable meanwhile) {
        long end = SystemClock.uptimeMillis() + seconds * 1000L;
        while (SystemClock.uptimeMillis() < end) {
            sleep(3000);
            String log = appLog();
            if (log.contains(failure)) {
                fail(failure + ": " + line(log, failure));
            }
            if (log.contains(pass)) {
                return log;
            }
            if (meanwhile != null) {
                meanwhile.run();
            }
        }
        fail("no \"" + pass + "\" after " + seconds + " s");
        return null;
    }

    static String line(String log, String part) {
        for (String l : log.split("\n")) {
            if (l.contains(part)) {
                return l.substring(l.indexOf(part));
            }
        }
        return "";
    }
}
