package kz.kzsigner.uitest;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.Until;

import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * The Kotlin + Compose app (docs/compose-plan.md), as far as it goes: it starts, reaches the
 * Rust core through UniFFI and shows the keys screen, with no keys saved yet. It is installed
 * next to the released app (kz.kzsigner.next) until it replaces it.
 */
@RunWith(AndroidJUnit4.class)
public class ComposeApp {
    private final Phone phone = new Phone(Phone.NEXT);

    @Test
    public void startsAndShowsTheKeysScreen() {
        phone.sh("svc power stayon true");
        phone.unlock();
        phone.start("");
        phone.device.wait(Until.hasObject(By.pkg(phone.app)), 20000);
        Phone.sleep(3000);
        if (!phone.running()) {
            phone.fail("the Compose app stopped after starting");
        }
        phone.shot("android-next-start");
        // "No keys yet" is the core's answer (list_keys on a vault file that isn't there),
        // so seeing it means the Kotlin bindings and the Rust library loaded
        for (String want : new String[] {"Your keys", "No keys yet"}) {
            if (!phone.appNames(want)) {
                phone.fail("the accessibility tree has no \"" + want + "\". The tree:\n" + phone.tree());
            }
        }
        Phone.say("the Compose app shows the keys screen");
    }
}
