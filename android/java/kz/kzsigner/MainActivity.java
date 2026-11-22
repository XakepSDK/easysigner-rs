package kz.kzsigner;

import android.app.NativeActivity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.graphics.Insets;
import android.view.View;
import android.view.WindowInsets;
import android.view.inputmethod.InputMethodManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Locale;

/**
 * kzsigner's window is Rust (NativeActivity runs it). This class only does what needs Java:
 * Android's file chooser and "Save as", sharing, files opened from other apps, and the
 * on-screen keyboard, and the security chip for stored keys. Rust calls {@link #call(String)}
 * and {@link #guard(String, byte[], byte[])}; see src/android.rs for the requests.
 */
public class MainActivity extends NativeActivity {
    private static final int PICK = 1;
    private static final int SAVE = 2;

    private final ArrayDeque<String> events = new ArrayDeque<>();
    /** The written file waiting for "Save as". */
    private volatile String saveFrom;
    /** The file field the chooser was opened for. */
    private volatile String pickFor;
    /** The security chip, for the key store. */
    private KeyGuard keyGuard;

    @Override
    protected void onCreate(Bundle state) {
        // copies of chosen files (keys too) and signed files from earlier runs
        delete(new File(getCacheDir(), "in"));
        delete(new File(getCacheDir(), "out"));
        delete(new File(getCacheDir(), "view"));
        super.onCreate(state);
        keyGuard = new KeyGuard(this);
        received(getIntent());
        selfTest(getIntent());
    }

    /**
     * CI's check of the security chip code on an emulator (scripts/android-selftest.sh):
     * started with {@code --ez selftest true}, it runs KeyGuard as the key store does and logs
     * each step under the tag KZSELFTEST, ending in PASS or FAIL. It runs on emulators only,
     * so no other app can show prompts on a phone through it.
     */
    private void selfTest(Intent intent) {
        if (intent == null || !intent.getBooleanExtra("selftest", false)) {
            return;
        }
        if (!"ranchu".equals(android.os.Build.HARDWARE)
                && !"goldfish".equals(android.os.Build.HARDWARE)) {
            return;
        }
        new Thread(() -> {
            String tag = "KZSELFTEST";
            try {
                byte[] plain = "kzsigner self-test".getBytes("UTF-8");
                byte[] aad = {1, 2, 3};
                String caps = new String(body(keyGuard.call("caps", null, null)), "UTF-8");
                android.util.Log.i(tag, "caps " + caps.replace('\n', ' '));
                if (!caps.startsWith("1,")) {
                    throw new Exception("no screen lock seen");
                }
                android.util.Log.i(tag, "insets " + insets());
                for (int auth = 0; auth <= 1; auth++) {
                    String name = "kzsigner-selftest-" + auth;
                    byte[] where = body(keyGuard.call("create\n" + name + "\n" + auth, null, null));
                    android.util.Log.i(tag, "create auth " + auth + " security " + where[0]);
                    String p = "\nkzsigner self-test\nauth " + auth + "\n";
                    byte[] sealed = body(keyGuard.call("seal\n" + name + p, plain, aad));
                    android.util.Log.i(tag, "seal auth " + auth + " ok");
                    byte[] back = body(keyGuard.call("open\n" + name + p, sealed, aad));
                    if (!java.util.Arrays.equals(back, plain)) {
                        throw new Exception("open gave other bytes");
                    }
                    android.util.Log.i(tag, "open auth " + auth + " ok");
                    byte[] bad = sealed.clone();
                    bad[bad.length - 1] ^= 1;
                    if (keyGuard.call("open\n" + name + p, bad, aad)[0] == 0) {
                        throw new Exception("a changed box opened");
                    }
                    keyGuard.call("delete\n" + name, null, null);
                }
                android.util.Log.i(tag, "PASS");
            } catch (Exception e) {
                android.util.Log.e(tag, "FAIL " + e);
            }
        }).start();
    }

    /** A KeyGuard answer's data, or an exception saying how it went wrong. */
    private static byte[] body(byte[] answer) throws Exception {
        if (answer.length > 0 && answer[0] == 0) {
            return java.util.Arrays.copyOfRange(answer, 1, answer.length);
        }
        String why = answer.length > 1
                ? new String(answer, 1, answer.length - 1, "UTF-8")
                : "status " + (answer.length > 0 ? answer[0] : -1);
        throw new Exception(why);
    }

    private static void delete(File f) {
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) {
                delete(c);
            }
        }
        f.delete();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        received(intent);
        selfTest(intent);
    }

    /** Called by Rust on its own thread. */
    public String call(String request) {
        String[] r = request.split("\n", -1);
        switch (r[0]) {
            case "poll":
                synchronized (events) {
                    return events.poll();
                }
            case "info":
                return getFilesDir().getAbsolutePath() + "\n" + getCacheDir().getAbsolutePath()
                        + "\n" + Locale.getDefault().getLanguage();
            case "pick":
                pickFor = r.length > 1 ? r[1] : "";
                runOnUiThread(() -> {
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType("*/*");
                    startActivityForResult(i, PICK);
                });
                return null;
            case "save":
                saveFrom = r[2];
                runOnUiThread(() -> {
                    Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType(mime(r[1]));
                    i.putExtra(Intent.EXTRA_TITLE, r[1]);
                    startActivityForResult(i, SAVE);
                });
                return null;
            case "share":
                runOnUiThread(() -> {
                    File f = new File(r[1]);
                    Intent i = new Intent(Intent.ACTION_SEND);
                    i.setType(mime(f.getName()));
                    i.putExtra(Intent.EXTRA_STREAM, SharedFiles.uri(this, f));
                    i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    startActivity(Intent.createChooser(i, null));
                });
                return null;
            case "view":
                runOnUiThread(() -> {
                    File f = new File(r[1]);
                    Intent i = new Intent(Intent.ACTION_VIEW);
                    i.setDataAndType(SharedFiles.uri(this, f), mime(f.getName()));
                    i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    try {
                        startActivity(i);
                    } catch (ActivityNotFoundException e) {
                        event("noviewer");
                    }
                });
                return null;
            case "insets":
                return insets();
            case "background":
                runOnUiThread(() -> moveTaskToBack(true));
                return null;
            case "keyboard":
                boolean show = r.length > 1 && r[1].equals("1");
                runOnUiThread(() -> keyboard(show));
                return null;
            default:
                return null;
        }
    }

    /**
     * Called by Rust on its own thread, never the UI thread: the key store's requests to the
     * security chip (see KeyGuard). A prompt blocks until the owner answers it.
     */
    public byte[] guard(String request, byte[] a, byte[] b) {
        return keyGuard.call(request, a, b);
    }

    /**
     * The edges the app must keep clear, in pixels: "left,top,right,bottom". Android 15 and
     * newer draw apps under the status bar, the gesture bar and the camera cutout; the bottom
     * also covers the on-screen keyboard while it is up.
     */
    private String insets() {
        View v = getWindow().getDecorView();
        WindowInsets w = v.getRootWindowInsets();
        if (w == null) {
            return "0,0,0,0";
        }
        Insets bars = w.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
        Insets ime = w.getInsets(WindowInsets.Type.ime());
        return bars.left + "," + bars.top + "," + bars.right + "," + Math.max(bars.bottom, ime.bottom);
    }

    private void keyboard(boolean show) {
        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        View v = getWindow().getDecorView();
        if (show) {
            v.setFocusable(true);
            v.setFocusableInTouchMode(true);
            v.requestFocus();
            imm.showSoftInput(v, 0);
        } else {
            imm.hideSoftInputFromWindow(v.getWindowToken(), 0);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        Uri uri = result == RESULT_OK && data != null ? data.getData() : null;
        if (request == PICK) {
            String field = pickFor;
            if (uri == null) {
                event("cancelled");
            } else {
                new Thread(() -> {
                    String p = copyIn(uri);
                    event(p != null ? "picked\n" + field + "\n" + p : "cancelled");
                }).start();
            }
        } else if (request == SAVE && uri == null) {
            event("notsaved");
        } else if (request == SAVE) {
            String from = saveFrom;
            new Thread(() -> {
                try (InputStream in = new FileInputStream(from);
                        OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
                    copy(in, out);
                    event("saved\n" + name(uri, new File(from).getName()));
                } catch (Exception e) {
                    event("error\n" + e.getMessage());
                }
            }).start();
        }
    }

    /** A file shared with or opened in kzsigner ("Open with", "Share"). */
    private void received(Intent intent) {
        if (intent == null) {
            return;
        }
        Uri uri = null;
        if (Intent.ACTION_VIEW.equals(intent.getAction())) {
            uri = intent.getData();
        } else if (Intent.ACTION_SEND.equals(intent.getAction())) {
            uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        }
        if (uri != null) {
            Uri u = uri;
            new Thread(() -> {
                String p = copyIn(u);
                if (p != null) {
                    event("open\n" + p);
                }
            }).start();
        }
    }

    private void event(String e) {
        synchronized (events) {
            events.add(e);
        }
    }

    /** Copies a chosen file into the app's cache under its own name; its path, or null. */
    private String copyIn(Uri uri) {
        String name = name(uri, "file");
        File dir = new File(getCacheDir(), "in/" + System.nanoTime());
        if (!dir.mkdirs()) {
            return null;
        }
        File f = new File(dir, name);
        try (InputStream in = getContentResolver().openInputStream(uri);
                OutputStream out = new FileOutputStream(f)) {
            copy(in, out);
            return f.getAbsolutePath();
        } catch (Exception e) {
            return null;
        }
    }

    /** The file's display name, only its last part. */
    private String name(Uri uri, String fallback) {
        String n = null;
        try (Cursor c = getContentResolver().query(uri, new String[] {OpenableColumns.DISPLAY_NAME},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                n = c.getString(0);
            }
        } catch (Exception e) {
            // no name: use the fallback
        }
        if (n == null) {
            n = uri.getLastPathSegment();
        }
        if (n != null) {
            // its last part, on one line (requests to and from Rust are line-separated)
            n = n.substring(n.lastIndexOf('/') + 1).replaceAll("[\\p{Cntrl}\\\\]", "_");
        }
        if (n == null || n.isEmpty() || n.equals(".") || n.equals("..")) {
            n = fallback;
        }
        return n;
    }

    private static void copy(InputStream in, OutputStream out) throws java.io.IOException {
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
    }

    static String mime(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        if (n.endsWith(".pdf")) {
            return "application/pdf";
        }
        if (n.endsWith(".cms") || n.endsWith(".p7s")) {
            return "application/pkcs7-signature";
        }
        if (n.endsWith(".txt")) {
            return "text/plain";
        }
        return "application/octet-stream";
    }
}
