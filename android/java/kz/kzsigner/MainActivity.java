package kz.kzsigner;

import android.app.NativeActivity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
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
 * on-screen keyboard. Rust calls {@link #call(String)}; see src/android.rs for the requests.
 */
public class MainActivity extends NativeActivity {
    private static final int PICK = 1;
    private static final int SAVE = 2;

    private final ArrayDeque<String> events = new ArrayDeque<>();
    /** The written file waiting for "Save as". */
    private volatile String saveFrom;
    /** The file field the chooser was opened for. */
    private volatile String pickFor;

    @Override
    protected void onCreate(Bundle state) {
        // copies of chosen files (keys too) and signed files from earlier runs
        delete(new File(getCacheDir(), "in"));
        delete(new File(getCacheDir(), "out"));
        super.onCreate(state);
        received(getIntent());
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
            case "keyboard":
                boolean show = r.length > 1 && r[1].equals("1");
                runOnUiThread(() -> keyboard(show));
                return null;
            default:
                return null;
        }
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
