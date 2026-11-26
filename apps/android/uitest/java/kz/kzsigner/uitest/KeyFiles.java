package kz.kzsigner.uitest;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * The test key files, PDFs and signed files (testdata/keys, ocsp, pdf and app, in
 * this APK's assets) as content:// URIs, read-only: content://kz.kzsigner.uitest.keys/alice_rsa.p12. What a files app
 * or a messenger hands over with "Open with" or Share.
 */
public class KeyFiles extends ContentProvider {
    static final String AUTHORITY = "kz.kzsigner.uitest.keys";

    static Uri uri(String name) {
        return Uri.parse("content://" + AUTHORITY + "/" + name);
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    private File file(Uri uri) throws IOException {
        String name = new File(uri.getPath()).getName();
        File f = new File(getContext().getCacheDir(), name);
        try (InputStream in = getContext().getAssets().open(name); OutputStream out = new FileOutputStream(f)) {
            // InputStream.transferTo is Android 13+; this runs on 11 too
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) > 0; ) {
                out.write(buf, 0, n);
            }
        }
        return f;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        try {
            return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (IOException e) {
            throw new FileNotFoundException(uri + ": " + e);
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        MatrixCursor c = new MatrixCursor(new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        try {
            File f = file(uri);
            c.addRow(new Object[] {f.getName(), f.length()});
        } catch (IOException e) {
            // no such file: no row
        }
        return c;
    }

    @Override
    public String getType(Uri uri) {
        return mime(uri.getPath());
    }

    /** What a files app says a file is, by its name. */
    static String mime(String name) {
        return name.endsWith(".pdf") ? "application/pdf"
                : name.endsWith(".cms") ? "application/pkcs7-signature"
                : name.endsWith(".xml") ? "text/xml"
                : name.endsWith(".txt") ? "text/plain" : "application/x-pkcs12";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] args) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        throw new UnsupportedOperationException();
    }
}
