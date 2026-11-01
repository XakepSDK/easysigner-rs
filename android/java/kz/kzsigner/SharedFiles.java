package kz.kzsigner;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Lets other apps read a file kzsigner shares (a signed document in the app's cache), read
 * only, for the duration of the share. URIs: content://kz.kzsigner.files/<path in the cache>.
 */
public class SharedFiles extends ContentProvider {
    static final String AUTHORITY = "kz.kzsigner.files";

    static Uri uri(Context c, File f) {
        String root = c.getCacheDir().getAbsolutePath();
        String p = f.getAbsolutePath();
        return new Uri.Builder().scheme("content").authority(AUTHORITY)
                .path(p.startsWith(root) ? p.substring(root.length()) : f.getName()).build();
    }

    private File file(Uri uri) throws FileNotFoundException {
        try {
            File root = getContext().getCacheDir().getCanonicalFile();
            File f = new File(root, uri.getPath()).getCanonicalFile();
            if (!f.getPath().startsWith(root.getPath() + File.separator) || !f.isFile()) {
                throw new FileNotFoundException(uri.toString());
            }
            return f;
        } catch (IOException e) {
            throw new FileNotFoundException(uri.toString());
        }
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) {
            throw new FileNotFoundException("read only");
        }
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        File f;
        try {
            f = file(uri);
        } catch (FileNotFoundException e) {
            return null;
        }
        MatrixCursor c = new MatrixCursor(new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        c.addRow(new Object[] {f.getName(), f.length()});
        return c;
    }

    @Override
    public String getType(Uri uri) {
        return MainActivity.mime(uri.getLastPathSegment() == null ? "" : uri.getLastPathSegment());
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] args) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        return 0;
    }
}
