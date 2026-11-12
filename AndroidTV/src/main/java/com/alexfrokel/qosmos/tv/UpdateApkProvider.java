package com.alexfrokel.qosmos.tv;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

public final class UpdateApkProvider extends ContentProvider {
    static final Uri URI = Uri.parse("content://com.alexfrokel.qosmos.tv.update/" + TvUpdater.APK);
    static final String MIME = "application/vnd.android.package-archive";

    @Override public boolean onCreate() { return true; }

    private File file() { return new File(getContext().getCacheDir(), TvUpdater.APK); }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!URI.equals(uri) || !"r".equals(mode)) throw new FileNotFoundException();
        return ParcelFileDescriptor.open(file(), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public String getType(Uri uri) { return URI.equals(uri) ? MIME : null; }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        if (!URI.equals(uri) || !file().isFile()) return null;
        String[] columns = projection == null
            ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        MatrixCursor cursor = new MatrixCursor(columns);
        MatrixCursor.RowBuilder row = cursor.newRow();
        for (String column : columns) {
            if (OpenableColumns.DISPLAY_NAME.equals(column)) row.add("Qosmos-TV.apk");
            else if (OpenableColumns.SIZE.equals(column)) row.add(file().length());
            else row.add(null);
        }
        return cursor;
    }

    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
