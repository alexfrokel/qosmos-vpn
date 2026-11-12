package com.alexfrokel.qosmos.tv;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.IntConsumer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

final class TvUpdater {
    static final String APK = "qosmos-update.apk";
    private static final String RELEASES = "https://github.com/alexfrokel/qosmos-tv-catalog/releases/";
    private static final byte[] MANIFEST_AAD = "Qosmos TV update v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] APK_KEY_LABEL = "Qosmos TV APK v1".getBytes(StandardCharsets.UTF_8);
    private static final int CHUNK = 1024 * 1024;
    private static final int MAX_APK = 128 * CHUNK;

    static final class Update {
        final String version;
        final long code;
        final int size;
        final String sha256;
        final byte[] prefix;
        final byte[] key;

        Update(JSONObject manifest, byte[] secret) throws Exception {
            version = manifest.getString("version");
            code = manifest.getLong("code");
            size = manifest.getInt("size");
            sha256 = manifest.getString("sha256");
            prefix = Base64.getDecoder().decode(manifest.getString("prefix"));
            if (!version.matches("[0-9]+\\.[0-9]+\\.[0-9]+") || code < 1 || size < 1 || size > MAX_APK
                    || prefix.length != 8 || !sha256.matches("[0-9a-f]{64}")) throw new IOException("Invalid update");
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(secret, "HmacSHA256"));
            key = hmac.doFinal(APK_KEY_LABEL);
        }
    }

    static Update check(Context context) throws Exception {
        byte[] key = TvCatalog.readKey(context);
        HttpsURLConnection connection = open(RELEASES + "latest/download/update.json");
        try (InputStream input = connection.getInputStream()) {
            Update update = new Update(new JSONObject(TvCatalog.decrypt(key, ProfileStore.read(input), MANIFEST_AAD)), key);
            return update.code > versionCode(context.getPackageManager().getPackageInfo(context.getPackageName(), 0))
                ? update : null;
        } finally {
            connection.disconnect();
        }
    }

    static File download(Context context, Update update, IntConsumer progress) throws Exception {
        File temporary = File.createTempFile("qosmos-update-", ".apk", context.getCacheDir());
        File ready = new File(context.getCacheDir(), APK);
        try {
            downloadInto(update, temporary, progress);
            verify(context, temporary, update.code);
            if (!temporary.renameTo(ready)) throw new IOException("Could not save the APK");
            return ready;
        } finally {
            temporary.delete();
        }
    }

    private static void downloadInto(Update update, File file, IntConsumer progress) throws Exception {
        HttpsURLConnection connection = open(RELEASES + "download/tv-v" + update.version + "/Qosmos-TV.apk.enc");
        try (DataInputStream input = new DataInputStream(connection.getInputStream());
             FileOutputStream output = new FileOutputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            SecretKeySpec key = new SecretKeySpec(update.key, "AES");
            byte[] encrypted = new byte[CHUNK + 16];
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            for (int offset = 0; offset < update.size; offset += CHUNK) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("Download interrupted");
                int length = Math.min(CHUNK, update.size - offset);
                input.readFully(encrypted, 0, length + 16);
                byte[] nonce = ByteBuffer.allocate(12).put(update.prefix).putInt(offset / CHUNK).array();
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                byte[] decrypted = cipher.doFinal(encrypted, 0, length + 16);
                output.write(decrypted);
                digest.update(decrypted);
                progress.accept((int) ((offset + length) * 100L / update.size));
            }
            if (input.read() != -1 || !update.sha256.equals(hex(digest.digest()))) throw new IOException("APK checksum mismatch");
        } finally {
            connection.disconnect();
        }
    }

    private static void verify(Context context, File apk, long code) throws Exception {
        PackageManager manager = context.getPackageManager();
        PackageInfo current = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
        PackageInfo downloaded = manager.getPackageArchiveInfo(apk.getAbsolutePath(), PackageManager.GET_SIGNATURES);
        if (downloaded == null || !current.packageName.equals(downloaded.packageName)
                || versionCode(downloaded) != code || code <= versionCode(current)
                || current.signatures == null || current.signatures.length == 0
                || !Arrays.equals(current.signatures, downloaded.signatures)) {
            throw new IOException("APK signature or version mismatch");
        }
    }

    static long versionCode(PackageInfo info) {
        return Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
    }

    private static HttpsURLConnection open(String address) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(address).openConnection();
        connection.setInstanceFollowRedirects(true);
        connection.setUseCaches(false);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(15000);
        return connection;
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) result.append(Character.forDigit((b & 0xff) >>> 4, 16)).append(Character.forDigit(b & 15, 16));
        return result.toString();
    }
}
