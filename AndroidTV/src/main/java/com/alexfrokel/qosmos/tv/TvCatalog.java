package com.alexfrokel.qosmos.tv;

import android.content.Context;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

final class TvCatalog {
    private static final String URL = "https://raw.githubusercontent.com/alexfrokel/qosmos-tv-catalog/main/catalog.json";
    private static final String API = "https://api.github.com/repos/alexfrokel/qosmos-tv-catalog/contents/catalog.json";
    private static final int LIMIT = 512 * 1024;
    private static final byte[] AAD = "Qosmos TV catalog v2".getBytes(StandardCharsets.UTF_8);

    static final class CatalogNotConfigured extends Exception { }

    static List<RealityProfile> download(Context context)
            throws IOException, GeneralSecurityException, JSONException, CatalogNotConfigured {
        int resource = context.getResources().getIdentifier("catalog_key", "raw", context.getPackageName());
        if (resource == 0) throw new CatalogNotConfigured();
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] secret;
        try (InputStream input = context.getResources().openRawResource(resource)) {
            secret = decoder.decode(ProfileStore.read(input).trim());
        }
        JSONObject catalog = new JSONObject(fetch());
        if (catalog.getInt("version") != 2) throw new IOException("Версия каталога не поддерживается.");
        byte[] nonce = decoder.decode(catalog.getString("nonce"));
        if (secret.length != 32 || nonce.length != 12) throw new IOException("Повреждён каталог.");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secret, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(AAD);
        String profiles = new String(cipher.doFinal(decoder.decode(catalog.getString("ciphertext"))), StandardCharsets.UTF_8);
        if (profiles.trim().isEmpty()) return java.util.Collections.emptyList();
        return RealityProfile.parseList(profiles);
    }

    private static String fetch() throws IOException {
        try {
            return fetch(URL + "?refresh=" + System.currentTimeMillis() / 1000);
        } catch (IOException unavailable) {
            return fetch(API);
        }
    }

    private static String fetch(String address) throws IOException {
        URL catalogUrl = new URL(address);
        HttpsURLConnection connection = (HttpsURLConnection) catalogUrl.openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Cache-Control", "no-cache");
            connection.setRequestProperty("Accept", "application/vnd.github.raw+json");
            connection.setConnectTimeout(6000);
            connection.setReadTimeout(8000);
            if (connection.getResponseCode() != 200 || connection.getContentLengthLong() > LIMIT) {
                throw new IOException("Каталог недоступен.");
            }
            try (InputStream input = connection.getInputStream()) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
                for (int count; (count = input.read(buffer)) != -1;) {
                    if (output.size() + count > LIMIT || System.nanoTime() >= deadline) {
                        throw new IOException("Каталог слишком большой или долго загружается.");
                    }
                    output.write(buffer, 0, count);
                }
                return new String(output.toByteArray(), StandardCharsets.UTF_8);
            }
        } finally {
            connection.disconnect();
        }
    }
}
