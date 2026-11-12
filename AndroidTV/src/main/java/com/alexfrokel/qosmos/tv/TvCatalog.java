package com.alexfrokel.qosmos.tv;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

final class TvCatalog {
    private static final String URL = "https://raw.githubusercontent.com/alexfrokel/qosmos-tv-catalog/main/catalog.json";
    private static final String API = "https://api.github.com/repos/alexfrokel/qosmos-tv-catalog/contents/catalog.json";
    private static final String ALIAS = "qosmos-tv-catalog-v1";
    private static final int LIMIT = 512 * 1024;
    private static final byte[] AAD = "Qosmos TV catalog v1".getBytes(StandardCharsets.UTF_8);

    static final class Device {
        final String id;
        final String publicKey;
        private final KeyStore.PrivateKeyEntry key;

        private Device(String id, String publicKey, KeyStore.PrivateKeyEntry key) {
            this.id = id;
            this.publicKey = publicKey;
            this.key = key;
        }
    }

    static synchronized Device device() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .build());
            generator.generateKeyPair();
        }
        KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) store.getEntry(ALIAS, null);
        byte[] publicKey = key.getCertificate().getPublicKey().getEncoded();
        byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(publicKey);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(fingerprint);
        return new Device(id, Base64.getEncoder().encodeToString(publicKey), key);
    }

    static List<RealityProfile> download(Device device) throws IOException, GeneralSecurityException, JSONException {
        JSONObject catalog = new JSONObject(fetch());
        if (catalog.getInt("version") != 1) throw new IOException("Версия каталога не поддерживается.");
        String wrapped = catalog.getJSONObject("devices").optString(device.id, "");
        if (wrapped.isEmpty()) return null;

        Base64.Decoder decoder = Base64.getDecoder();
        Cipher unwrap = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        unwrap.init(Cipher.DECRYPT_MODE, device.key.getPrivateKey(),
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        byte[] secret = unwrap.doFinal(decoder.decode(wrapped));
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
