package com.alexfrokel.qosmos.tv;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

final class ProfileStore {
    static final String PENDING = "import-pending.txt";

    private final SharedPreferences preferences;

    ProfileStore(Context context) {
        preferences = context.getSharedPreferences("profiles", Context.MODE_PRIVATE);
    }

    String source() {
        return preferences.getString("source", "");
    }

    List<RealityProfile> profiles() {
        List<RealityProfile> all = saved("local");
        for (RealityProfile remote : saved("remote")) {
            if (all.stream().noneMatch(remote::sameEndpointAndCredentials)) all.add(remote);
        }
        return all;
    }

    RealityProfile selected() {
        List<RealityProfile> profiles = profiles();
        if (profiles.isEmpty()) return null;
        int index = preferences.getInt("selected", 0);
        return profiles.get(index >= 0 && index < profiles.size() ? index : 0);
    }

    void select(int index) {
        preferences.edit().putInt("selected", index).apply();
    }

    void replaceRemote(String source, List<RealityProfile> profiles) throws IOException {
        RealityProfile previous = selected();
        List<RealityProfile> combined = saved("local");
        for (RealityProfile profile : profiles) {
            if (combined.stream().noneMatch(profile::sameEndpointAndCredentials)) combined.add(profile);
        }
        save(preferences.edit().putString("source", source).putString("remote", serialize(profiles)),
            combined, previous);
    }

    void importLocal(List<RealityProfile> imported) throws IOException {
        RealityProfile previous = selected();
        List<RealityProfile> combined = saved("local");
        for (RealityProfile profile : imported) {
            if (combined.stream().noneMatch(profile::sameEndpointAndCredentials)) combined.add(profile);
        }
        if (combined.size() > 50) throw new IOException("Сохранено больше 50 профилей.");
        SharedPreferences.Editor edit = preferences.edit().putString("local", serialize(combined));
        for (RealityProfile profile : saved("remote")) {
            if (combined.stream().noneMatch(profile::sameEndpointAndCredentials)) combined.add(profile);
        }
        save(edit, combined, previous);
    }

    private void save(SharedPreferences.Editor edit, List<RealityProfile> combined, RealityProfile previous)
            throws IOException {
        int selected = 0;
        if (previous != null) {
            for (int index = 0; index < combined.size(); index++) {
                if (previous.sameEndpointAndCredentials(combined.get(index))) {
                    selected = index;
                    break;
                }
            }
        }
        if (!edit.putInt("selected", selected).commit()) throw new IOException("Не удалось сохранить профили.");
    }

    private List<RealityProfile> saved(String key) {
        String text = preferences.getString(key, "");
        return text.isEmpty() ? new ArrayList<>() : RealityProfile.parseList(text);
    }

    private static String serialize(List<RealityProfile> profiles) {
        List<String> links = new ArrayList<>();
        for (RealityProfile profile : profiles) links.add(profile.link);
        return String.join("\n", links);
    }

    static List<RealityProfile> download(String source) throws IOException {
        URI url;
        try {
            url = URI.create(source);
        } catch (IllegalArgumentException e) {
            throw new IOException("Нужна корректная HTTPS-ссылка.");
        }
        if (!"https".equalsIgnoreCase(url.getScheme()) || url.getHost() == null
                || url.getUserInfo() != null || url.getFragment() != null || source.length() > 4096) {
            throw new IOException("Нужна корректная HTTPS-ссылка.");
        }
        HttpsURLConnection connection = (HttpsURLConnection) url.toURL().openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(6000);
            connection.setReadTimeout(7000);
            int code = connection.getResponseCode();
            if (code != 200) throw new IOException("Источник вернул HTTP " + code + ".");
            if (connection.getContentLengthLong() > RealityProfile.MAX_BYTES) {
                throw new IOException("Список профилей больше 256 КБ.");
            }
            try (InputStream input = connection.getInputStream()) {
                return RealityProfile.parseList(read(input));
            }
        } finally {
            connection.disconnect();
        }
    }

    static String read(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        for (int count; (count = input.read(buffer)) >= 0;) {
            if (System.nanoTime() - deadline >= 0) throw new IOException("Источник слишком долго отвечает.");
            if (output.size() + count > RealityProfile.MAX_BYTES) {
                throw new IOException("Список профилей больше 256 КБ.");
            }
            output.write(buffer, 0, count);
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }
}
